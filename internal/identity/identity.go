// Package identity implements SPIFFE/mTLS peer-identity extraction for the
// TrustLoop gateway.
//
// Scope (issue #3 -- "Gateway scaffold + SPIFFE/mTLS identity extraction"):
// given an incoming connection authenticated via SPIFFE mTLS, correctly
// extract and report the peer's SPIFFE ID for a valid peer, and correctly
// reject a connection that doesn't present one (self-signed junk cert,
// expired cert, wrong trust domain, or no cert at all).
//
// This package deliberately does NOT implement any X.509/TLS trust
// decisions itself -- doing so would violate trustloop/CLAUDE.md's "do not
// implement identity issuance or the authorization engine from scratch."
// Every accept/reject decision below is made by the official go-spiffe SDK
// (github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig), which builds a
// *tls.Config from caller-supplied SVID/bundle sources and wires its
// VerifyPeerCertificate callback to go-spiffe's own certificate-chain
// verification (x509svid.ParseAndVerify) against the SPIRE-issued trust
// bundle. This package's job is narrower: hand go-spiffe the sources, and
// turn a successfully verified peer certificate into a spiffeid.ID that the
// rest of the gateway (and, in #4, the OpenFGA check) can use.
//
// What is explicitly OUT of scope here, per the issue:
//   - The OpenFGA authorization check itself (issue #4) -- ServerTLSConfig
//     below uses tlsconfig.AuthorizeAny(), i.e. "accept any peer who proves
//     a real SPIFFE identity for this trust domain", not "accept only
//     peers who are allowed to do X". Restricting *which* identities may
//     proceed is a policy decision that belongs to the OpenFGA delegation
//     graph, not a second, redundant, hand-rolled allowlist in this
//     package.
//   - Structured allow/deny audit logging (also issue #4) -- there is no
//     "allow" or "deny" decision made in this package at all, only
//     "identity extracted" or "identity extraction failed". Logging that
//     narrower fact is the caller's (cmd/gateway's) job.
package identity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// ServerTLSConfig returns a *tls.Config that terminates mutual TLS using
// the gateway's own SVID (presented to the peer) and the given bundle
// source (used to verify the peer's presented SVID).
//
// It requires and verifies a client certificate
// (tlsconfig.MTLSServerConfig sets tls.RequireAnyClientCert plus a
// VerifyPeerCertificate callback that performs the real chain verification
// against bundleSource) -- a peer that presents no certificate, an expired
// one, one issued by a CA outside bundleSource's trust domain(s), or a
// self-signed one never in bundleSource at all, fails the TLS handshake
// itself. That failure happens inside crypto/tls before any application
// code (including this package's ExtractPeerID) ever runs -- there is no
// window where a rejected peer's data reaches the gateway's stand-in tool
// call handling.
func ServerTLSConfig(svidSource x509svid.Source, bundleSource x509bundle.Source) *tls.Config {
	// AuthorizeAny(): see the package doc comment above -- narrowing this
	// to specific SPIFFE IDs is issue #4's job (the OpenFGA check), not
	// this ticket's. Every peer that clears mTLS verification is handed to
	// the connection handler; it's the handler (and, later, the
	// authorization check) that decides what happens next.
	return tlsconfig.MTLSServerConfig(svidSource, bundleSource, tlsconfig.AuthorizeAny())
}

// ClientTLSConfig returns a *tls.Config for dialing a specific gateway
// instance over mutual TLS: it presents svidSource's SVID to the server and
// only accepts a server whose SPIFFE ID is exactly expectedServerID
// (tlsconfig.AuthorizeID -- deliberately narrower than the server side's
// AuthorizeAny, because a *client* dialing a *specific* gateway should
// always know and pin exactly which identity it expects to be talking to;
// "any authenticated server will do" would defeat the point of mTLS on the
// client side).
func ClientTLSConfig(svidSource x509svid.Source, bundleSource x509bundle.Source, expectedServerID spiffeid.ID) *tls.Config {
	return tlsconfig.MTLSClientConfig(svidSource, bundleSource, tlsconfig.AuthorizeID(expectedServerID))
}

// ExtractPeerID completes (if not already complete) the TLS handshake on
// conn and returns the SPIFFE ID extracted from the peer's verified leaf
// certificate.
//
// By the time this function is called, go-spiffe's VerifyPeerCertificate
// callback (wired in by ServerTLSConfig) has already run as part of the
// handshake and has already made the real trust decision -- this function
// cannot make a connection more or less trusted than the handshake already
// did. What it adds is just: surface the handshake outcome as a Go error
// (for logging/rejection), and, on success, parse the now-trusted peer
// certificate's SPIFFE URI SAN into a spiffeid.ID.
func ExtractPeerID(ctx context.Context, conn *tls.Conn) (spiffeid.ID, error) {
	if err := conn.HandshakeContext(ctx); err != nil {
		// This is the reject path the ticket asks to prove: no valid
		// SPIFFE identity presented -> the mTLS handshake itself fails ->
		// no SPIFFE ID is ever extracted. The underlying error already
		// distinguishes *why* (e.g. "tls: client didn't provide a
		// certificate" for no-cert, "x509svid: could not verify leaf
		// certificate: ... certificate signed by unknown authority" for a
		// self-signed/wrong-CA cert, "x509svid: could not get X509 bundle:
		// ... no X.509 bundle found" for a wrong-trust-domain SPIFFE ID, or
		// a standard crypto/x509 "certificate has expired" for an expired
		// one) -- callers should propagate/log it rather than collapsing it
		// to a single generic reason.
		return spiffeid.ID{}, fmt.Errorf("mTLS handshake failed: %w", err)
	}

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		// Defensive only: tlsconfig.MTLSServerConfig sets
		// tls.RequireAnyClientCert, so crypto/tls itself refuses to
		// complete a handshake with zero peer certificates -- this branch
		// should be unreachable in practice. Kept because silently
		// returning a zero-value spiffeid.ID on an empty chain would be a
		// far worse failure mode than an explicit error here.
		return spiffeid.ID{}, errors.New("mTLS handshake succeeded but peer presented no certificate")
	}

	// The handshake already verified this certificate chains to a trust
	// bundle root (see ServerTLSConfig) -- IDFromCert only parses the
	// SPIFFE ID out of the now-trusted leaf's URI SAN, it does not perform
	// any additional trust decision.
	id, err := x509svid.IDFromCert(state.PeerCertificates[0])
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("verified peer certificate has no valid SPIFFE ID: %w", err)
	}
	return id, nil
}
