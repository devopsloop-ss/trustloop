// Command gateway-verify proves -- against a real, running gateway, not
// just via unit tests -- that issue #3's two acceptance criteria hold:
//
//  1. A peer presenting a real SPIRE-issued SVID for this trust domain is
//     accepted, and the gateway extracts and reports the correct SPIFFE ID.
//  2. A peer that does NOT present a valid SPIFFE identity is rejected --
//     covering "no cert", "self-signed junk cert", and "cert for the wrong
//     trust domain" concretely (an "expired cert" case is covered by
//     internal/identity's unit tests instead: reliably producing a
//     genuinely expired SVID from the *live* SPIRE server without either
//     waiting out its real TTL or reaching into SPIRE's own signing key
//     isn't something this program does -- see the unit tests for how that
//     case is exercised against a controlled, short-lived CA instead).
//
// This follows the same pattern as cmd/openfga-verify: a small, re-runnable
// Go program that performs the real protocol exchange and reports PASS/FAIL
// per check, exiting non-zero if anything didn't match what was expected --
// not "the process started" as the bar for success.
//
// The valid-peer check needs an actual SPIRE-issued SVID, which only exists
// for a workload the K8s workload attestor recognizes -- so this program is
// meant to run as a pod matching an existing registration entry (see
// hack/gateway/setup.sh, which runs it as the trustloop-sample /
// sample-workload identity already created by hack/spire/setup.sh, reusing
// it rather than minting a second one). The invalid-peer checks need no
// SPIRE identity at all -- that's the point -- so they build their own
// throwaway, deliberately-untrusted certificates.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/devopsloop-ss/trustloop/internal/identity"
)

func main() {
	socket := flag.String("workload-api-socket", "", "SPIFFE Workload API socket address for the valid-peer check. If empty, falls back to SPIFFE_ENDPOINT_SOCKET.")
	gatewayAddr := flag.String("gateway-addr", "", "host:port of the gateway's mTLS listener")
	expectedGatewayID := flag.String("expected-gateway-id", "", "the gateway's expected SPIFFE ID (spiffe://...), pinned by the valid-peer client")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "timeout for each dial attempt")
	flag.Parse()

	if *gatewayAddr == "" || *expectedGatewayID == "" {
		fmt.Fprintln(os.Stderr, "usage: gateway-verify -gateway-addr host:port -expected-gateway-id spiffe://...")
		os.Exit(2)
	}
	gatewayID, err := spiffeid.FromString(*expectedGatewayID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -expected-gateway-id: %v\n", err)
		os.Exit(2)
	}

	if err := run(*socket, *gatewayAddr, gatewayID, *dialTimeout); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

type result struct {
	name   string
	want   string // "accept" or "reject"
	got    string
	detail string
}

func (r result) passed() bool { return r.want == r.got }

func run(socket, gatewayAddr string, gatewayID spiffeid.ID, dialTimeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var results []result

	// --- Check 1: a real SPIRE-issued SVID is accepted, and the identity
	// the gateway echoes back in its ack matches this process's own SPIFFE
	// ID exactly -- proving extraction produced the *correct* ID, not just
	// *an* ID. ------------------------------------------------------------
	r, err := checkValidPeer(ctx, socket, gatewayAddr, gatewayID, dialTimeout)
	if err != nil {
		return fmt.Errorf("running valid-peer check: %w", err)
	}
	results = append(results, r)

	// --- Checks 2-4: peers with no valid SPIFFE identity are rejected ---
	results = append(results, checkRejected("no client certificate presented", gatewayAddr, dialTimeout, nil))

	wrongDomainCert, err := selfSignedSPIFFECert("spiffe://wrong-trust-domain.example.org/ns/evil/sa/mallory")
	if err != nil {
		return fmt.Errorf("building wrong-trust-domain test cert: %w", err)
	}
	results = append(results, checkRejected("cert for a trust domain the gateway doesn't trust", gatewayAddr, dialTimeout, wrongDomainCert))

	// Same trust domain as the real one, but self-signed rather than
	// chained to the real SPIRE CA -- this is the "self-signed junk cert"
	// case: syntactically a valid SPIFFE ID for the right trust domain,
	// cryptographically not trusted by it.
	junkCert, err := selfSignedSPIFFECert(gatewayID.TrustDomain().ID().String() + "/ns/trustloop-sample/sa/impersonator")
	if err != nil {
		return fmt.Errorf("building self-signed junk test cert: %w", err)
	}
	results = append(results, checkRejected("self-signed cert claiming this trust domain but not issued by its SPIRE CA", gatewayAddr, dialTimeout, junkCert))

	fmt.Println()
	allPassed := true
	for _, r := range results {
		status := "PASS"
		if !r.passed() {
			status = "FAIL"
			allPassed = false
		}
		fmt.Printf("%s  %-70s  want=%-6s got=%-6s  %s\n", status, r.name, r.want, r.got, r.detail)
	}
	fmt.Println()
	if !allPassed {
		return errors.New("one or more checks did not match expectation")
	}
	fmt.Println("all checks passed: a real SPIRE identity is accepted and correctly extracted; invalid peers are rejected")
	return nil
}

// checkValidPeer fetches this process's own SPIRE-issued SVID via the
// Workload API and dials the gateway with it, expecting acceptance and a
// correctly-extracted identity echoed back.
func checkValidPeer(ctx context.Context, socket, gatewayAddr string, gatewayID spiffeid.ID, dialTimeout time.Duration) (result, error) {
	var opts []workloadapi.X509SourceOption
	if socket != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return result{}, fmt.Errorf("fetching this process's own SVID from the SPIRE Workload API: %w", err)
	}
	defer source.Close()

	ownSVID, err := source.GetX509SVID()
	if err != nil {
		return result{}, fmt.Errorf("reading fetched SVID: %w", err)
	}

	name := fmt.Sprintf("real SPIRE SVID (%s) is accepted and correctly identified", ownSVID.ID)
	tlsConfig := identity.ClientTLSConfig(source, source, gatewayID)

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(dialCtx, "tcp", gatewayAddr)
	if err != nil {
		return result{name: name, want: "accept", got: "reject", detail: err.Error()}, nil
	}
	defer conn.Close()

	ack, err := sendAndReadAck(conn, "gateway-verify: stand-in tool call from valid peer")
	if err != nil {
		return result{name: name, want: "accept", got: "reject", detail: fmt.Sprintf("connected but tool-call exchange failed: %v", err)}, nil
	}

	wantSubstr := "peer_spiffe_id=" + ownSVID.ID.String()
	if !strings.Contains(ack, wantSubstr) {
		return result{name: name, want: "accept", got: "reject",
			detail: fmt.Sprintf("gateway ack did not contain expected %q -- got %q (extraction produced the wrong identity)", wantSubstr, ack)}, nil
	}
	return result{name: name, want: "accept", got: "accept", detail: "ack: " + ack}, nil
}

// checkRejected dials gatewayAddr presenting cert (or no certificate at all
// if cert is nil), and expects the mTLS handshake itself to fail. It does
// not use the Workload API and does not authenticate the gateway's own
// certificate (InsecureSkipVerify) -- these are adversarial/throwaway
// client configs whose only purpose is to prove the gateway refuses them,
// not real client code, so pinning the server's identity here would be
// beside the point.
func checkRejected(name, gatewayAddr string, dialTimeout time.Duration, cert *tls.Certificate) result {
	cfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // deliberate: this dialer's only purpose is to prove a BAD client cert is rejected server-side; the server's own identity is irrelevant to that.
	}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}

	conn, err := net.DialTimeout("tcp", gatewayAddr, dialTimeout)
	if err != nil {
		return result{name: name, want: "reject", got: "reject", detail: fmt.Sprintf("(TCP connect itself failed: %v)", err)}
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(dialTimeout))
	tlsConn := tls.Client(conn, cfg)
	handshakeErr := tlsConn.Handshake()
	defer tlsConn.Close()

	// IMPORTANT (this is the subtle part): under TLS 1.3, a client's
	// Handshake() call can return success even when the SERVER is about to
	// reject the connection over the client's certificate. TLS 1.3's client
	// finishes its handshake flight (send Certificate, CertificateVerify,
	// Finished) without waiting for any acknowledgement from the server --
	// the server only evaluates VerifyPeerCertificate once THAT flight
	// arrives, and if it rejects, the resulting alert is just the next
	// thing on the wire, delivered asynchronously. So Handshake() returning
	// nil here is NOT proof the gateway accepted this peer -- only that the
	// client finished sending its side. The definitive signal is whether
	// the ensuing read/write (the stand-in tool-call exchange) succeeds:
	// if the server already aborted, that exchange fails with the
	// now-delivered alert (typically "remote error: tls: bad certificate"
	// or similar) instead of a real ack. This is exactly why checkRejected
	// always attempts the exchange rather than trusting Handshake()'s
	// return value alone -- see the gateway's own server-side log (checked
	// independently by hack/gateway/setup.sh) for the authoritative
	// accept/reject decision either way.
	_, ackErr := sendAndReadAck(tlsConn, "gateway-verify: this connection should have been rejected")

	switch {
	case handshakeErr != nil:
		return result{name: name, want: "reject", got: "reject", detail: "handshake failed: " + handshakeErr.Error()}
	case ackErr != nil:
		return result{name: name, want: "reject", got: "reject", detail: "handshake reported success but the server then closed/rejected the connection: " + ackErr.Error()}
	default:
		return result{name: name, want: "reject", got: "accept", detail: "handshake succeeded AND a full stand-in tool-call round trip succeeded -- the gateway genuinely accepted this peer"}
	}
}

func sendAndReadAck(conn net.Conn, line string) (string, error) {
	if _, err := fmt.Fprintf(conn, "%s\n", line); err != nil {
		return "", fmt.Errorf("writing stand-in tool call: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading ack: %w", err)
	}
	return ack, nil
}

// selfSignedSPIFFECert builds a throwaway EC keypair and a self-signed
// certificate carrying rawSPIFFEID as its sole URI SAN -- i.e. a
// certificate that LOOKS like an SVID (has a SPIFFE ID) but was never
// issued by any SPIRE server, signed by nothing this or any other trust
// domain's bundle would recognize. This exists purely to feed
// checkRejected adversarial input; it is not, and must never be mistaken
// for, a real identity-issuance code path (see trustloop/CLAUDE.md: "do not
// implement identity issuance from scratch" -- this is the deliberate
// opposite of that, a *fake* the gateway is expected to refuse).
func selfSignedSPIFFECert(rawSPIFFEID string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	uri, err := url.Parse(rawSPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("parsing %q as a URI: %w", rawSPIFFEID, err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generating serial number: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "gateway-verify: deliberately untrusted test cert"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-signing certificate: %w", err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
