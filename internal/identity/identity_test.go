package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// These tests exercise the accept and reject paths required by issue #3
// entirely in-process, against a synthetic CA -- they do not talk to a real
// SPIRE deployment (that's what hack/gateway/setup.sh's live E2E run via
// cmd/gateway-verify is for). The point of testing against a synthetic CA
// we fully control, rather than only against the live cluster, is that it
// lets us reliably produce cases that are impractical to get a real SPIRE
// server to hand out on demand -- most importantly an *expired* SVID,
// without waiting out a real TTL or reaching into SPIRE's signing key.
//
// Every case below asserts against the exact SAME code path
// cmd/gateway/main.go uses in production: ServerTLSConfig +
// ExtractPeerID. Nothing here reimplements or bypasses that -- these tests
// would fail to catch a real bug if they did.

const testTrustDomain = "trustloop-test.local"

func TestExtractPeerID_AcceptsValidPeer(t *testing.T) {
	ca := newTestCA(t, testTrustDomain)

	serverID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-gateway/sa/gateway")
	serverSVID := ca.issueSVID(t, serverID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	clientID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-sample/sa/sample-workload")
	clientSVID := ca.issueSVID(t, clientID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	got, rejected := dial(t, ca, serverSVID, clientTLSConfig(ca, clientSVID))
	if rejected != nil {
		t.Fatalf("expected the valid peer to be accepted, got rejected: %v", rejected)
	}
	if got != clientID {
		t.Fatalf("extracted peer ID = %q, want %q", got, clientID)
	}
}

func TestExtractPeerID_RejectsNoCertificate(t *testing.T) {
	ca := newTestCA(t, testTrustDomain)
	serverID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-gateway/sa/gateway")
	serverSVID := ca.issueSVID(t, serverID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	// No client certificate at all -- tlsconfig.MTLSServerConfig sets
	// tls.RequireAnyClientCert, so the handshake itself must fail before
	// ever reaching application code.
	clientCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // test dialer; only the server-side rejection is under test
	}

	_, rejected := dial(t, ca, serverSVID, clientCfg)
	if rejected == nil {
		t.Fatal("expected a connection with no client certificate to be rejected, but it was accepted")
	}
	if !strings.Contains(rejected.Error(), "certificate") {
		t.Errorf("rejection reason %q does not look like a missing-certificate error", rejected)
	}
}

func TestExtractPeerID_RejectsWrongTrustDomain(t *testing.T) {
	serverCA := newTestCA(t, testTrustDomain)
	serverID := spiffeid.RequireFromPath(serverCA.trustDomain, "/ns/trustloop-gateway/sa/gateway")
	serverSVID := serverCA.issueSVID(t, serverID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	// A DIFFERENT trust domain, with its own (otherwise perfectly valid,
	// properly CA-signed) SPIRE-shaped SVID. The server's bundle source
	// only knows about serverCA.trustDomain, so x509svid.ParseAndVerify
	// fails at the "get X.509 bundle for this SPIFFE ID's trust domain"
	// step -- it never even gets to signature verification. This is the
	// realistic stand-in for "a cert not issued by this trust domain's
	// SPIRE": cryptographically there is no difference between a real SVID
	// from a genuinely different trust domain and one from an attacker's
	// private CA claiming to be a different trust domain -- both fail
	// identically here, which is the correct behavior.
	otherCA := newTestCA(t, "other-trust-domain.example")
	otherID := spiffeid.RequireFromPath(otherCA.trustDomain, "/ns/trustloop-sample/sa/sample-workload")
	otherSVID := otherCA.issueSVID(t, otherID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	// Note: the client trusts the SERVER via serverCA (so the client itself
	// accepts the gateway's certificate and completes its side of the
	// handshake) while presenting otherSVID -- an SVID for a trust domain
	// the server has never heard of -- as its OWN identity. That's what
	// actually exercises the server-side rejection under test; if the
	// client's bundle source were otherCA instead, the client would reject
	// the *server's* certificate first and this test would be checking the
	// wrong side of the handshake.
	_, rejected := dial(t, serverCA, serverSVID, clientTLSConfig(serverCA, otherSVID))
	if rejected == nil {
		t.Fatal("expected a peer from a different trust domain to be rejected, but it was accepted")
	}
	if !strings.Contains(rejected.Error(), "bundle") {
		t.Errorf("rejection reason %q does not look like a trust-domain/bundle lookup failure", rejected)
	}
}

func TestExtractPeerID_RejectsSelfSignedJunkCert(t *testing.T) {
	serverCA := newTestCA(t, testTrustDomain)
	serverID := spiffeid.RequireFromPath(serverCA.trustDomain, "/ns/trustloop-gateway/sa/gateway")
	serverSVID := serverCA.issueSVID(t, serverID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	// Self-signed: syntactically a valid SPIFFE ID for the RIGHT trust
	// domain (so the bundle lookup above would succeed), but signed by a
	// key the server's trust bundle has never heard of -- the "self-signed
	// junk cert" case named explicitly in issue #3. This must fail at
	// signature/chain verification, distinctly from the wrong-trust-domain
	// case above (which fails earlier, at the bundle lookup).
	junkID := spiffeid.RequireFromPath(serverCA.trustDomain, "/ns/trustloop-sample/sa/impersonator")
	junkCert := selfSignedCert(t, junkID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	clientCfg := &tls.Config{
		Certificates:       []tls.Certificate{junkCert},
		InsecureSkipVerify: true, //nolint:gosec // test dialer; only the server-side rejection is under test
	}
	_, rejected := dial(t, serverCA, serverSVID, clientCfg)
	if rejected == nil {
		t.Fatal("expected a self-signed junk certificate to be rejected, but it was accepted")
	}
	if !strings.Contains(rejected.Error(), "verify leaf certificate") {
		t.Errorf("rejection reason %q does not look like a chain-verification failure", rejected)
	}
}

func TestExtractPeerID_RejectsExpiredCert(t *testing.T) {
	ca := newTestCA(t, testTrustDomain)
	serverID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-gateway/sa/gateway")
	serverSVID := ca.issueSVID(t, serverID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	// Signed by the REAL CA (so this isn't the self-signed-junk case, and
	// it's the right trust domain, so it's not that case either) but with
	// a validity window that already ended -- the one negative case that's
	// genuinely awkward to get a live SPIRE server to hand out on demand
	// (see the package-level test comment), which is exactly why it's
	// covered here against a CA this test fully controls.
	expiredID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-sample/sa/sample-workload")
	expiredSVID := ca.issueSVID(t, expiredID, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))

	_, rejected := dial(t, ca, serverSVID, clientTLSConfig(ca, expiredSVID))
	if rejected == nil {
		t.Fatal("expected an expired certificate to be rejected, but it was accepted")
	}
	if !strings.Contains(rejected.Error(), "expired") {
		t.Errorf("rejection reason %q does not look like an expiry failure", rejected)
	}
}

// --- test scaffolding -------------------------------------------------

// dial spins up a one-shot ServerTLSConfig-backed TLS listener presenting
// serverSVID, dials it once with clientCfg, and returns either the
// extracted peer ID (accept path) or the rejection error (reject path) --
// exactly mirroring what cmd/gateway/main.go's handleConn does with a real
// connection.
func dial(t *testing.T, serverBundle x509bundle.Source, serverSVID *x509svid.SVID, clientCfg *tls.Config) (spiffeid.ID, error) {
	t.Helper()

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer rawLn.Close()

	serverTLSCfg := ServerTLSConfig(serverSVID, serverBundle)
	ln := tls.NewListener(rawLn, serverTLSCfg)

	type serverResult struct {
		id  spiffeid.ID
		err error
	}
	resultCh := make(chan serverResult, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			resultCh <- serverResult{err: err}
			return
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		id, err := ExtractPeerID(ctx, conn.(*tls.Conn))
		resultCh <- serverResult{id: id, err: err}
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, dialErr := (&tls.Dialer{Config: clientCfg}).DialContext(dialCtx, "tcp", rawLn.Addr().String())
	if clientConn != nil {
		defer clientConn.Close()
	}

	select {
	case res := <-resultCh:
		// Prefer the server's own view of what happened -- it's the code
		// path under test (ExtractPeerID). The client-side dial error (if
		// any) is consistent with it but secondary.
		return res.id, res.err
	case <-time.After(5 * time.Second):
		if dialErr != nil {
			// The server never got far enough to Accept/handshake at all
			// (e.g. the client aborted before completing its side) -- the
			// client's error is the only signal we have.
			return spiffeid.ID{}, dialErr
		}
		t.Fatal("timed out waiting for server-side handshake result")
		return spiffeid.ID{}, nil
	}
}

// clientTLSConfig builds a client-side mTLS config that presents svid and
// accepts any server identity (tlsconfig.AuthorizeAny) -- these tests are
// about whether the SERVER (ExtractPeerID, via ServerTLSConfig) correctly
// accepts/rejects the CLIENT, not the reverse, so the client side
// deliberately doesn't pin an expected server ID the way
// identity.ClientTLSConfig (used by cmd/gateway-verify) does.
func clientTLSConfig(bundle x509bundle.Source, svid *x509svid.SVID) *tls.Config {
	return tlsconfig.MTLSClientConfig(svid, bundle, tlsconfig.AuthorizeAny())
}

// testCA is a minimal, self-contained X.509 CA used only to issue
// SPIRE-shaped SVIDs for these tests. It intentionally duplicates none of
// go-spiffe's own verification logic (that would defeat the point of these
// tests) -- it only issues certificates; ServerTLSConfig/ExtractPeerID
// (the code under test) do all of the actual verifying.
type testCA struct {
	trustDomain spiffeid.TrustDomain
	cert        *x509.Certificate
	key         *ecdsa.PrivateKey
	bundle      *x509bundle.Bundle
}

func newTestCA(t *testing.T, trustDomain string) *testCA {
	t.Helper()
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		t.Fatalf("parsing trust domain %q: %v", trustDomain, err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
		Subject:               pkix.Name{CommonName: "test CA for " + trustDomain},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signing CA certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}

	return &testCA{
		trustDomain: td,
		cert:        cert,
		key:         key,
		bundle:      x509bundle.FromX509Authorities(td, []*x509.Certificate{cert}),
	}
}

// GetX509BundleForTrustDomain lets *testCA itself be used directly as an
// x509bundle.Source, same as the real bundle would be.
func (ca *testCA) GetX509BundleForTrustDomain(td spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	return ca.bundle.GetX509BundleForTrustDomain(td)
}

func (ca *testCA) issueSVID(t *testing.T, id spiffeid.ID, notBefore, notAfter time.Time) *x509svid.SVID {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: id.String()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{id.URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("issuing SVID for %s: %v", id, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing issued SVID: %v", err)
	}
	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{leaf},
		PrivateKey:   key,
	}
}

// selfSignedCert builds a certificate carrying a SPIFFE URI SAN that is
// signed by its OWN key rather than any CA -- used for the
// self-signed-junk-cert test case.
func selfSignedCert(t *testing.T, id spiffeid.ID, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(t),
		Subject:      pkix.Name{CommonName: id.String()},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:         []*url.URL{id.URL()},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-signing certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial number: %v", err)
	}
	return serial
}
