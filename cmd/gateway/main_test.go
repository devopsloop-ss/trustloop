package main

// Unit tests for issue #4's core job: given an already-verified peer
// identity and a stand-in tool-call request, handleConn calls the
// authorization checker, writes exactly one structured audit.Entry
// reflecting the real outcome, and replies to the peer accordingly -- for
// BOTH the allow and the deny path.
//
// These tests exercise handleConn against a synthetic CA (same pattern as
// internal/identity/identity_test.go -- see that file's package comment for
// why a controlled CA is used rather than a live SPIRE deployment) and a
// FAKE canCallChecker (not a live OpenFGA server): unit tests need to
// reliably produce both a granted and an ungranted outcome on demand
// without depending on external state. The real OpenFGA Check call itself
// is exercised separately, live, by hack/gateway/setup.sh's end-to-end
// verification (see cmd/gateway-verify) -- that is what actually proves
// "gated by a real OpenFGA Check", not these tests. These tests prove the
// gateway's own logic around that call: it reaches the checker with the
// right (subject, tool) derived from the verified identity, and it does the
// right thing -- for both outcomes -- with whatever the checker returns.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"log"
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

	"github.com/devopsloop-ss/trustloop/internal/audit"
	"github.com/devopsloop-ss/trustloop/internal/authz"
)

const testTrustDomain = "trustloop-gateway-test.local"

// fakeChecker is a canCallChecker whose answer is scripted per test --
// standing in for OpenFGA's Check API so these tests can reliably exercise
// both the allow and deny path without a live OpenFGA server. It also
// records exactly what it was asked, so tests can assert the gateway
// derived the right OpenFGA subject/tool from the verified identity and
// request.
type fakeChecker struct {
	allow      bool
	err        error
	gotSubject string
	gotTool    string
}

func (f *fakeChecker) CheckCanCall(_ context.Context, agentSubject, tool string) (authz.Decision, error) {
	f.gotSubject = agentSubject
	f.gotTool = tool
	if f.err != nil {
		return authz.Decision{Subject: agentSubject, Relation: authz.Relation, Object: "tool:" + tool}, f.err
	}
	return authz.Decision{
		Subject:  agentSubject,
		Relation: authz.Relation,
		Object:   "tool:" + tool,
		Allowed:  f.allow,
		Reason:   fmt.Sprintf("fake Check(user=%s, relation=%s, object=tool:%s) returned allowed=%v", agentSubject, authz.Relation, tool, f.allow),
	}, nil
}

func TestHandleConn_AllowedToolCall(t *testing.T) {
	ca := newTestCA(t, testTrustDomain)
	clientID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-sample/sa/sample-workload")

	checker := &fakeChecker{allow: true}
	var auditBuf bytes.Buffer
	reply := runHandleConn(t, ca, clientID, checker, audit.New(&auditBuf), "search")

	if !strings.Contains(reply, "decision=allow") {
		t.Fatalf("reply = %q, want it to contain \"decision=allow\"", reply)
	}
	if !strings.Contains(reply, "peer_spiffe_id="+clientID.String()) {
		t.Errorf("reply = %q, want it to contain the caller's SPIFFE ID", reply)
	}

	entry := decodeAuditEntry(t, auditBuf.Bytes())
	if entry.Decision != audit.Allow {
		t.Errorf("audit entry Decision = %q, want %q", entry.Decision, audit.Allow)
	}
	if entry.CallerSPIFFEID != clientID.String() {
		t.Errorf("audit entry CallerSPIFFEID = %q, want %q", entry.CallerSPIFFEID, clientID.String())
	}
	if entry.Tool != "search" {
		t.Errorf("audit entry Tool = %q, want %q", entry.Tool, "search")
	}
	if entry.OnBehalfOf != audit.OnBehalfOfUnresolved {
		t.Errorf("audit entry OnBehalfOf = %q, want the documented placeholder %q", entry.OnBehalfOf, audit.OnBehalfOfUnresolved)
	}
	if entry.Reason == "" {
		t.Error("audit entry Reason is empty -- every decision must explain why")
	}
	if entry.Error != "" {
		t.Errorf("audit entry Error = %q, want empty on a successful check", entry.Error)
	}

	wantSubject := "agent:ns/trustloop-sample/sa/sample-workload"
	if checker.gotSubject != wantSubject {
		t.Errorf("checker was asked about subject %q, want %q (derived from the verified SPIFFE ID, not client input)", checker.gotSubject, wantSubject)
	}
	if checker.gotTool != "search" {
		t.Errorf("checker was asked about tool %q, want %q", checker.gotTool, "search")
	}
}

func TestHandleConn_DeniedToolCall(t *testing.T) {
	ca := newTestCA(t, testTrustDomain)
	clientID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-sample/sa/sample-workload")

	checker := &fakeChecker{allow: false}
	var auditBuf bytes.Buffer
	reply := runHandleConn(t, ca, clientID, checker, audit.New(&auditBuf), "delete_prod_db")

	if !strings.Contains(reply, "decision=deny") {
		t.Fatalf("reply = %q, want it to contain \"decision=deny\"", reply)
	}

	entry := decodeAuditEntry(t, auditBuf.Bytes())
	if entry.Decision != audit.Deny {
		t.Errorf("audit entry Decision = %q, want %q", entry.Decision, audit.Deny)
	}
	if entry.Tool != "delete_prod_db" {
		t.Errorf("audit entry Tool = %q, want %q", entry.Tool, "delete_prod_db")
	}
	if entry.Reason == "" {
		t.Error("audit entry Reason is empty -- a denial must say why")
	}
}

// TestHandleConn_FailsClosedOnOpenFGAError proves the fail-closed contract
// documented on authz.Checker.CheckCanCall: if the OpenFGA call itself
// errors, the connection is denied, never allowed, and the audit entry
// records the underlying error.
func TestHandleConn_FailsClosedOnOpenFGAError(t *testing.T) {
	ca := newTestCA(t, testTrustDomain)
	clientID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-sample/sa/sample-workload")

	checker := &fakeChecker{err: fmt.Errorf("simulated OpenFGA outage")}
	var auditBuf bytes.Buffer
	reply := runHandleConn(t, ca, clientID, checker, audit.New(&auditBuf), "search")

	if !strings.Contains(reply, "decision=deny") {
		t.Fatalf("reply = %q, want a deny reply when the OpenFGA check errors (fail closed)", reply)
	}

	entry := decodeAuditEntry(t, auditBuf.Bytes())
	if entry.Decision != audit.Deny {
		t.Errorf("audit entry Decision = %q, want %q (fail closed on error)", entry.Decision, audit.Deny)
	}
	if entry.Error == "" {
		t.Error("audit entry Error is empty, want the underlying OpenFGA error recorded")
	}
}

// decodeAuditEntry expects buf to contain exactly one ndjson line (the
// audit.Logger's output for a single handleConn call) and decodes it.
func decodeAuditEntry(t *testing.T, buf []byte) audit.Entry {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(buf)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one audit log line, got %d: %q", len(lines), buf)
	}
	var entry audit.Entry
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("audit log line is not valid JSON: %v (line: %q)", err, lines[0])
	}
	return entry
}

// runHandleConn spins up a one-shot ServerTLSConfig-backed listener (the
// exact same server TLS config production code uses -- see
// internal/identity.ServerTLSConfig), dials it with a real, validly-issued
// client SVID, sends tool as the stand-in tool-call line, and returns the
// gateway's reply line.
func runHandleConn(t *testing.T, ca *testCA, clientID spiffeid.ID, checker canCallChecker, auditLogger *audit.Logger, tool string) string {
	t.Helper()

	serverID := spiffeid.RequireFromPath(ca.trustDomain, "/ns/trustloop-gateway/sa/gateway")
	serverSVID := ca.issueSVID(t, serverID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))
	clientSVID := ca.issueSVID(t, clientID, time.Now().Add(-time.Minute), time.Now().Add(time.Hour))

	rawLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	defer rawLn.Close()

	// import from the package under test's own ServerTLSConfig usage --
	// mirrors run()'s wiring exactly.
	serverTLSCfg := serverTLSConfigForTest(serverSVID, ca)
	ln := tls.NewListener(rawLn, serverTLSCfg)

	logger := log.New(&bytes.Buffer{}, "", 0) // narrative logger's output isn't under test here
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			t.Errorf("accepted connection is not *tls.Conn")
			return
		}
		handleConn(context.Background(), tlsConn, checker, auditLogger, logger)
	}()

	clientTLSCfg := tlsconfig.MTLSClientConfig(clientSVID, ca, tlsconfig.AuthorizeID(serverID))
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{Config: clientTLSCfg}).DialContext(dialCtx, "tcp", rawLn.Addr().String())
	if err != nil {
		t.Fatalf("dialing gateway: %v", err)
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "%s\n", tool); err != nil {
		t.Fatalf("sending stand-in tool call: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("reading gateway reply: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for handleConn to finish")
	}

	return reply
}

// serverTLSConfigForTest builds the same *tls.Config production code builds
// via internal/identity.ServerTLSConfig, without importing that package
// twice under a different name -- it's re-declared here rather than
// imported because internal/identity.ServerTLSConfig takes an
// x509svid.Source/x509bundle.Source, and *testCA/*x509svid.SVID already
// satisfy those interfaces exactly the way identity_test.go's helpers do.
func serverTLSConfigForTest(svid *x509svid.SVID, bundle x509bundle.Source) *tls.Config {
	return tlsconfig.MTLSServerConfig(svid, bundle, tlsconfig.AuthorizeAny())
}

// --- test CA scaffolding (same pattern as internal/identity/identity_test.go) ---

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

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generating serial number: %v", err)
	}
	return serial
}
