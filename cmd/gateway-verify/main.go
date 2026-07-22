// Command gateway-verify proves -- against a real, running gateway, not
// just via unit tests -- that issue #3's and issue #4's acceptance criteria
// hold:
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
//  3. (issue #4) A tool call for a tool this identity IS granted (via a real
//     tuple, written by this program into the SAME OpenFGA store
//     cmd/openfga-verify uses -- see writeGrantedTuple below) is allowed by
//     the live gateway, gated by a real OpenFGA Check call -- not a stub.
//  4. (issue #4) A tool call for a tool this identity is NOT granted is
//     denied by the live gateway, again via a real OpenFGA Check call.
//
// This follows the same pattern as cmd/openfga-verify: a small, re-runnable
// Go program that performs the real protocol exchange and reports PASS/FAIL
// per check, exiting non-zero if anything didn't match what was expected --
// not "the process started" as the bar for success.
//
// The valid-peer checks (including both authz checks, which need a peer the
// gateway can identify in the first place) need an actual SPIRE-issued
// SVID, which only exists for a workload the K8s workload attestor
// recognizes -- so this program is meant to run as a pod matching an
// existing registration entry (see hack/gateway/setup.sh, which runs it as
// the trustloop-sample / sample-workload identity already created by
// hack/spire/setup.sh, reusing it rather than minting a second one). The
// invalid-peer checks need no SPIRE identity at all -- that's the point --
// so they build their own throwaway, deliberately-untrusted certificates.
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

	"github.com/openfga/go-sdk/client"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/devopsloop-ss/trustloop/internal/authz"
	"github.com/devopsloop-ss/trustloop/internal/identity"
)

// grantedTool and ungrantedTool are the two tool names used for the issue
// #4 checks. grantedTool has a real tuple written for it (see
// writeGrantedTuple); ungrantedTool deliberately never does -- its whole
// purpose is to prove the deny path is real, not a stub that always says
// yes.
const (
	grantedTool   = "gateway-verify-granted-tool"
	ungrantedTool = "gateway-verify-ungranted-tool"
)

func main() {
	socket := flag.String("workload-api-socket", "", "SPIFFE Workload API socket address for the valid-peer check. If empty, falls back to SPIFFE_ENDPOINT_SOCKET.")
	gatewayAddr := flag.String("gateway-addr", "", "host:port of the gateway's mTLS listener")
	expectedGatewayID := flag.String("expected-gateway-id", "", "the gateway's expected SPIFFE ID (spiffe://...), pinned by the valid-peer client")
	dialTimeout := flag.Duration("dial-timeout", 10*time.Second, "timeout for each dial attempt")
	openfgaAPIURL := flag.String("openfga-api-url", "http://openfga.openfga.svc.cluster.local:8080", "OpenFGA HTTP API base URL -- same store the live gateway checks against (see cmd/gateway's flag of the same name).")
	openfgaStoreName := flag.String("openfga-store-name", "trustloop-dev", "OpenFGA store name -- must be the SAME store cmd/openfga-verify created and the gateway checks against, never a parallel one.")
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

	if err := run(*socket, *gatewayAddr, gatewayID, *dialTimeout, *openfgaAPIURL, *openfgaStoreName); err != nil {
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

func run(socket, gatewayAddr string, gatewayID spiffeid.ID, dialTimeout time.Duration, openfgaAPIURL, openfgaStoreName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var results []result

	// Fetch this process's own SPIRE-issued SVID ONCE and reuse it for every
	// check below that needs a valid peer identity (the plain accept check
	// and both issue #4 authz checks) -- they're all, cryptographically,
	// the exact same workload identity, so there is no reason to pull a
	// fresh SVID from the Workload API three separate times.
	var opts []workloadapi.X509SourceOption
	if socket != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	}
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return fmt.Errorf("fetching this process's own SVID from the SPIRE Workload API: %w", err)
	}
	defer source.Close()

	ownSVID, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("reading fetched SVID: %w", err)
	}

	// --- issue #4 setup: write a real can_call tuple, into the SAME
	// OpenFGA store the live gateway checks against, granting THIS
	// identity's derived OpenFGA subject permission to call grantedTool.
	// This has to happen before the authz checks below -- it's what makes
	// "genuinely granted" case genuine (a real tuple OpenFGA will actually
	// find), not something asserted about a mock. -------------------------
	if err := writeGrantedTuple(ctx, openfgaAPIURL, openfgaStoreName, ownSVID.ID); err != nil {
		return fmt.Errorf("writing the granted can_call tuple for the live authz checks: %w", err)
	}

	// --- Check 1: a real SPIRE-issued SVID is accepted, and the identity
	// the gateway echoes back in its ack matches this process's own SPIFFE
	// ID exactly -- proving extraction produced the *correct* ID, not just
	// *an* ID. This uses grantedTool so the connection also succeeds all
	// the way through the (issue #4) authz check, rather than conflating
	// "was the peer accepted" with "was the request denied for an unrelated
	// reason". ------------------------------------------------------------
	r, err := checkValidPeer(ctx, source, ownSVID, gatewayAddr, gatewayID, dialTimeout)
	if err != nil {
		return fmt.Errorf("running valid-peer check: %w", err)
	}
	results = append(results, r)

	// --- Checks 2-3 (issue #4): a real, live OpenFGA Check call gates the
	// gateway's decision -- once for a tool this identity IS granted (via
	// the tuple just written above) and once for a tool it is NOT. Both
	// dial with the SAME real SPIRE identity as check 1; only the
	// requested tool differs, isolating the authz decision as the only
	// variable under test. ------------------------------------------------
	results = append(results, checkAuthz(ctx, source, ownSVID, gatewayAddr, gatewayID, dialTimeout, grantedTool, "allow"))
	results = append(results, checkAuthz(ctx, source, ownSVID, gatewayAddr, gatewayID, dialTimeout, ungrantedTool, "deny"))

	// --- Checks 4-6: peers with no valid SPIFFE identity are rejected ---
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
	fmt.Println("all checks passed: a real SPIRE identity is accepted and correctly extracted; a real OpenFGA Check grants and denies tool calls exactly as tupled; invalid peers are rejected")
	return nil
}

// writeGrantedTuple writes (agent:<subject derived from ownID>, can_call,
// tool:grantedTool) into the OpenFGA store the live gateway checks against
// -- using authz.SubjectForSPIFFEID, the EXACT SAME derivation the gateway
// itself uses (internal/authz), so this tuple's subject is guaranteed to
// match whatever the gateway computes for this identity, not a
// hand-maintained parallel guess at the same string.
//
// Deliberately does NOT write anything for ungrantedTool -- see that
// constant's doc comment. Write is idempotent (duplicate tuples ignored),
// same as cmd/openfga-verify's writes, so re-running this program (e.g.
// hack/gateway/setup.sh re-run) is safe.
func writeGrantedTuple(ctx context.Context, apiURL, storeName string, ownID spiffeid.ID) error {
	fga, err := client.NewSdkClient(&client.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		return fmt.Errorf("constructing OpenFGA client for %s: %w", apiURL, err)
	}

	listResp, err := fga.ListStores(ctx).Options(client.ClientListStoresOptions{Name: &storeName}).Execute()
	if err != nil {
		return fmt.Errorf("listing OpenFGA stores: %w", err)
	}
	var storeID string
	for _, s := range listResp.Stores {
		if s.Name == storeName {
			storeID = s.Id
			break
		}
	}
	if storeID == "" {
		return fmt.Errorf("OpenFGA store %q not found -- run hack/openfga/setup.sh first", storeName)
	}
	if err := fga.SetStoreId(storeID); err != nil {
		return fmt.Errorf("setting store id: %w", err)
	}

	subject := authz.SubjectForSPIFFEID(ownID)
	_, err = fga.Write(ctx).
		Body(client.ClientWriteRequest{
			Writes: []client.ClientTupleKey{
				{User: subject, Relation: authz.Relation, Object: "tool:" + grantedTool},
			},
		}).
		Options(client.ClientWriteOptions{
			Conflict: client.ClientWriteConflictOptions{
				OnDuplicateWrites: client.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
			},
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("writing tuple (%s, %s, tool:%s): %w", subject, authz.Relation, grantedTool, err)
	}
	fmt.Printf("granted tuple written (or already present): (%s, %s, tool:%s)\n", subject, authz.Relation, grantedTool)
	return nil
}

// checkValidPeer dials the gateway with the given real SVID, expecting
// acceptance, a correctly-extracted identity echoed back, and (since it
// requests grantedTool, per writeGrantedTuple above) an allow decision.
func checkValidPeer(ctx context.Context, svidSource *workloadapi.X509Source, ownSVID *x509svid.SVID, gatewayAddr string, gatewayID spiffeid.ID, dialTimeout time.Duration) (result, error) {
	name := fmt.Sprintf("real SPIRE SVID (%s) is accepted and correctly identified", ownSVID.ID)
	tlsConfig := identity.ClientTLSConfig(svidSource, svidSource, gatewayID)

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(dialCtx, "tcp", gatewayAddr)
	if err != nil {
		return result{name: name, want: "accept", got: "reject", detail: err.Error()}, nil
	}
	defer conn.Close()

	ack, err := sendAndReadAck(conn, grantedTool)
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

// checkAuthz (issue #4) dials the gateway with the given real SVID, sends
// tool as the stand-in tool-call request, and expects the gateway's real
// OpenFGA Check-backed decision in the ack to be wantDecision ("allow" or
// "deny").
func checkAuthz(ctx context.Context, svidSource *workloadapi.X509Source, ownSVID *x509svid.SVID, gatewayAddr string, gatewayID spiffeid.ID, dialTimeout time.Duration, tool, wantDecision string) result {
	var name string
	if wantDecision == "deny" {
		name = fmt.Sprintf("live OpenFGA Check: ungranted tool %q is denied for this identity", tool)
	} else {
		name = fmt.Sprintf("live OpenFGA Check: granted tool %q is allowed for this identity", tool)
	}
	tlsConfig := identity.ClientTLSConfig(svidSource, svidSource, gatewayID)

	dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	conn, err := (&tls.Dialer{Config: tlsConfig}).DialContext(dialCtx, "tcp", gatewayAddr)
	if err != nil {
		return result{name: name, want: wantDecision, got: "connect-failed", detail: err.Error()}
	}
	defer conn.Close()

	ack, err := sendAndReadAck(conn, tool)
	if err != nil {
		return result{name: name, want: wantDecision, got: "no-ack", detail: fmt.Sprintf("connected but tool-call exchange failed: %v", err)}
	}

	got := "unknown"
	switch {
	case strings.Contains(ack, "decision=allow"):
		got = "allow"
	case strings.Contains(ack, "decision=deny"):
		got = "deny"
	}
	return result{name: name, want: wantDecision, got: got, detail: "ack: " + ack}
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
