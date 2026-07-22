// Command gateway is the TrustLoop enforcement gateway process.
//
// Per issue #3, it fetches its own SPIRE-issued SVID + trust bundle via the
// SPIFFE Workload API (workloadapi.NewX509Source -- the official go-spiffe
// client, not a hand-rolled Workload API caller), terminates mTLS
// connections, and for every peer that presents a valid SVID for this trust
// domain, extracts that peer's SPIFFE ID.
//
// Per issue #4, every extracted identity is then gated on a real OpenFGA
// authorization decision before the stand-in tool call is allowed through:
// the gateway calls OpenFGA's Check API (internal/authz) for the "agent ->
// can_call -> tool" relation, and every decision -- allow AND deny -- is
// written to a structured audit log (internal/audit) with who, what, when,
// and why, per trustloop/CLAUDE.md's non-negotiable.
//
// It stands in for the future MCP-protocol-aware gateway (see ROADMAP.md
// Phase 1) with the smallest possible protocol: read one newline-terminated
// line from the peer -- that line IS the name of the tool being requested
// (issue #4's minimal extension of issue #3's stand-in protocol: "a tool
// call" now means "which tool", not just an opaque message) -- and reply
// with an ack that states the decision (allow/deny), so the outcome is
// provable from the *caller's* side too, not just a server-side log line an
// external verifier has to take on faith.
//
// Explicitly OUT of scope for this binary (see issue #4's scope boundary):
//   - No MCP wire protocol parsing -- "which tool" is the entire stand-in
//     request line, not a parsed field within a larger structured message.
//   - No composition with the "user -> can_act_on_behalf_of -> agent"
//     delegation hop -- see internal/authz and internal/audit's doc
//     comments (ROADMAP.md Phase 2).
//   - No actual tool-call forwarding -- there is no downstream tool server
//     yet for an allowed call to be proxied to; "allow" here means "the
//     gateway's authorization check passed", not "the tool ran".
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spiffe/go-spiffe/v2/workloadapi"

	"github.com/devopsloop-ss/trustloop/internal/audit"
	"github.com/devopsloop-ss/trustloop/internal/authz"
	"github.com/devopsloop-ss/trustloop/internal/identity"
)

func main() {
	socket := flag.String("workload-api-socket", "", "SPIFFE Workload API socket address (e.g. unix:///spiffe-workload-api/spire-agent.sock). If empty, go-spiffe falls back to the SPIFFE_ENDPOINT_SOCKET environment variable.")
	listenAddr := flag.String("listen-addr", ":8443", "address to accept mTLS connections on")
	openfgaAPIURL := flag.String("openfga-api-url", "http://openfga.openfga.svc.cluster.local:8080", "OpenFGA HTTP API base URL. Defaults to the in-cluster Service DNS name (see hack/openfga/setup.sh) since the gateway runs in-cluster; override to a localhost port-forward (see hack/openfga/setup.sh's port-forward) for local/out-of-cluster runs.")
	openfgaStoreName := flag.String("openfga-store-name", "trustloop-dev", "OpenFGA store to authorize against. Must already exist (created by cmd/openfga-verify / hack/openfga/setup.sh) -- the gateway finds it, it never creates one.")
	flag.Parse()

	logger := log.New(os.Stdout, "gateway: ", log.LstdFlags|log.Lmicroseconds)
	// Deliberately a SEPARATE, prefix-free, timestamp-free *log.Logger
	// writing to the same stdout: every line this one emits is a bare JSON
	// object (see internal/audit), so it stays directly `jq`-able out of
	// `kubectl logs` without the human-readable "gateway: 2026/... " prefix
	// the narrative logger above adds. Both interleave in the same pod log
	// stream, but each line is unambiguous about which kind it is (starts
	// with "gateway: " or starts with "{").
	auditLogger := audit.New(os.Stdout)

	checker, err := authz.NewChecker(*openfgaAPIURL, *openfgaStoreName)
	if err != nil {
		// Fail loudly at startup rather than serving connections with no
		// way to authorize them. The alternative -- start anyway and
		// fail-closed-deny every request once a connection actually comes
		// in -- would look like the gateway is up and healthy while every
		// call is silently rejected; better to never reach Ready at all.
		logger.Fatalf("connecting to OpenFGA (issue #4 requires a real authorization check for every request, not a stub): %v", err)
	}

	if err := run(*socket, *listenAddr, checker, auditLogger, logger); err != nil {
		logger.Fatalf("exiting: %v", err)
	}
}

// canCallChecker is the subset of *authz.Checker that handleConn depends
// on, so tests can supply a fake OpenFGA response without a live OpenFGA
// server (see main_test.go) while production code (main, above) always
// wires in the real *authz.Checker calling the real OpenFGA Check API --
// never a stub standing in for the actual authorization engine itself.
type canCallChecker interface {
	CheckCanCall(ctx context.Context, agentSubject, tool string) (authz.Decision, error)
}

func run(socket, listenAddr string, checker canCallChecker, auditLogger *audit.Logger, logger *log.Logger) error {
	// Shut down cleanly on SIGTERM (how Kubernetes asks a pod to stop) as
	// well as SIGINT (local Ctrl-C during development), rather than
	// getting killed mid-handshake.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	var opts []workloadapi.X509SourceOption
	if socket != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	}

	// This is the first MVP acceptance criterion from ROADMAP.md Phase 1:
	// "A workload gets a real SPIRE SVID automatically on startup -- no
	// manual cert copying." NewX509Source blocks until the SPIRE agent (via
	// the Workload API, over the Unix socket the SPIFFE CSI driver mounts
	// into this pod -- see deploy/gateway/chart) delivers this process's
	// own SVID and the trust bundle for its trust domain, and keeps both
	// updated (rotated) in the background for as long as the source is
	// open. There is no long-lived credential anywhere in this process:
	// if the pod restarts, it gets a freshly issued SVID the same way, and
	// the SVID SPIRE hands out here is short-lived by SPIRE's own default
	// TTL, not something this code controls or extends.
	source, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return fmt.Errorf("fetching the gateway's own SVID from the SPIRE Workload API: %w", err)
	}
	defer source.Close()

	ownSVID, err := source.GetX509SVID()
	if err != nil {
		return fmt.Errorf("reading fetched SVID: %w", err)
	}
	logger.Printf("own identity: %s", ownSVID.ID)

	// svid.Source and bundle.Source here are the SAME *workloadapi.X509Source
	// -- it implements both interfaces (it presents this gateway's SVID to
	// peers, and supplies the trust bundle used to verify peers' SVIDs).
	tlsConfig := identity.ServerTLSConfig(source, source)

	rawLn, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", listenAddr, err)
	}
	ln := tls.NewListener(rawLn, tlsConfig)
	defer ln.Close()
	logger.Printf("listening for mTLS connections on %s", listenAddr)

	// Close the listener when asked to shut down, which unblocks the
	// Accept() loop below with a well-understood error instead of leaving
	// it hanging.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				logger.Printf("shutting down: %v", ctx.Err())
				return nil
			}
			logger.Printf("accept error: %v", err)
			continue
		}
		tlsConn, ok := conn.(*tls.Conn)
		if !ok {
			// Unreachable in practice -- ln is a tls.Listener, every
			// connection it Accepts is a *tls.Conn. Guarding anyway rather
			// than blindly asserting, since a panic here would take down
			// every other in-flight connection's goroutine group with it.
			logger.Printf("accepted a non-TLS connection from %s (unexpected) -- closing", conn.RemoteAddr())
			_ = conn.Close()
			continue
		}
		go handleConn(ctx, tlsConn, checker, auditLogger, logger)
	}
}

// handleConn extracts the peer's SPIFFE identity (rejecting the connection
// if it doesn't have one), reads the stand-in "which tool" request
// described in the package doc comment, checks OpenFGA's can_call relation
// for that (identity, tool) pair, writes a structured audit log entry for
// the decision (issue #4's non-negotiable: every decision, allow AND deny),
// and replies to the peer with the outcome.
func handleConn(ctx context.Context, conn *tls.Conn, checker canCallChecker, auditLogger *audit.Logger, logger *log.Logger) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	peerID, err := identity.ExtractPeerID(ctx, conn)
	if err != nil {
		// The reject path: see internal/identity.ExtractPeerID's doc
		// comment for why the underlying error already explains *which*
		// case this was (no cert / expired / wrong trust domain /
		// self-signed junk not in the bundle).
		//
		// Deliberately NOT an audit.Logger entry: there is no SPIFFE
		// identity here to attribute a decision to -- this is a rejected
		// mTLS handshake, not an authorization decision about a known
		// caller. It's still fully logged (via the narrative logger, same
		// as issue #3), just not as an authz Entry with a caller identity
		// that doesn't exist.
		logger.Printf("REJECTED connection from %s: %v", remote, err)
		return
	}
	logger.Printf("ACCEPTED connection from %s: peer SPIFFE ID = %s", remote, peerID)

	// Stand-in "MCP tool call" (see package doc comment: real MCP wire
	// protocol parsing is out of scope for this ticket). One
	// newline-terminated line is enough to prove the extracted identity is
	// actually usable by whatever comes after the handshake -- not just
	// logged and discarded. As of issue #4, that line IS the name of the
	// tool being requested.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	tool := strings.TrimSpace(line)
	if tool == "" {
		if err != nil {
			logger.Printf("peer %s (%s) disconnected before sending a stand-in tool call: %v", remote, peerID, err)
		}
		return
	}
	logger.Printf("stand-in tool call from %s: tool=%q", peerID, tool)

	// The actual authorization check (issue #4's core job): the OpenFGA
	// "user" is derived ONLY from the cryptographically verified peerID
	// above, never from anything read off the wire -- see
	// authz.SubjectForSPIFFEID's doc comment for why that matters.
	subject := authz.SubjectForSPIFFEID(peerID)
	decision, checkErr := checker.CheckCanCall(ctx, subject, tool)

	entry := audit.Entry{
		CallerSPIFFEID: peerID.String(),
		OnBehalfOf:     audit.OnBehalfOfUnresolved,
		Tool:           tool,
		FGASubject:     decision.Subject,
		FGARelation:    decision.Relation,
		FGAObject:      decision.Object,
		RemoteAddr:     remote,
	}

	var reply string
	if checkErr != nil {
		// Fail CLOSED: an OpenFGA call that errored (network failure, store
		// gone, etc.) is not evidence of a grant. See
		// authz.Checker.CheckCanCall's doc comment -- this is the one place
		// that contract is enforced.
		entry.Decision = audit.Deny
		entry.Reason = fmt.Sprintf("OpenFGA check failed -- failing closed (deny): %v", checkErr)
		entry.Error = checkErr.Error()
		reply = fmt.Sprintf("ack decision=deny peer_spiffe_id=%s tool=%q reason=%q\n", peerID, tool, entry.Reason)
	} else if decision.Allowed {
		entry.Decision = audit.Allow
		entry.Reason = decision.Reason
		reply = fmt.Sprintf("ack decision=allow peer_spiffe_id=%s tool=%q\n", peerID, tool)
	} else {
		entry.Decision = audit.Deny
		entry.Reason = decision.Reason
		reply = fmt.Sprintf("ack decision=deny peer_spiffe_id=%s tool=%q reason=%q\n", peerID, tool, entry.Reason)
	}

	// This is the audit log entry itself -- written for BOTH allow and deny,
	// unconditionally, before the reply is even sent, so a crash or failed
	// write on the reply path below can never suppress the record of the
	// decision that was actually made.
	auditLogger.Log(entry)
	logger.Printf("%s: peer=%s tool=%q reason=%s", strings.ToUpper(string(entry.Decision)), peerID, tool, entry.Reason)

	// Note: an "allow" here means the authorization check passed -- there is
	// no downstream tool server yet for the call to be forwarded to (see
	// package doc comment). Forwarding is future work once real MCP
	// protocol parsing exists.
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(reply)); err != nil {
		logger.Printf("writing reply to %s (%s): %v", remote, peerID, err)
	}
}
