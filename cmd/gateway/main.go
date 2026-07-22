// Command gateway is the TrustLoop enforcement gateway process (scaffold).
//
// Per issue #3, this binary proves ONLY the identity-extraction half of the
// gateway: it fetches its own SPIRE-issued SVID + trust bundle via the
// SPIFFE Workload API (workloadapi.NewX509Source -- the official go-spiffe
// client, not a hand-rolled Workload API caller), terminates mTLS
// connections, and for every peer that presents a valid SVID for this trust
// domain, extracts and logs that peer's SPIFFE ID.
//
// It stands in for the future MCP-protocol-aware gateway (see ROADMAP.md
// Phase 1) with the smallest possible protocol: read one newline-terminated
// line from the peer (a stand-in "tool call"), log who sent it, and echo an
// acknowledgement that includes the SPIFFE ID the gateway extracted -- so
// the extraction result is provable from the *caller's* side too, not just
// a server-side log line an external verifier has to take on faith.
//
// Explicitly OUT of scope for this binary (see issue #3's scope boundary,
// and issues #4/#6):
//   - No OpenFGA authorization check -- every peer with a valid SPIFFE ID
//     for this trust domain is accepted (see internal/identity's
//     ServerTLSConfig doc comment for why that's the correct scope, not a
//     shortcut).
//   - No structured allow/deny audit log -- issue #4's job, once there is
//     an actual authorization decision to log. What IS logged here is
//     narrower: every accepted connection's extracted SPIFFE ID, and every
//     rejected handshake's reason, which is what this ticket has to prove
//     works.
//   - No MCP wire protocol parsing.
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

	"github.com/devopsloop-ss/trustloop/internal/identity"
)

func main() {
	socket := flag.String("workload-api-socket", "", "SPIFFE Workload API socket address (e.g. unix:///spiffe-workload-api/spire-agent.sock). If empty, go-spiffe falls back to the SPIFFE_ENDPOINT_SOCKET environment variable.")
	listenAddr := flag.String("listen-addr", ":8443", "address to accept mTLS connections on")
	flag.Parse()

	logger := log.New(os.Stdout, "gateway: ", log.LstdFlags|log.Lmicroseconds)

	if err := run(*socket, *listenAddr, logger); err != nil {
		logger.Fatalf("exiting: %v", err)
	}
}

func run(socket, listenAddr string, logger *log.Logger) error {
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
		go handleConn(ctx, tlsConn, logger)
	}
}

// handleConn extracts the peer's SPIFFE identity (rejecting the connection
// if it doesn't have one) and then runs the stand-in "MCP tool call"
// exchange described in the package doc comment.
func handleConn(ctx context.Context, conn *tls.Conn, logger *log.Logger) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()

	peerID, err := identity.ExtractPeerID(ctx, conn)
	if err != nil {
		// The reject path: see internal/identity.ExtractPeerID's doc
		// comment for why the underlying error already explains *which*
		// case this was (no cert / expired / wrong trust domain /
		// self-signed junk not in the bundle).
		logger.Printf("REJECTED connection from %s: %v", remote, err)
		return
	}
	logger.Printf("ACCEPTED connection from %s: peer SPIFFE ID = %s", remote, peerID)

	// Stand-in "MCP tool call" (see package doc comment: real MCP wire
	// protocol parsing is out of scope for this ticket). One
	// newline-terminated line is enough to prove the extracted identity is
	// actually usable by whatever comes after the handshake -- not just
	// logged and discarded.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		if err != nil {
			logger.Printf("peer %s (%s) disconnected before sending a stand-in tool call: %v", remote, peerID, err)
		}
		return
	}
	logger.Printf("stand-in tool call from %s: %q", peerID, trimmed)

	ack := fmt.Sprintf("ack peer_spiffe_id=%s tool_call=%q\n", peerID, trimmed)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(ack)); err != nil {
		logger.Printf("writing ack to %s (%s): %v", remote, peerID, err)
	}
}
