// Package audit implements TrustLoop's structured allow/deny decision log.
//
// Scope (issue #4; trustloop/CLAUDE.md non-negotiable: "Every allow/deny
// decision must be logged with enough detail to answer 'who, on whose
// behalf, called what, when, why allowed/denied' -- no exceptions, from the
// first commit that makes a real authorization check."). This package is
// that log: one structured Entry per decision, covering both outcomes
// (allow AND deny), never free text.
//
// Format: newline-delimited JSON (JSON Lines / ndjson) -- one Entry object
// per line, written verbatim with no other log framing mixed into the same
// stream. This is a deliberate stepping stone toward ROADMAP.md Phase 4
// ("queryable audit log, not just structured logs on disk"): ndjson is
// directly queryable today with `kubectl logs ... | jq 'select(.decision ==
// "deny")'`, and it's also the natural line-oriented input format for
// whatever eventually ships this log to a real queryable store (a log
// pipeline, a database) without needing the emission format itself
// rewritten later -- only the destination changes.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// OnBehalfOfUnresolved is the placeholder value for Entry.OnBehalfOf until
// the gateway composes the "user -> can_act_on_behalf_of -> agent"
// delegation hop into its decision (ROADMAP.md Phase 2: "Multi-hop
// delegation... each hop scoped down").
//
// Issue #4's authorization check (internal/authz) is deliberately scoped to
// just "agent -> can_call -> tool" (see that package's doc comment), and the
// gateway's current stand-in wire protocol (see cmd/gateway) carries no
// separate "delegating user" field at all yet -- there is genuinely nothing
// honest to log here beyond an explicit placeholder. The JSON key is always
// present (never omitted) precisely so a future consumer of this log can
// filter/alert on "on_behalf_of == unresolved" today, rather than having to
// guess whether a missing key means "not delegated" or "we forgot to log
// it".
const OnBehalfOfUnresolved = "unresolved: Phase 1 gateway checks agent->tool (can_call) only, see ROADMAP.md Phase 2"

// Decision is the outcome of an authorization check, as a string so it
// serializes to something a human or `jq` can read directly rather than a
// bare boolean.
type Decision string

const (
	Allow Decision = "allow"
	Deny  Decision = "deny"
)

// Entry is one allow/deny decision record. Field names are the stable,
// queryable schema this ticket's non-negotiable asks for -- who, on whose
// behalf, what, when, why -- plus the OpenFGA check coordinates that
// produced the decision, so "why" is answerable without reading source
// code. JSON tags are deliberately snake_case (not Go's default
// CamelCase): whatever eventually queries this log (Phase 4) is far more
// likely to be jq/SQL/a log pipeline than Go code.
type Entry struct {
	// Time is when the decision was made (who/what/when).
	Time time.Time `json:"time"`
	// Decision is the outcome: Allow or Deny. Always one of the two -- see
	// the package doc comment, both outcomes are logged identically, never
	// just the denials or just the allows.
	Decision Decision `json:"decision"`

	// CallerSPIFFEID is "who": the caller's SPIFFE ID as extracted from a
	// cryptographically verified mTLS peer certificate
	// (internal/identity.ExtractPeerID) -- never a value taken from
	// anything the peer merely said about itself.
	CallerSPIFFEID string `json:"caller_spiffe_id"`
	// OnBehalfOf answers "on whose behalf" -- see OnBehalfOfUnresolved's
	// doc comment for why this is a documented placeholder today, not a
	// resolved identity.
	OnBehalfOf string `json:"on_behalf_of"`

	// Tool is "what": the requested tool/action, taken verbatim from the
	// stand-in tool-call request (see cmd/gateway).
	Tool string `json:"tool"`

	// FGASubject/FGARelation/FGAObject are exactly the (user, relation,
	// object) triple passed to OpenFGA's Check call that produced this
	// decision (internal/authz.Decision) -- the authoritative "why" this
	// was allowed or denied traces back to these three values plus whatever
	// tuples exist in the store, not to anything this process decided on
	// its own.
	FGASubject  string `json:"fga_subject"`
	FGARelation string `json:"fga_relation"`
	FGAObject   string `json:"fga_object"`

	// Reason is a human-readable "why", suitable for a log line on its own
	// without cross-referencing the FGA* fields (e.g. "OpenFGA
	// Check(user=agent:..., relation=can_call, object=tool:...) returned
	// allowed=false") or, on an error path, why the decision defaulted to
	// deny (e.g. "OpenFGA unreachable: ...").
	Reason string `json:"reason"`
	// Error holds the underlying error (if any) that led to a fail-closed
	// deny -- e.g. OpenFGA being unreachable. Empty on every decision that
	// completed a real Check call, allowed or denied.
	Error string `json:"error,omitempty"`

	// RemoteAddr is the TCP peer address the connection came from --
	// supplementary context, not itself a trust signal (unlike
	// CallerSPIFFEID, which the handshake cryptographically verified).
	RemoteAddr string `json:"remote_addr,omitempty"`
}

// Logger writes Entry records as one JSON object per line to an
// io.Writer, safe for concurrent use by multiple connection-handling
// goroutines (see cmd/gateway: each connection is handled on its own
// goroutine, and every one of them logs decisions through the same
// Logger).
type Logger struct {
	mu  sync.Mutex
	out io.Writer
}

// New returns a Logger that writes ndjson audit entries to out.
func New(out io.Writer) *Logger {
	return &Logger{out: out}
}

// Log writes e as a single JSON line. If e.Time is the zero value, it is
// filled in with the current UTC time first.
//
// Log never returns an error: an audit entry that failed to even marshal
// (unreachable in practice for this fixed struct -- every field is a
// plain string, Decision, or time.Time) still produces a line explaining
// that failure, rather than silently dropping the record. Losing an audit
// entry silently would be strictly worse than a malformed one that at
// least announces it happened.
func (l *Logger) Log(e Entry) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}

	b, err := json.Marshal(e)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil {
		fmt.Fprintf(l.out, "{\"time\":%q,\"decision\":\"error\",\"reason\":%q}\n",
			time.Now().UTC().Format(time.RFC3339Nano), fmt.Sprintf("failed to marshal audit entry: %v", err))
		return
	}
	l.out.Write(b) //nolint:errcheck // best-effort log write; nothing meaningful to do with a write failure to the process's own stdout
	l.out.Write([]byte("\n"))
}
