// Package authz calls OpenFGA's Check API to decide whether an already
// SPIFFE-authenticated caller may invoke a given tool.
//
// Scope (issue #4 -- "OpenFGA check integration + audit logging"): given a
// caller's SPIFFE ID (already extracted and verified by internal/identity)
// and a requested tool name, ask OpenFGA whether the "agent -> can_call ->
// tool" relation from deploy/openfga/model.fga holds, and report back
// exactly what OpenFGA said. This package makes NO authorization decision
// itself -- per trustloop/CLAUDE.md ("do not implement identity issuance or
// the authorization engine from scratch"), OpenFGA's Check API is the sole
// source of truth for allow/deny. This package's only job is shaping that
// request correctly (using the official github.com/openfga/go-sdk client,
// the same SDK and calling pattern as cmd/openfga-verify -- see that file's
// package doc comment) and turning the response into something the gateway
// can log and act on.
//
// Explicitly out of scope here (see ROADMAP.md Phase 2 and model.fga's own
// comments): composing this with the "user -> can_act_on_behalf_of ->
// agent" delegation hop into a single check. Issue #4 checks agent->tool
// only; a full "can user X reach tool Y via some agent" check is later
// work, once the gateway actually needs to resolve a delegating user from
// the wire protocol (which it does not yet -- see cmd/gateway's doc
// comment on the stand-in request shape).
package authz

import (
	"context"
	"fmt"
	"strings"

	"github.com/openfga/go-sdk/client"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Relation is the single OpenFGA relation issue #4's gateway check is
// scoped to. See the package doc comment for why this is not composed with
// the delegation relation yet.
const Relation = "can_call"

// Checker calls OpenFGA's Check API for can_call decisions against a single
// pre-existing store (found, never created -- see NewChecker).
type Checker struct {
	fga *client.OpenFgaClient
}

// NewChecker connects to the OpenFGA HTTP API at apiURL and binds to the
// store named storeName.
//
// It deliberately FINDS rather than creates the store: per the ticket
// ("same store/model from the previous OpenFGA ticket -- check
// cmd/openfga-verify for how it's named/reused, don't create a parallel
// one"), the store and its authorization model are owned by
// cmd/openfga-verify (issue #2's Phase 0 work). If storeName doesn't exist
// yet, that means Phase 0 setup (hack/openfga/setup.sh) hasn't run -- the
// correct behavior is a loud startup failure, not silently standing up a
// second, empty, parallel store the gateway would then (incorrectly) find
// nothing granted in.
//
// Check calls made through the returned Checker do not pin an
// AuthorizationModelId (unlike cmd/openfga-verify, which pins the ID of the
// model it JUST wrote in the same run). Omitting it lets OpenFGA's Check API
// float to the store's most recently written model version automatically --
// the correct default here, since this package never writes a model itself
// and so has no "the one I just wrote" ID to pin to.
func NewChecker(apiURL, storeName string) (*Checker, error) {
	fga, err := client.NewSdkClient(&client.ClientConfiguration{ApiUrl: apiURL})
	if err != nil {
		return nil, fmt.Errorf("constructing OpenFGA client for %s: %w", apiURL, err)
	}

	storeID, err := findStore(context.Background(), fga, storeName)
	if err != nil {
		return nil, err
	}
	if err := fga.SetStoreId(storeID); err != nil {
		return nil, fmt.Errorf("setting store id on OpenFGA client: %w", err)
	}
	return &Checker{fga: fga}, nil
}

func findStore(ctx context.Context, fga *client.OpenFgaClient, name string) (string, error) {
	listResp, err := fga.ListStores(ctx).
		Options(client.ClientListStoresOptions{Name: &name}).
		Execute()
	if err != nil {
		return "", fmt.Errorf("listing OpenFGA stores: %w", err)
	}
	for _, s := range listResp.Stores {
		if s.Name == name {
			return s.Id, nil
		}
	}
	return "", fmt.Errorf("OpenFGA store %q not found -- run hack/openfga/setup.sh (or cmd/openfga-verify) first to create it and load the authorization model; the gateway never creates it itself", name)
}

// SubjectForSPIFFEID derives the OpenFGA "user" identifier for a can_call
// check from a caller's SPIFFE ID.
//
// SECURITY: callers MUST pass a SPIFFE ID that has already been extracted
// from a cryptographically verified mTLS peer certificate
// (internal/identity.ExtractPeerID) -- never a value read from request
// payload data. The entire point of gating on SPIFFE identity is that it
// cannot be forged by whoever is on the other end of the connection; if the
// OpenFGA subject were instead derived from something the peer merely
// *says* about itself, that would silently reopen the "Confused Deputy" gap
// TrustLoop exists to close (see README.md's "Why").
//
// The identifier is built from the SPIFFE ID's path (e.g.
// "/ns/trustloop-sample/sa/sample-workload" becomes
// "agent:ns/trustloop-sample/sa/sample-workload"), not the full
// "spiffe://<trust-domain>/..." URI: every tuple in this store's model
// already assumes a single trust domain, so repeating the trust domain and
// carrying "//" into every OpenFGA object ID would add no information,
// only noise.
func SubjectForSPIFFEID(id spiffeid.ID) string {
	return "agent:" + strings.TrimPrefix(id.Path(), "/")
}

// Decision is the result of a can_call check -- everything the caller needs
// to both act on the outcome and write a complete audit log entry (issue
// #4) without re-deriving anything.
type Decision struct {
	Subject  string // OpenFGA "user" checked, e.g. "agent:ns/.../sa/..."
	Relation string
	Object   string // OpenFGA object checked, e.g. "tool:search"
	Allowed  bool
	Reason   string // human-readable explanation of the outcome, for audit logging
}

// CheckCanCall asks OpenFGA whether agentSubject (see SubjectForSPIFFEID)
// may invoke tool, via the can_call relation.
//
// On any error reaching or querying OpenFGA, it returns a zero-value
// Decision.Allowed (false) alongside a non-nil error -- callers MUST treat
// an error here as "deny" (fail closed), never "skip the check and allow"
// or "allow by default". An authorization engine that is unreachable is not
// evidence of a grant.
func (c *Checker) CheckCanCall(ctx context.Context, agentSubject, tool string) (Decision, error) {
	object := "tool:" + tool

	resp, err := c.fga.Check(ctx).
		Body(client.ClientCheckRequest{User: agentSubject, Relation: Relation, Object: object}).
		Execute()
	if err != nil {
		return Decision{Subject: agentSubject, Relation: Relation, Object: object},
			fmt.Errorf("calling OpenFGA Check(user=%s, relation=%s, object=%s): %w", agentSubject, Relation, object, err)
	}

	allowed := resp.GetAllowed()
	reason := fmt.Sprintf("OpenFGA Check(user=%s, relation=%s, object=%s) returned allowed=%v", agentSubject, Relation, object, allowed)
	return Decision{
		Subject:  agentSubject,
		Relation: Relation,
		Object:   object,
		Allowed:  allowed,
		Reason:   reason,
	}, nil
}
