// Command openfga-verify stands up the TrustLoop Phase 0 authorization
// model against a running local OpenFGA server and proves it behaves
// correctly.
//
// This is intentionally NOT a throwaway script. Per ROADMAP.md Phase 0 and
// CLAUDE.md's "auditable, verified, not just assumed to work" standard, a
// future session (or CI) needs to be able to re-run this and get the same
// answer. It does five things, in order, every time it runs:
//
//  1. Finds-or-creates an OpenFGA store named "trustloop-dev".
//  2. Reads deploy/openfga/model.fga (the DSL source of truth) and writes
//     it to that store as a new authorization model version.
//  3. Writes a small set of test tuples representing one granted delegation
//     (user -> agent) and one granted tool call (agent -> tool). Writes are
//     idempotent (duplicate tuples are ignored, not errored) so re-running
//     this against a store that already has them is safe.
//  4. Runs Check calls covering both relations in both directions: a tuple
//     that was granted (expect allowed) and a tuple that was never granted
//     (expect denied). This is the actual verification the ticket asks for
//     -- not "the server started", but "the model enforces what we think
//     it enforces".
//  5. Reports PASS/FAIL per check and exits non-zero if any check's result
//     didn't match what we expected.
//
// IMPORTANT: OpenFGA itself is the authorization engine here. This program
// only talks to it via the official Go SDK -- it does not evaluate
// permissions itself. See trustloop/CLAUDE.md: "do not implement identity
// issuance or the authorization engine from scratch."
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openfga/go-sdk/client"
	"github.com/openfga/language/pkg/go/transformer"
)

func main() {
	apiURL := flag.String("api-url", "http://localhost:8080", "OpenFGA HTTP API base URL")
	storeName := flag.String("store-name", "trustloop-dev", "OpenFGA store to find-or-create")
	modelPath := flag.String("model-file", "deploy/openfga/model.fga", "Path to the OpenFGA DSL model file (run from repo root, or pass an absolute/relative path)")
	flag.Parse()

	if err := run(*apiURL, *storeName, *modelPath); err != nil {
		fmt.Fprintf(os.Stderr, "\nFAILED: %v\n", err)
		os.Exit(1)
	}
}

func run(apiURL, storeName, modelPath string) error {
	ctx := context.Background()

	// --- 1. Connect, and find-or-create the store -------------------------
	//
	// A bare client with no StoreId yet -- we need one to call ListStores /
	// CreateStore, which are store-scoped-request-free operations.
	fga, err := client.NewSdkClient(&client.ClientConfiguration{
		ApiUrl: apiURL,
	})
	if err != nil {
		return fmt.Errorf("constructing OpenFGA client: %w", err)
	}

	storeID, err := findOrCreateStore(ctx, fga, storeName)
	if err != nil {
		return err
	}
	fmt.Printf("store %q: %s\n", storeName, storeID)

	if err := fga.SetStoreId(storeID); err != nil {
		return fmt.Errorf("setting store id on client: %w", err)
	}

	// --- 2. Load the DSL model and push it as a new model version --------
	//
	// model.fga is the single source of truth for the authorization model
	// (see comments in that file). We transform it to the JSON shape the
	// API expects using OpenFGA's own DSL transformer library -- we do not
	// hand-write or hand-maintain a parallel JSON copy of the model.
	dsl, err := os.ReadFile(modelPath)
	if err != nil {
		return fmt.Errorf("reading model file %q: %w", modelPath, err)
	}

	modelJSON, err := transformer.TransformDSLToJSON(string(dsl))
	if err != nil {
		return fmt.Errorf("transforming DSL to JSON: %w", err)
	}

	var modelReq client.ClientWriteAuthorizationModelRequest
	if err := json.Unmarshal([]byte(modelJSON), &modelReq); err != nil {
		return fmt.Errorf("decoding transformed model JSON: %w", err)
	}

	modelResp, err := fga.WriteAuthorizationModel(ctx).Body(modelReq).Execute()
	if err != nil {
		return fmt.Errorf("writing authorization model: %w", err)
	}
	modelID := modelResp.GetAuthorizationModelId()
	fmt.Printf("authorization model written: %s\n", modelID)

	// --- 3. Write test tuples ----------------------------------------------
	//
	// Two grants, matching the two relations in the ticket:
	//   user:alice   can_act_on_behalf_of  agent:agent1
	//   agent:agent1 can_call              tool:search
	//
	// Deliberately NOT granted (used below as the negative/denied cases):
	//   user:mallory can_act_on_behalf_of  agent:agent1   (never written)
	//   agent:agent1 can_call              tool:delete_prod_db (never written)
	writes := []client.ClientTupleKey{
		{User: "user:alice", Relation: "can_act_on_behalf_of", Object: "agent:agent1"},
		{User: "agent:agent1", Relation: "can_call", Object: "tool:search"},
	}
	_, err = fga.Write(ctx).
		Body(client.ClientWriteRequest{Writes: writes}).
		Options(client.ClientWriteOptions{
			AuthorizationModelId: &modelID,
			// Re-running this program against a store that already has
			// these tuples (e.g. setup.sh run twice) must not fail --
			// writing a tuple that already exists is a no-op, not an error.
			Conflict: client.ClientWriteConflictOptions{
				OnDuplicateWrites: client.CLIENT_WRITE_REQUEST_ON_DUPLICATE_WRITES_IGNORE,
			},
		}).
		Execute()
	if err != nil {
		return fmt.Errorf("writing test tuples: %w", err)
	}
	fmt.Println("test tuples written (or already present)")

	// --- 4. Verify: run checks and compare against expectation ------------
	type check struct {
		name     string
		user     string
		relation string
		object   string
		want     bool // expected "allowed"
	}
	checks := []check{
		{
			name: "granted delegation is allowed",
			user: "user:alice", relation: "can_act_on_behalf_of", object: "agent:agent1",
			want: true,
		},
		{
			name: "ungranted delegation is denied",
			user: "user:mallory", relation: "can_act_on_behalf_of", object: "agent:agent1",
			want: false,
		},
		{
			name: "granted tool call is allowed",
			user: "agent:agent1", relation: "can_call", object: "tool:search",
			want: true,
		},
		{
			name: "ungranted tool call is denied",
			user: "agent:agent1", relation: "can_call", object: "tool:delete_prod_db",
			want: false,
		},
	}

	fmt.Println()
	allPassed := true
	for _, c := range checks {
		resp, err := fga.Check(ctx).
			Body(client.ClientCheckRequest{User: c.user, Relation: c.relation, Object: c.object}).
			Options(client.ClientCheckOptions{AuthorizationModelId: &modelID}).
			Execute()
		if err != nil {
			allPassed = false
			fmt.Printf("FAIL  %-32s  error calling Check: %v\n", c.name, err)
			continue
		}

		got := resp.GetAllowed()
		status := "PASS"
		if got != c.want {
			status = "FAIL"
			allPassed = false
		}
		fmt.Printf("%s  %-32s  (%s, %s, %s) => allowed=%v (want %v)\n",
			status, c.name, c.user, c.relation, c.object, got, c.want)
	}

	fmt.Println()
	if !allPassed {
		return fmt.Errorf("one or more checks did not match expectation")
	}
	fmt.Println("all checks passed: the model grants exactly what was tupled and nothing else")
	return nil
}

// findOrCreateStore looks for an existing store with the given name and
// reuses it; otherwise it creates a new one. This keeps repeated runs of
// this program (and the setup script that calls it) from piling up
// duplicate stores every time -- important since this is meant to be
// re-run, not run-once-and-forget.
func findOrCreateStore(ctx context.Context, fga *client.OpenFgaClient, name string) (string, error) {
	listResp, err := fga.ListStores(ctx).
		Options(client.ClientListStoresOptions{Name: &name}).
		Execute()
	if err != nil {
		return "", fmt.Errorf("listing stores: %w", err)
	}
	for _, s := range listResp.Stores {
		if s.Name == name {
			return s.Id, nil
		}
	}

	createResp, err := fga.CreateStore(ctx).
		Body(client.ClientCreateStoreRequest{Name: name}).
		Execute()
	if err != nil {
		return "", fmt.Errorf("creating store: %w", err)
	}
	return createResp.GetId(), nil
}
