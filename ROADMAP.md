# TrustLoop Roadmap

## Architecture (settled)

- **Identity:** [SPIRE](https://spiffe.io/) issues every agent workload a short-lived X.509 SVID via Kubernetes workload attestation. No manual cert handling, no static API keys.
- **Authorization/delegation:** [OpenFGA](https://openfga.dev/) holds the relationship graph. Delegation is an explicit, revocable relation (e.g. `can_act_on_behalf_of`), following OpenFGA's documented AI-agent authorization pattern — permissions are delegated, not copied.
- **Enforcement:** a gateway/proxy in front of MCP tool calls — extracts the caller's SPIFFE identity, checks OpenFGA, allows or denies, logs the decision. This is the actual product.
- **Orchestrator adapters:** thin integration points for existing K8s-native orchestrators (Argo Workflow step, [Topoloop](https://github.com/devopsloop-ss/topoloop) topology handoff, etc.) — the core must work without any of them.

## Phase 0 — Environment

- [x] SPIRE server + agent running locally on the local dev cluster (matching Topoloop's local target — originally a per-repo k3d cluster, now the shared minikube profile; see CLAUDE.md), installed via the official `spiffe/spire` Helm chart, issuing SVIDs to sample workloads automatically
- [x] OpenFGA running locally on the same cluster, installed via the official `openfga/helm-charts` chart (not docker-compose — see CLAUDE.md), with a minimal authorization model: `User -> can_act_on_behalf_of -> Agent`, `Agent -> can_call -> Tool`
- **Done when:** a fresh clone + one script gets a sample agent workload a real SPIRE-issued SVID (verifiable via `spire-server entry show`) and a verified OpenFGA model, both via `helm install`, not hand-rolled install scripts — **met**: `hack/spire/setup.sh` installs SPIRE server+agent (chart `spire/spire@0.29.0`) on the local cluster, creates a K8s-selector-based registration entry (`k8s:ns:trustloop-sample`, `k8s:sa:sample-workload`), and verifies issuance both server-side (`spire-server entry show`) and workload-side (the sample pod's own fetched X.509 SVID, pulled out and inspected with `openssl x509`); `hack/openfga/setup.sh` does the same for OpenFGA
- [x] Migrated the local dev target from k3d-on-Docker-Desktop to the shared minikube (Hyper-V) cluster after Docker Desktop was retired (2026-07-22) — all three `hack/*/setup.sh` verify flows re-run and passing on minikube (issue #14)

## Phase 1 — MVP: one enforced tool call, standalone

Scope is deliberately narrow and deliberately *not* tied to any orchestrator yet — prove the core mechanism works in isolation first.

- [x] Gateway process that intercepts an MCP tool call, extracts caller SPIFFE identity, checks OpenFGA, allows/denies
  - [x] Gateway scaffold + SPIFFE/mTLS identity extraction (issue #3) -- `cmd/gateway` fetches its own SVID/trust bundle from the SPIRE Workload API via `go-spiffe`, terminates mutual TLS, and correctly extracts a valid peer's SPIFFE ID (verified end-to-end against a real SPIRE-issued SVID) while rejecting peers with no cert, a self-signed cert, or a cert for a trust domain the gateway doesn't trust (verified end-to-end; an expired-cert case is covered by unit tests against a controlled CA). See `hack/gateway/setup.sh` for the repeatable live verification and `internal/identity` for the unit tests.
  - [x] OpenFGA authorization check + allow/deny decision (issue #4) -- `internal/authz` calls OpenFGA's real `Check` API (via the official `openfga/go-sdk`, same pattern as `cmd/openfga-verify`) for the `can_call` relation, against the SAME store/model `cmd/openfga-verify` creates -- no parallel store, no stub. The gateway's stand-in tool-call request (issue #3's one-line protocol) is extended with a notion of "which tool" -- the line itself. Verified end-to-end by `hack/gateway/setup.sh`: `cmd/gateway-verify` writes a real, granted `can_call` tuple for its own live SPIRE identity into the running OpenFGA store, then proves the gateway allows that tool and denies a different, deliberately ungranted one -- both against the real, running OpenFGA, not a mock. An OpenFGA call that errors fails closed (deny), never open.
- [x] At least 2 test cases: an authorized call succeeds end-to-end; an unauthorized call is rejected with a clear reason -- `cmd/gateway-verify`'s live checks (above) cover both against the real cluster; `cmd/gateway`'s unit tests (`TestHandleConn_AllowedToolCall`, `TestHandleConn_DeniedToolCall`, `TestHandleConn_FailsClosedOnOpenFGAError`) cover both plus the fail-closed error path in isolation.
- [x] Every decision logged with: caller identity, on-whose-behalf, tool called, timestamp, allow/deny, and why -- `internal/audit` writes one structured (ndjson) `Entry` per decision, both allow and deny, covering exactly those fields (`on_behalf_of` is an explicit, documented placeholder for now -- see that package's doc comment -- since composing the `user -> can_act_on_behalf_of -> agent` delegation hop into this decision is Phase 2 work, not issue #4's scope).
- [ ] One working integration example: the gateway mediates a tool call made from inside an Argo Workflow step (proves "adoptable by an existing orchestrator," not just ours)
- [ ] Entire MVP runs locally via a single documented command (`helm install` against the local minikube cluster, or a script wrapping it) — no cloud dependency

**MVP acceptance criteria (all must hold):**
1. A workload gets a real SPIRE SVID automatically on startup — no manual cert copying.
2. An authorized MCP tool call succeeds through the gateway; an unauthorized one is rejected — both verified by test.
3. Every decision is logged with enough detail to answer "who, on whose behalf, what, when, why" without reading source code.
4. The Argo Workflow integration example works using only documented adapter code, not one-off hacks.
5. A contributor cloning the repo cold can reach "example passing" in under ~15 minutes following the README alone.

## Phase 2 — Delegation chains

- [ ] Multi-hop delegation (Agent A → Agent B → Agent C), each hop scoped down, not just re-granted wholesale
- [ ] Revocation that actually propagates (revoking A's grant invalidates downstream delegations from A)

## Phase 3 — More adapters + policy authoring

- [ ] Kestra, kagent, and generic sidecar/proxy mode for anything else
- [ ] CLI or minimal UI for authoring/reviewing delegation policies (no raw OpenFGA model editing required for common cases)

## Phase 4 — Observability

- [ ] Metrics (decision latency, allow/deny rates)
- [ ] Queryable audit log, not just structured logs on disk

## Non-goals (for now)

- Being a general-purpose authorization service for non-agent use cases — scope is MCP tool calls and agent delegation specifically.
- A hosted/managed version — self-hosted only until the local/self-hosted path is solid.
