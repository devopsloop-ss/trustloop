# TrustLoop Roadmap

## Architecture (settled)

- **Identity:** [SPIRE](https://spiffe.io/) issues every agent workload a short-lived X.509 SVID via Kubernetes workload attestation. No manual cert handling, no static API keys.
- **Authorization/delegation:** [OpenFGA](https://openfga.dev/) holds the relationship graph. Delegation is an explicit, revocable relation (e.g. `can_act_on_behalf_of`), following OpenFGA's documented AI-agent authorization pattern — permissions are delegated, not copied.
- **Enforcement:** a gateway/proxy in front of MCP tool calls — extracts the caller's SPIFFE identity, checks OpenFGA, allows or denies, logs the decision. This is the actual product.
- **Orchestrator adapters:** thin integration points for existing K8s-native orchestrators (Argo Workflow step, [Topoloop](https://github.com/devopsloop-ss/topoloop) topology handoff, etc.) — the core must work without any of them.

## Phase 0 — Environment

- [x] SPIRE server + agent running locally on a k3d cluster (matching Topoloop's local target), installed via the official `spiffe/spire` Helm chart, issuing SVIDs to sample workloads automatically
- [x] OpenFGA running locally on a k3d cluster (`trustloop-dev`), installed via the official `openfga/helm-charts` chart (not docker-compose — see CLAUDE.md), with a minimal authorization model: `User -> can_act_on_behalf_of -> Agent`, `Agent -> can_call -> Tool`
- **Done when:** a fresh clone + one script gets a sample agent workload a real SPIRE-issued SVID (verifiable via `spire-server entry show`) and a verified OpenFGA model, both via `helm install`, not hand-rolled install scripts — **met**: `hack/spire/setup.sh` installs SPIRE server+agent (chart `spire/spire@0.29.0`) on `trustloop-dev`, creates a K8s-selector-based registration entry (`k8s:ns:trustloop-sample`, `k8s:sa:sample-workload`), and verifies issuance both server-side (`spire-server entry show`) and workload-side (the sample pod's own fetched X.509 SVID, pulled out and inspected with `openssl x509`); `hack/openfga/setup.sh` does the same for OpenFGA

## Phase 1 — MVP: one enforced tool call, standalone

Scope is deliberately narrow and deliberately *not* tied to any orchestrator yet — prove the core mechanism works in isolation first.

- [ ] Gateway process that intercepts an MCP tool call, extracts caller SPIFFE identity, checks OpenFGA, allows/denies
- [ ] At least 2 test cases: an authorized call succeeds end-to-end; an unauthorized call is rejected with a clear reason
- [ ] Every decision logged with: caller identity, on-whose-behalf, tool called, timestamp, allow/deny, and why
- [ ] One working integration example: the gateway mediates a tool call made from inside an Argo Workflow step (proves "adoptable by an existing orchestrator," not just ours)
- [ ] Entire MVP runs locally via a single documented command (`helm install` against the local k3d cluster, or a script wrapping it) — no cloud dependency

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
