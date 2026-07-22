# TrustLoop

An adoptable identity, authorization, and delegation framework for AI agents and MCP tool calls — designed to plug into existing Kubernetes-native workflow orchestrators (Argo Workflows, Kestra, kagent, [Topoloop](https://github.com/devopsloop-ss/topoloop), or your own) rather than requiring a specific platform.

Status: **pre-MVP.** See [ROADMAP.md](ROADMAP.md) for the phased plan and current MVP scope.

## Why

MCP's authorization story is a known, serious gap as of 2026: once an agent authenticates to an MCP server, it implicitly gets every tool that server exposes — no per-tool check, no verifiable caller identity, no way to express "Agent A may act on behalf of User X, but only for these tools." "Unauthenticated Access" and "Confused Deputy" are the top two risks in the 2026 MCP Security Top 10, and identity/audit/access-control gaps are cited as a leading reason agentic pilots stall before production.

TrustLoop doesn't reinvent authorization — it wires together two mature, adopted-in-production building blocks and makes them usable at the MCP tool-call boundary:

- **[SPIRE](https://spiffe.io/)** (SPIFFE) — every agent gets a cryptographically verifiable, short-lived workload identity (an SVID), issued automatically via Kubernetes workload attestation. No shared static API keys.
- **[OpenFGA](https://openfga.dev/)** (CNCF, Google Zanzibar model) — delegation is modeled as an explicit, revocable relationship (`can_act_on_behalf_of`), not a copied credential. Every MCP tool call is checked against this graph before being forwarded.

The genuinely new work here is the **integration**: a thin enforcement gateway sitting in front of MCP tool calls, adapters for existing orchestrators, and a delegation model designed specifically for agent-to-agent handoffs — not the identity or authorization engines themselves.

## Design principles

- **Don't roll your own auth.** SPIRE and OpenFGA are the trust boundary. TrustLoop is the glue, not a replacement.
- **Orchestrator-agnostic.** The core (identity issuance + delegation graph + enforcement gateway) must work standalone; orchestrator integrations are adapters on top, not requirements.
- **Auditable by default.** Every allow/deny decision answers "who acted on whose behalf, calling what, when, and why" from day one — not bolted on later.
- **Open source, Apache 2.0.** See [LICENSE](LICENSE).

## Status

Phase 0 is underway. Follow [ROADMAP.md](ROADMAP.md) for MVP progress.

### Local OpenFGA (Phase 0)

OpenFGA is the authorization engine for the `User -> can_act_on_behalf_of -> Agent`
and `Agent -> can_call -> Tool` delegation model (see [ROADMAP.md](ROADMAP.md)).
This repo does not implement authorization itself — see [CLAUDE.md](CLAUDE.md).

Requires `minikube`, `helm`, and `kubectl` locally (matching Topoloop's
local dev target — see [CLAUDE.md](CLAUDE.md)). Local Kubernetes is
**minikube with the Hyper-V driver** on Windows (Docker Desktop and k3d were
retired 2026-07-22 — see CLAUDE.md), which means:

- Hyper-V enabled, and your user in the **Hyper-V Administrators** group
  (`minikube` lifecycle commands manage a Hyper-V VM; plain `kubectl`/`helm`
  need no special rights). Group membership takes effect at next sign-in.
- `MINIKUBE_HOME=D:\minikube` — the VM image/profile state live on D:
  (C: is nearly full). The setup scripts default this themselves on Windows;
  set it in your own shell too if you run `minikube` by hand, or minikube
  won't find the existing profile and will try to create a new VM.
- The cluster is the **default `minikube` profile, shared with Topoloop**
  (namespace-separated: Topoloop owns `argo`; TrustLoop owns `openfga`,
  `spire-server`, `trustloop-sample`, `trustloop-gateway`). Don't create a
  per-repo profile, and never `minikube delete` just for this repo — see
  [hack/dev-cluster.sh](hack/dev-cluster.sh).

Bring OpenFGA up on the shared local minikube cluster, load the model, and
verify it behaves correctly (one command):

```sh
hack/openfga/setup.sh
```

This:

1. Ensures the shared minikube cluster is up ([hack/dev-cluster.sh](hack/dev-cluster.sh) — starts it if needed, reuses it if running).
2. Installs OpenFGA via its official Helm chart ([deploy/openfga/values.yaml](deploy/openfga/values.yaml) pins the chart to a specific version — see that file for why, and why `replicaCount: 1` matters with the in-memory datastore).
3. Port-forwards the OpenFGA HTTP API to `localhost:8080`.
4. Runs [cmd/openfga-verify](cmd/openfga-verify) which:
   - Finds-or-creates an OpenFGA store (`trustloop-dev`).
   - Loads [deploy/openfga/model.fga](deploy/openfga/model.fga) — the DSL source of truth for the model — as a new authorization model version.
   - Writes a couple of test tuples: one granted delegation, one granted tool call.
   - Runs `Check` calls for both a granted and an ungranted case per relation, and reports PASS/FAIL against what's expected — this is the actual verification, not just "the server started."

The script and the `openfga-verify` program are both safe to re-run — the
cluster, Helm release, store, and model are all found-or-created/upgraded in
place, and duplicate tuple writes are ignored.

### Local SPIRE (Phase 0)

SPIRE issues every agent workload a short-lived, cryptographically verifiable
SPIFFE identity (an X.509 SVID) via Kubernetes workload attestation — no
manual cert handling, no static API keys. This repo does not implement
identity issuance itself — see [CLAUDE.md](CLAUDE.md).

Also requires `openssl` locally (used only to inspect the workload's fetched
certificate as part of verification — never to issue or handle anything
identity-related itself). Bring SPIRE up on the same shared minikube
cluster, create a registration entry for a throwaway sample workload, and
verify it actually receives a real SVID (one command):

```sh
hack/spire/setup.sh
```

This:

1. Ensures the shared minikube cluster is up (same
   [hack/dev-cluster.sh](hack/dev-cluster.sh) as `hack/openfga/setup.sh`).
2. Installs SPIRE server + agent via the official `spiffe/spire` Helm chart
   ([deploy/spire/values.yaml](deploy/spire/values.yaml) pins the chart to a
   specific version and documents every non-default setting — trust domain,
   why the SPIRE Controller Manager is off, why kubelet cert verification is
   skipped — and why).
3. Waits for the agent to attest to the server via the K8s node attestor
   (PSAT), then creates a registration entry for a sample workload using the
   K8s *workload* attestor: selectors `k8s:ns:trustloop-sample` /
   `k8s:sa:sample-workload`, not a hand-typed workload ID — any pod running
   as that namespace/service-account gets issued the identity automatically.
4. Deploys the sample workload
   ([deploy/spire/sample-workload.yaml](deploy/spire/sample-workload.yaml))
   and verifies issuance twice: server-side via `spire-server entry show`,
   and workload-side by pulling the actual issued certificate back out of
   the pod and inspecting it with `openssl x509` — proving a real SVID was
   issued to the workload, not just that the server thinks it should be.

### Local gateway (Phase 1)

The gateway (`cmd/gateway`) is the enforcement point the rest of TrustLoop's
Phase 1 work builds on. For every connection it:

1. Fetches its own SPIRE-issued identity via the SPIFFE Workload API and
   terminates SPIFFE/mTLS connections, correctly extracting the caller's
   SPIFFE ID for a valid peer and refusing a peer that doesn't present one
   (no certificate, a self-signed cert, or a cert for a trust domain this
   gateway doesn't trust). See [CLAUDE.md](CLAUDE.md) — this repo does not
   implement identity issuance or X.509/TLS trust decisions itself; every
   accept/reject decision here is made by the official
   [go-spiffe](https://github.com/spiffe/go-spiffe) SDK.
2. Checks the caller's identity against a real OpenFGA `Check` call
   (`internal/authz`) for the `can_call` relation from
   [deploy/openfga/model.fga](deploy/openfga/model.fga), against the
   requested tool — again, the actual allow/deny decision is made by
   OpenFGA, not by this repo.
3. Writes a structured (ndjson) audit log entry (`internal/audit`) for
   *every* decision, allow and deny alike, with who, what, when, and why —
   see that package's doc comment for the exact schema and how it's a
   deliberate stepping stone toward [ROADMAP.md](ROADMAP.md) Phase 4's
   queryable audit log.

Requires SPIRE and OpenFGA already running locally (`hack/spire/setup.sh`
and `hack/openfga/setup.sh`, above). No Docker on the host is needed: the
gateway binary is cross-compiled locally (`go build`) and the image is
built with `minikube image build` against the Docker daemon *inside* the
minikube VM, landing it directly in the cluster's image store with no
registry involved.
Builds the gateway, deploys it via its own Helm chart
([deploy/gateway/chart](deploy/gateway/chart)), and proves both the
identity accept/reject behavior and the OpenFGA-backed allow/deny behavior
against the live cluster — including writing a real, granted `can_call`
tuple into the same OpenFGA store `hack/openfga/setup.sh` created, and
proving both a genuinely granted and a genuinely ungranted tool call behave
correctly — (one command):

```sh
hack/gateway/setup.sh
```

Tear it down with `helm uninstall` / `kubectl delete namespace` on
TrustLoop's own namespaces (each setup script prints the exact commands for
its component when it finishes) — **not** `minikube delete`, which would
also destroy Topoloop's half of the shared cluster.
