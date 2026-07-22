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

Requires `k3d`, `helm`, and `kubectl` locally (matching Topoloop's local dev
target — see [CLAUDE.md](CLAUDE.md)). Bring OpenFGA up on a local k3d
cluster, load the model, and verify it behaves correctly (one command):

```sh
hack/openfga/setup.sh
```

This:

1. Creates a local k3d cluster named `trustloop-dev` if one doesn't already exist (reuses it if it does).
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

Tear it down with:

```sh
k3d cluster delete trustloop-dev
```
