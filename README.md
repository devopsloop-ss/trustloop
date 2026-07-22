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

Nothing runnable yet — this repo currently holds the plan. Follow [ROADMAP.md](ROADMAP.md) for MVP progress.
