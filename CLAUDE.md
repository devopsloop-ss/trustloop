# TrustLoop — Repo Rules

Supplements the workspace-root `CLAUDE.md` (loaded automatically as ancestor context — open-source-only, resourcing, journaling policy all apply here too). This file only holds what's specific to *this* repo.

## Stack

- **Go.** Matches SPIRE and OpenFGA (both Go), and is a deliberate learning choice as well as a technical one.
- **Comment thoroughly.** Same standard as Topoloop — explain what non-trivial identity/authz mechanisms are doing and why, not just business logic. This is security-critical code; a future reader needs to understand *why* a check exists, not just that it does.
- **Do not implement identity issuance or the authorization engine from scratch.** SPIRE issues identity; OpenFGA evaluates authorization. This repo's code is the enforcement gateway and orchestrator adapters — the glue, not the trust boundary itself.

## Non-negotiable for this repo specifically

- Every allow/deny decision must be logged with enough detail to answer "who, on whose behalf, called what, when, why allowed/denied" — no exceptions, from the first commit that makes a real authorization check.
- No static long-lived credentials for agent identity. If a test/example needs a shortcut, it must be clearly marked as a dev-only shortcut, not a pattern to copy.
