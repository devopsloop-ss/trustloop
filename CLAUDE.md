# TrustLoop — Repo Rules

Supplements the workspace-root `CLAUDE.md` (loaded automatically as ancestor context — open-source-only, resourcing, journaling policy all apply here too). This file only holds what's specific to *this* repo.

## Stack

- **Go.** Matches SPIRE and OpenFGA (both Go), and is a deliberate learning choice as well as a technical one.
- **Comment thoroughly.** Same standard as Topoloop — explain what non-trivial identity/authz mechanisms are doing and why, not just business logic. This is security-critical code; a future reader needs to understand *why* a check exists, not just that it does.
- **Do not implement identity issuance or the authorization engine from scratch.** SPIRE issues identity; OpenFGA evaluates authorization. This repo's code is the enforcement gateway and orchestrator adapters — the glue, not the trust boundary itself.

## Non-negotiable for this repo specifically

- Every allow/deny decision must be logged with enough detail to answer "who, on whose behalf, called what, when, why allowed/denied" — no exceptions, from the first commit that makes a real authorization check.
- No static long-lived credentials for agent identity. If a test/example needs a shortcut, it must be clearly marked as a dev-only shortcut, not a pattern to copy.

## Working a ticket

Work happens across multiple sessions: a separate "orchestrator" session tracks the [project board](https://github.com/orgs/devopsloop-ss/projects/1) and reviews results; each ticket gets worked in its own session, scoped to just that ticket. If you're a session picking up a ticket here:

1. `gh issue view <n>` — the ticket has a turn/token estimate and enough scope to start; cross-reference [ROADMAP.md](ROADMAP.md) for which phase it belongs to and how it fits the whole.
2. Branch: `issue-<n>-<short-slug>`.
3. Implement only what the ticket covers — resist scope creep into other open tickets even if related.
4. Commit referencing the issue (e.g. `Refs #<n>`).
5. Open a PR with `Closes #<n>` in the description so the issue auto-closes on merge.
6. **Don't merge your own PR.** Leave that for the orchestrator session/user to review — that review is the whole point of the split.
