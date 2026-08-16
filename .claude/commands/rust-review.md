---
description: Run the senior-Rust review loop over the API layers (routes, handlers, services, tests) until the reviewer approves
---

Run the mandatory review loop described in `CLAUDE.md`.

Scope: `$ARGUMENTS` if given, otherwise the whole API surface (`crates/server/**`).

Steps:

1. Run `cargo fmt`, `cargo clippy --all-targets`, and `cargo test`. Fix anything
   they report before going further.
2. Spawn `rust-api-reviewer` synchronously (`run_in_background: false`).
3. Apply its feedback. Where you disagree, say why concretely rather than
   silently skipping.
4. Continue the **same** agent with `SendMessage` so it verifies the fixes with
   its context intact.
5. Loop until `VERDICT: APPROVE`, then re-run clippy and the tests.
6. Report to the user: what the reviewer found, what you changed, anything you
   pushed back on and why, and how many rounds it took.

Never let this reviewer touch `crates/core/` or `crates/cli/` — those are
`/core-review`'s and `/cli-review`'s jobs.
