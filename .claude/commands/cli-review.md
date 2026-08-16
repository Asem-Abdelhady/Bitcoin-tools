---
description: Run the senior-Rust CLI review loop over crates/cli until the reviewer approves
---

Run the mandatory review loop from `CLAUDE.md`, against the command-line front
end.

Scope: `$ARGUMENTS` if given, otherwise all of `crates/cli` including its
`Cargo.toml`, its `tests/`, and its inline `#[cfg(test)]` modules.

Steps:

1. Run `cargo fmt`, `cargo clippy --all-targets`, and `cargo test`. Fix anything
   they report before going further.
2. Spawn `rust-cli-reviewer` synchronously (`run_in_background: false`).
3. Apply its feedback. Where you disagree, say why concretely rather than
   silently skipping. If you resolve a finding by documenting a decision, write
   the document in the same turn and re-read it to confirm it landed.
4. Continue the **same** agent with `SendMessage` so it verifies the fixes with
   its context intact.
5. Loop until `VERDICT: APPROVE`, then re-run clippy and the tests.
6. Report: what it found, what you changed, what you pushed back on and why,
   and how many rounds it took.

Never let this reviewer touch `crates/core/**` or `crates/server/**` — those are
`/core-review`'s and `/rust-review`'s jobs.

A finding about the human/`--json` contract is not verified by reading the diff.
Re-run the command both ways and compare what each mode actually prints.
