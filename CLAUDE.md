# bitcoin-tools

A cargo workspace: a Bitcoin domain library, and an axum JSON API over it.

## Workspace

| Crate | Path | What it is |
|---|---|---|
| `bitcoin-tools-core` | `crates/core/` | The domain library. Published. No HTTP, no I/O, no framework. See its [README](crates/core/README.md) — it is the spec. |
| `bitcoin-tools-web-server` | `crates/server/` | The axum API. `publish = false`. |
| `bitcoin-tools-vectors` | `crates/vectors/` | Known-good test vectors, shared by both test suites. `publish = false`, dev-dependency only. |

The split is load-bearing: core **cannot** reference the server, because it is
a separate crate and the compiler says so. That was a convention before; it is
now a build error.

## Server layers

| Layer | Path | Responsibility |
|---|---|---|
| Routes | `crates/server/src/routes/` | URL and method binding, transport limits |
| Handlers | `crates/server/src/handlers/` | Transport: extraction, DTOs, status codes |
| Services | `crates/server/src/services/` | Use cases and input policy; **no HTTP** |

Core's own layering (L0–L4, nothing imports upward) is in its README.

## Reuse these — a new endpoint should add none of them

| Building block | What it gives you |
|---|---|
| `lib::app()` | The one place routes are mounted. Tests drive this, never a sub-router, so a mistyped `nest` prefix fails the suite. |
| `routes::body_limit(max)` | Per-route transport cap, sized from the domain constant. Required on any route taking hex. |
| `bitcoin_tools_core::hex` | The only hex codec: `encode`, `decode`, `normalize`, `HexError`. |
| `services::input::hex_bytes` | The only definition of "usable hex input": trim, `0x`, empty, size cap. |
| `services::error::ServiceError<E>` | `Input`-or-`Domain`. State only your own parse error type. |
| `handlers::error` | `ApiError` trait + `ApiRejection<E>`. `IntoResponse`, the JSON envelope, `JsonRejection` mapping, and the 404/405 fallbacks are all implemented once. |

A new endpoint's entire error cost is one `impl ApiError for MyDomainError` giving
a status and a slug. If you find yourself writing an `ErrorBody`, an
`IntoResponse` impl, a hex parser, or `max_bytes * 2 + 1024`, stop — it exists.

## Mandatory review loop

**After writing or changing any Rust code, you must run the review loop before
reporting the work as done.** Not optional, however small the change.

Two reviewers own disjoint halves of the tree. Pick by what you touched; if a
change spans both, run both loops.

| You changed | Reviewer | Forbidden from reading for critique |
|---|---|---|
| `crates/server/**` | `rust-api-reviewer` | `crates/core/**` |
| `crates/core/**` (incl. its README) | `rust-core-reviewer` | `crates/server/**` |

`crates/vectors/` belongs to whichever reviewer's tests changed.

`rust-core-reviewer` judges core as a **published cargo package** that a future
CLI and this server both depend on — public API design, no panics on public
paths, no framework leakage. See
[crates/core/README.md](crates/core/README.md) for the feature set and the
layering it reviews against.

1. Run `cargo fmt --all`, `cargo clippy --workspace --all-targets`, and
   `cargo test --workspace`. Touching core also means
   `cargo check -p bitcoin-tools-core --no-default-features`, since `serde` is
   an optional feature and a gated derive is easy to add without noticing.
   Fix everything they report first — never send failing code to review.
2. Spawn the appropriate subagent (`run_in_background: false`).
3. Apply the feedback. Push back if a finding is wrong — you are a peer in this
   review, not a rubber stamp — but you must either fix it or state a concrete
   reason it does not apply. **If you resolve a finding by "documenting the
   decision", actually write the document in the same turn, then re-read the
   file to confirm it landed.** Never report a fix you have not verified.
4. Continue the **same** agent with `SendMessage` (not a fresh `Agent` call,
   which loses its context) so it can verify the fixes and converge.
5. Repeat until the agent returns `VERDICT: APPROVE` and you agree.
6. Re-run `cargo clippy --all-targets` and `cargo test` after the final change.

Do not spawn a new reviewer per round, and do not stop at the first round of
feedback. If you and the agent still disagree after three rounds, stop and
surface the disagreement to the user rather than looping.

Each reviewer's exclusion is in its own definition. Do not override either —
they are what keep the two reviews independent.

## Conventions

### Request shape

- Domain endpoints keep a self-documenting field name: `{"script": "<hex>"}`,
  `{"tx": "<hex>"}`.
- Generic `/tools` endpoints share `HexRequest { hex: String }` rather than each
  inventing a key. A caller should not need a lookup table for an API with one
  input shape.
- All request DTOs use `deny_unknown_fields`.

### JSON

- camelCase on the wire (`#[serde(rename_all = "camelCase")]`), snake_case in Rust.
- **Some domain enums serialise straight to the wire on purpose.** `ScriptKind`,
  `ScriptFields`, `Category` and `DecodeError` are stable value types with
  explicit serde spellings, and those spellings *are* the published contract —
  changing one is an API break, not a refactor. `AnalyzedInstruction` gets a
  handler-side view instead, because it carries `Opcode` and `Vec<u8>` that have
  to be rendered as a name and hex. Follow that split: value enums may go direct,
  anything needing rendering gets a view.

### Errors

Slugs are shared and kebab-case, produced by `ApiError::slug`:

| Slug | Status | Meaning |
|---|---|---|
| `empty-input` | 400 | Field was empty after trimming |
| `invalid-hex` | 400 | Not hex, or odd length |
| `input-too-large` | 413 | Past the domain size cap |
| `malformed-json` | 400 | Body is not JSON |
| `invalid-body` | 422 | Valid JSON, wrong shape or types |
| `unsupported-media-type` | 415 | Missing or wrong `Content-Type` |
| `unreadable-body` | 413 / 400 | Body could not be buffered: 413 past the route's transport cap, 400 if the stream failed |
| `invalid-transaction` | 400 | Valid hex, not a transaction |
| `not-found` | 404 | No endpoint at this path |
| `method-not-allowed` | 405 | Endpoint exists, wrong method |
| `not-implemented` | 501 | Route wired up, no implementation yet |
| `bad-request` | varies | Catch-all for `JsonRejection` variants added by a future axum release; `JsonRejection` is `#[non_exhaustive]`. Seeing this means the mapping in `handlers::error` needs a new arm. |

Note one endpoint can return 413 under two slugs: `unreadable-body` is the
transport cap rejecting the request before the handler runs,
`input-too-large` is the service rejecting the decoded value. Both are real and
the distinction is worth keeping, but document it for clients.

A malformed *request* is 4xx. Malformed *data* the request asked about is a
judgement call: a broken script returns 200 with an `error` field, because
showing where it broke is the point; a broken transaction returns 400, because
once field boundaries stop lining up there is no partial answer.

### Tests

- API tests go through `app()` at real URIs, using
  `crates/server/tests/common/mod.rs`.
- Vectors come from the `bitcoin-tools-vectors` crate, never from a path or a
  restated expectation. Core asserts its decoder reproduces each vector; the
  server asserts its HTTP response equals the same one.

## Open decisions

- **Path casing.** Paths are currently single lowercase words (`/script`,
  `/splitter`) while JSON is camelCase. `/tools/reverse_bytes` introduces
  snake_case. Kebab-case (`/tools/reverse-bytes`) is the common REST
  convention — the user's call, not to be changed unilaterally.
- Trailing slashes 404 (`/transactions/script/`). Undecided whether to normalise.
- No env-based config, request logging, or graceful shutdown yet.
