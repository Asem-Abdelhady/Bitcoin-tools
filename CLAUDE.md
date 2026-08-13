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
| Handlers | `crates/server/src/handlers/` | Transport: extraction, response views, status codes |
| Services | `crates/server/src/services/` | Use cases and input policy; **no HTTP** |

"DTO" splits in two, and the split follows the responsibilities above.
A **response** is a view — it renders domain values into strings and decides
what a client sees — so it lives with the handler (`SplitTxResponse`,
`BuildTxResponse`). A **request shape** is input policy — which fields exist,
which are optional, `camelCase`, `deny_unknown_fields` — so it lives with the
service that validates it (`TxSpec`). `serde` is a serialization crate, not a
transport one; `core` derives it too, and a mirrored pair of structs with an
identity `From` between them is four edits per field with the compiler
catching three.

Core's own layering (L0–L4, nothing imports upward) is in its README.

## Reuse these — a new endpoint should add none of them

| Building block | What it gives you |
|---|---|
| `lib::app()` | The one place routes are mounted. Tests drive this, never a sub-router, so a mistyped `nest` prefix fails the suite. |
| `routes::body_limit(max)` | Per-route transport cap, sized from the domain constant. Required on any route taking hex. |
| `bitcoin_tools_core::hex` | The only hex codec: `encode`, `decode`, `normalize`, `HexError`. |
| `services::input::hex_bytes` | The only definition of "usable hex input": trim, `0x`, empty, size cap. |
| `services::input::hex_bytes_exact` | The same, for a field of one fixed width. Both directions of the width become *your* domain error, so the endpoint keeps a slug named for what it parses. |
| `services::error::ServiceError<E>` | `Input`-or-`Domain`. State only your own parse error type. |
| `handlers::error` | `ApiError` trait + `ApiRejection<E>`. `IntoResponse`, the JSON envelope, `JsonRejection` mapping, and the 404/405 fallbacks are all implemented once. |
| `tests/common::assert_transport_contract` | The four assertions every JSON endpoint owes a client — unknown field, broken body, missing `Content-Type`, wrong method. A suite asserts its *domain*; the transport half is one line. |
| `tests/common::assert_error` | Status and slug together, with the body in the failure message. |

A new endpoint's entire error cost is one `impl ApiError for MyDomainError` giving
a status and a slug. If you find yourself writing an `ErrorBody`, an
`IntoResponse` impl, a hex parser, `max_bytes * 2 + 1024`, or a fourth copy of
"unknown field is 422", stop — it exists.

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
  `{"tx": "<hex>"}`, `{"header": "<hex>"}`.
- Two endpoints over one input share **one** request struct, in the service
  that validates it — `/blocks/hash` and `/blocks/header` both take
  `BlockHeaderRequest`. Two structs with identical fields would let the two
  drift apart while looking deliberate.
- Generic `/tools` endpoints share `HexRequest { hex: String }` rather than each
  inventing a key. A caller should not need a lookup table for an API with one
  input shape.
- An endpoint whose input is a *structure* rather than one payload says so with
  named fields: `/transactions/builder` takes
  `{"type", "version", "lockTime", "inputs": [...], "outputs": [...]}`. Optional
  fields carry the domain's own defaults (version 2, locktime 0, sequence
  `0xffffffff`, empty scriptSig) and `type` is required, because the
  serialization changes the bytes, the txid, and whether a witness survives at
  all — that is not a default anyone should inherit silently.
- All request DTOs use `deny_unknown_fields`, and all of them live in their
  service — `TxSpec`, `SplitTxRequest`, `AnalyzeScriptRequest`,
  `BlockHeaderRequest`, `GenerateKeyRequest`, `PublicKeyRequest`. No exceptions
  left; a request shape in a handler is drift, not variation.
- `network` and `compressed` default to mainnet and compressed, from
  `services::keys` so the two key endpoints cannot drift. The domain
  deliberately gives `Network` no `Default` — picking one is a transport
  decision, not a domain fact.

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
| `invalid-block-header` | 400 | Valid hex, but not the 80 bytes a header is |
| `invalid-txid` | 400 | A `txid` field was not 32 bytes of hex |
| `invalid-private-key` | 400 | Not 32 bytes, or 32 bytes that are not a scalar (zero, or at/above the group order) |
| `no-inputs` | 400 | A build request spends nothing |
| `no-outputs` | 400 | A build request pays nothing |
| `duplicate-input` | 400 | Two inputs name the same outpoint |
| `null-prevout` | 400 | An input spends the null outpoint, which only a coinbase may do |
| `amount-out-of-range` | 400 | An output value, or the total, is above 21M BTC |
| `segwit-without-witness` | 400 | `type: segwit` with no witness data — BIP144 requires the legacy encoding |
| `witness-on-legacy` | 400 | `type: legacy` with witness data, which that encoding cannot hold |
| `transaction-too-large` | 413 | The *built* transaction is past the domain size cap |
| `not-found` | 404 | No endpoint at this path |
| `method-not-allowed` | 405 | Endpoint exists, wrong method |
| `not-implemented` | 501 | Route wired up, no implementation yet |
| `bad-request` | varies | Catch-all for `JsonRejection` variants added by a future axum release; `JsonRejection` is `#[non_exhaustive]`. Seeing this means the mapping in `handlers::error` needs a new arm. |

The builder's slugs are per-rule rather than one `invalid-transaction`,
because each names a different mistake in the caller's request and a client
branching on them can say which field to fix. A field-level hex problem inside
a build request keeps the slug it has everywhere else (`invalid-hex`,
`input-too-large`) and adds the position to the message, so clients do not
learn two vocabularies for one failure.

Note one endpoint can return 413 under two slugs: `unreadable-body` is the
transport cap rejecting the request before the handler runs,
`input-too-large` is the service rejecting the decoded value. Both are real and
the distinction is worth keeping, but document it for clients.

A **fixed-width** input has no "too large", and `services::input::hex_bytes_exact`
is where that rule lives. A block header is 80 bytes and a private key is 32, so
a byte over and a byte under are one mistake with one answer —
`invalid-block-header` or `invalid-private-key`, 400, in both directions,
carrying the size actually sent. `input-too-large` elsewhere means a 10 kB
script or a 1 MB transaction, and a client should not learn two vocabularies for
one failure; the builder settled this for its wrong-length `txid`. Pass the
helper a closure building your own error and it handles both directions.

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
