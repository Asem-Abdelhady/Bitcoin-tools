# bitcoin-tools

A cargo workspace: a Bitcoin domain library, and an axum JSON API over it.

## Workspace

| Crate | Path | What it is |
|---|---|---|
| `bitcoin-tools-core` | `crates/core/` | The domain library. Published. No HTTP, no I/O, no framework. See its [README](crates/core/README.md) — it is the spec. |
| `bitcoin-tools-server` | `crates/server/` | The axum API. `publish = false`. |
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
| `services::error::ServiceError<E>` | `Input`-or-`Domain`. State only your own parse error type. Skip it when there is no domain half: `/tools/reverse-bytes` returns bare `InputError`, because reversing decoded bytes cannot fail and a two-armed error would have a variant nothing constructs. |
| `services::tools::HexRequest` | `{"hex": "<hex>"}`, for a `/tools` endpoint whose input is one payload with no domain noun to name it after. |
| `handlers::error` | `ApiError` trait + `ApiRejection<E>`. `IntoResponse`, the JSON envelope, `JsonRejection` mapping, and the 404/405 fallbacks are all implemented once. |
| `tests/common::assert_transport_contract` | The four assertions every JSON endpoint owes a client — unknown field, broken body, missing `Content-Type`, wrong method. A suite asserts its *domain*; the transport half is one line. |
| `tests/common::assert_error` | Status and slug together, with the body in the failure message. Returns the body for message checks. |
| `tests/common::post_json_headers` | Response headers, for the endpoints whose contract includes one. |
| `handlers::NO_STORE` | `Cache-Control: no-store`. Set by every endpoint returning a secret and by no others, so its presence means something. |
| `handlers::address` | Every address a public key produces, with its parts. `/keys/public` and `/hd/derive` both render it — two places deciding which addresses exist is two places to forget BIP143. |
| `handlers::Secret<T>` | The return type of an endpoint that hands over a secret. Pairs with `NO_STORE` so the signature says it. |

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
- All request DTOs use `deny_unknown_fields` and live in their service; a
  request shape in a handler is drift, not variation. Deliberately not
  enumerated — the list went stale twice, and the rule is grep-checkable while
  a list is not.
- A signature is read in whichever encoding its *length* says: exactly 64
  bytes is compact, anything else is DER. `/crypto/verify` reports `encoding`
  back, because that rule is the server's own inference rather than something
  the caller stated.
- `network` defaults to mainnet from `services::default_network`, shared by
  `/keys` and `/hd`; `compressed` defaults to true from `services::keys`. The
  domain deliberately gives `Network` no `Default` — picking one is a transport
  decision, not a domain fact.
- **A field that names a notation is required, never defaulted.** `/tools/number`
  takes `base` and `/tools/units` takes `denomination`, both mandatory, for the
  reason `/transactions/builder` requires `type`: the answer changes. `10` is
  two, ten or sixteen; `1` is a satoshi or a hundred million of them. A default
  there would return a confident wrong answer rather than an error.
- **A value that must not be rounded arrives as a string.** `/tools/number`'s
  `value` and `/tools/units`' `amount` refuse a JSON number, which is a double in
  most consumers — exact only below 2^53. 1.2 exists so a 256-bit key can be read
  in decimal, and money is held in integer satoshis precisely so `0.1 + 0.2`
  cannot lose one. Both endpoints answer in strings for the same reason,
  including the satoshi count.

### JSON

- camelCase on the wire (`#[serde(rename_all = "camelCase")]`), snake_case in Rust.
- **Some domain enums serialise straight to the wire on purpose.** `ScriptKind`,
  `ScriptFields`, `Category` and `DecodeError` are stable value types with
  explicit serde spellings, and those spellings *are* the published contract —
  changing one is an API break, not a refactor. `AnalyzedInstruction` gets a
  handler-side view instead, because it carries `Opcode` and `Vec<u8>` that have
  to be rendered as a name and hex. Follow that split: value enums may go direct,
  anything needing rendering gets a view.
- **Where an enum names the answers, the response keys are its serde spellings.**
  `/tools/number` answers under `binary`/`decimal`/`hexadecimal` and
  `/tools/units` under `satoshi`/`microbitcoin`/`millibitcoin`/`bitcoin` —
  exactly the tokens `Base` and `Denomination` deserialize from, which is what
  the request field takes. So one token means one thing in both directions and a
  client can feed a response key straight back in as a request value. Note this
  is why those two keys are not camelCased: `microBitcoin` would be a *second*
  spelling of a value the request already names. `a_units_response_names_every_denomination_the_domain_has`
  pins the set against `Denomination::all()` rather than restating it.

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
| `invalid-word-count` | 400 | Not 12, 15, 18, 21 or 24 words |
| `invalid-seed` | 400 | Not 16–64 bytes, or a seed BIP32 refuses |
| `invalid-derivation-path` | 400 | Not a path; the message names the step |
| `too-many-keys` | 400 | More children than one derive request may ask for |
| `index-out-of-range` | 400 | A child index past the largest normal one, 2³¹−1 |
| `invalid-public-key` | 400 | Not a point on the curve, or not a SEC1 encoding |
| `invalid-message-hash` | 400 | Not the 32 bytes ECDSA signs |
| `invalid-signature` | 400 | Not strict DER (BIP66) and not 64 compact bytes, or `r`/`s` is not a scalar |
| `no-inputs` | 400 | A build request spends nothing |
| `no-outputs` | 400 | A build request pays nothing |
| `duplicate-input` | 400 | Two inputs name the same outpoint |
| `null-prevout` | 400 | An input spends the null outpoint, which only a coinbase may do |
| `amount-out-of-range` | 400 | An amount is past what an amount can be: above 21M BTC for a build request's output or total, above `u64` satoshis at `/tools/units` |
| `amount-too-precise` | 400 | A fraction finer than the unit holds — `0.1 sat` is not a small amount, it is not an amount |
| `invalid-amount` | 400 | Not an amount at all: negative, a stray character, a second decimal point |
| `invalid-number` | 400 | Not a digit in the base the request named; the message gives the offset |
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

**A cap on the input is `input-too-large`; a value past what the type can hold
is not.** `/tools/number` refuses 4097 digits with `input-too-large` and a 413,
because that is a size cap like any other and the caller's fix is to send less.
`/tools/units` refuses more satoshis than fit in a `u64` with
`amount-out-of-range` and a 400, because the *string* was a perfectly ordinary
size and it is the quantity that does not exist. Same for
`amount-too-precise` — `0.1 sat` is twelve characters. Reach for
`input-too-large` when the payload is too big, never when the number is.

**Secrets.** An endpoint returns one only if producing it is its purpose:
`/keys/generate`, `/hd/mnemonic`, `/hd/derive`. What that forbids is handing a
secret back merely because one was given — `/keys/public` takes a private key
and returns only public data. Every endpoint that does return a secret sets
`NO_STORE` and returns `Secret<T>`; `keys_api` asserts `/keys/public` does
*not*, which is what keeps the header a statement rather than boilerplate.

**A type holding a secret writes its own `Debug`.** Requests as well as
responses. Deriving `Debug` on a type holding a seed, a passphrase, a key or a
mnemonic is the bug — `core` already hand-writes one for `PrivateKey`,
`Mnemonic` and `Xpriv`, and a server type that derives it undoes that. Request
logging is a planned feature, and the first `tracing` layer anyone adds formats
an extractor's output with `{:?}`.

**Only the leaves need writing.** A derived `Debug` calls each field's impl, so
redaction propagates through a composite for free. The eight types that hold a
secret each write their own — the three requests `DeriveRequest`,
`GenerateMnemonicRequest` and `PublicKeyRequest`, and the five response views
`PrivateKeyView`, `MnemonicView`, `ExtendedKeyView`, `DerivedPrivateKeyView` and
`GenerateMnemonicResponse`, the last being the one composite carrying a
plaintext field of its own. `GenerateKeyResponse`, `DerivedKeyView` and
`DeriveResponse` hold secrets only through those fields, so they still derive.

Each impl redacts the secret fields and keeps printing the rest, and each has a
test asserting *both* — a redaction that blanked everything would pass half a
test and lose the debugging value that is the only reason `Debug` is there.
`a_derived_debug_inherits_the_leafs_redaction` pins the propagation itself.

**A `false` answer is not an error.** `/crypto/verify` returns 200 with
`valid: false` for a signature that does not verify: that is the question the
endpoint exists to answer, and there is no sub-reason a caller could act on.
Only bytes that are not a signature *at all* are a 400. The same split governs
how far the domain reaches — a four-kilobyte signature still hears
`invalid-signature`, because 72 bytes is a fact about DER rather than a policy
of this server, and the route cap sits high enough to let the domain say so.

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

- **Path casing.** A multi-word path is kebab-case: `/tools/reverse-bytes` is
  the first one and settles that much, since kebab is the ordinary REST
  convention. `the_multi_word_path_is_kebab_case` asserts the snake_case
  spelling 404s rather than quietly aliasing. What is still open is the
  *existing* single-word paths (`/script`, `/splitter`, `/derive`) — they read
  the same under every convention, so renaming them buys nothing and is the
  user's call, not to be done unilaterally.
- Trailing slashes 404 (`/transactions/script/`). Undecided whether to normalise.
- **`/hd/seed`** — words plus passphrase in, seed out. The missing direction:
  nothing in the API takes a mnemonic, so a caller who kept the sentence and
  the passphrase (which is what BIP39 trains people to keep) cannot get back to
  their wallet here, and `/hd/mnemonic`'s `passphrase` field cannot be
  exercised against a sentence the caller already has. Small, and it is what
  would make that field fully honest.
- No env-based config, request logging, or graceful shutdown yet.
