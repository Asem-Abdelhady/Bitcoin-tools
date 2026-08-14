# bitcoin-tools-server

An axum JSON API over [`bitcoin-tools-core`](../core/README.md).

Fourteen endpoints, no state, no configuration: the process binds a port and
answers. Every route is `POST`, takes JSON, and returns JSON — including its
errors.

**Looking for the endpoint reference?** It is in the [workspace
README](../../README.md): request and response shapes, worked examples, and the
error-slug table a client branches on. This file is about how the crate is
built and how to work in it.

`publish = false`. It exists to expose core over HTTP, and deliberately holds no
Bitcoin logic of its own.

```console
$ cargo run -p bitcoin-tools-server           # 0.0.0.0:3000
$ cargo test -p bitcoin-tools-server
```

## Layers

| Layer | Path | Responsibility |
|---|---|---|
| Routes | [`src/routes/`](src/routes/) | URL and method binding, transport limits. No logic. |
| Handlers | [`src/handlers/`](src/handlers/) | Transport: extraction, response views, status codes. |
| Services | [`src/services/`](src/services/) | Use cases and input policy. **No HTTP.** |

A service does not know it is being called over HTTP — no `StatusCode`, no
`Json`, no axum types in a signature. That is what makes the input policy
testable as a unit and reusable by something that is not this server.

**"DTO" splits in two, and the split follows the layers above.**

A **response** is a view. It renders domain values into strings and decides what
a client sees, so it lives with the handler: `SplitTxResponse`,
`BuildTxResponse`, `ReverseResponse`.

A **request shape** is input policy — which fields exist, which are optional,
`camelCase`, `deny_unknown_fields` — so it lives with the service that validates
it: `TxSpec`, `UnitsRequest`, `DeriveRequest`.

`serde` is a serialization crate, not a transport one; core derives it too, and
a mirrored pair of structs with an identity `From` between them is four edits
per field with the compiler catching three.

## One request, end to end

`POST /tools/reverse-bytes` is the smallest complete endpoint in the crate and
the one worth reading first.

**Route** — [`routes/tools/mod.rs`](src/routes/tools/mod.rs) binds the path and
the transport cap, sized from the domain constant:

```rust
.route(
    "/reverse-bytes",
    post(reverse::post_reverse_bytes).layer(DefaultBodyLimit::max(body_limit(MAX_BYTES))),
)
```

**Service** — [`services/tools/reverse.rs`](src/services/tools/reverse.rs) owns
the input policy and nothing else:

```rust
pub fn decode(request: &HexRequest) -> Result<Vec<u8>, InputError> {
    hex_bytes(&request.hex, SUBJECT, MAX_BYTES)
}
```

**Handler** — [`handlers/tools/reverse.rs`](src/handlers/tools/reverse.rs) does
the rendering, because rendering is what reversal *is*:

```rust
pub async fn post_reverse_bytes(
    payload: Result<Json<HexRequest>, JsonRejection>,
) -> Result<Json<ReverseResponse>, ApiRejection<InputError>> {
    let Json(request) = payload?;
    let bytes = decode(&request).map_err(ApiRejection::Domain)?;

    Ok(Json(ReverseResponse {
        input: hex::encode(&bytes),
        reversed: hex::encode_rev(&bytes),
        bytes: bytes.len(),
    }))
}
```

Note the rejection type: `ApiRejection<InputError>`, not the
`ServiceError<E>` every other endpoint declares. Reversing decoded bytes cannot
fail, so there is no domain half to name — and the day it grows one, that line
stops compiling rather than mapping a real error onto a status somebody guessed.
`/keys/generate` makes the same statement with `Infallible`.

## Reuse these — a new endpoint should add none of them

| Building block | What it gives you |
|---|---|
| `lib::app()` | The one place routes are mounted. Tests drive this, never a sub-router, so a mistyped `nest` prefix fails the suite. |
| `routes::body_limit(max)` | Per-route transport cap, sized from the domain constant. Required on any route taking hex. |
| `bitcoin_tools_core::hex` | The only hex codec: `encode`, `decode`, `normalize`, `HexError`. |
| `services::input::hex_bytes` | The only definition of "usable hex input": trim, `0x`, empty, size cap. |
| `services::input::hex_bytes_allowing_empty` | The same, for a field where empty is a real value — an unsigned `scriptSig`, an empty witness item. |
| `services::input::hex_bytes_exact` | The same, for a field of one fixed width. Both directions of the width become *your* domain error, so the endpoint keeps a slug named for what it parses. |
| `services::error::ServiceError<E>` | `Input`-or-`Domain`. State only your own parse error type; `map_domain` re-labels the domain half when one service builds on another. |
| `services::tools::HexRequest` | `{"hex": "<hex>"}`, for a `/tools` endpoint whose input is one payload with no domain noun to name it after. |
| `services::keys::private_key` | The one definition of "read a private key from a request", shared by `/keys/public` and `/crypto/sign`. |
| `services::default_network` / `keys::default_compressed` | Mainnet, and compressed. Stated once so `/keys` and `/hd` cannot disagree. |
| `handlers::error` | `ApiError` trait + `ApiRejection<E>`. `IntoResponse`, the JSON envelope, `JsonRejection` mapping, and the 404/405 fallbacks are all implemented once. |
| `handlers::address` | Every address a public key produces, with its parts. `/keys/public` and `/hd/derive` both render it — two places deciding which addresses exist is two places to forget BIP143. |
| `handlers::NO_STORE` | `Cache-Control: no-store`. Set by every endpoint returning a secret and by no others, so its presence means something. |
| `handlers::Secret<T>` | The return type of an endpoint that hands over a secret. Pairs with `NO_STORE` so the signature says it. |
| `tests/common::assert_transport_contract` | The four assertions every JSON endpoint owes a client. A suite asserts its *domain*; the transport half is one line. |
| `tests/common::assert_error` | Status and slug together, with the body in the failure message. Returns the body for message checks. |
| `tests/common::post_ok` / `post_json` / `post_json_headers` | The happy path, the raw path, and the response headers for the endpoints whose contract includes one. |

If you find yourself writing an `ErrorBody`, an `IntoResponse` impl, a hex
parser, `max_bytes * 2 + 1024`, or a fourth copy of "unknown field is 422" —
stop. It exists.

## Adding an endpoint

1. **Service.** A request struct with `#[serde(rename_all = "camelCase",
   deny_unknown_fields)]`, and a function taking `&Request` and returning
   `Result<DomainValue, ServiceError<YourError>>`. Validate through
   `services::input`; never parse hex by hand.
2. **Handler.** A response view deriving `Serialize` with `rename_all =
   "camelCase"`, and an `async fn` taking `Result<Json<Request>,
   JsonRejection>`.
3. **Error.** One `impl ApiError for YourDomainError` giving a status and a
   kebab-case slug. That is the entire error cost of a new endpoint.
4. **Route.** One `.route(...)` line with a `body_limit` sized from the domain
   constant, in the existing group's router — a new file plus a `mod`
   declaration is not worth it for one line.
5. **Tests.** A suite driving `app()` at the real URI, plus
   `assert_transport_contract` for the transport half.

Then run the review loop in [`.claude/CLAUDE.md`](../../.claude/CLAUDE.md) —
`cargo fmt`, `cargo clippy --workspace --all-targets`, `cargo test --workspace`,
then the `rust-api-reviewer` agent until it approves.

## Errors

One envelope, everywhere, including the 404 and 405 fallbacks:

```json
{"error": "invalid-block-header", "message": "a block header is 80 bytes, got 1"}
```

`error` is a stable kebab-case slug produced by `ApiError::slug`; `message` is
for a human and carries the specifics. The full slug table is in the [workspace
README](../../README.md#errors). What matters when you are adding one:

- **Reuse a slug when the client's fix is the same.** A field-level hex problem
  inside a build request keeps `invalid-hex` and adds the position to the
  message. Clients should not learn two vocabularies for one failure.
- **Split a slug when the fix differs.** The builder's rules are per-rule —
  `no-inputs`, `duplicate-input`, `null-prevout` — because each names a
  different mistake and a client branching on them can say which field to fix.
- **A fixed-width input has no "too large."** A header is 80 bytes and a private
  key is 32, so a byte over and a byte under are one mistake with one answer.
  `hex_bytes_exact` is where that lives; pass it a closure building your own
  error and it handles both directions. `input-too-large` elsewhere means a
  10 kB script.
- **A cap on the input is `input-too-large`; a value past what the type holds is
  not.** 4097 digits is a size problem (413). More satoshis than fit in a `u64`
  is `amount-out-of-range` (400) — the string was an ordinary size and it is the
  quantity that does not exist.
- **One endpoint can return 413 under two slugs.** `unreadable-body` is the
  route's transport cap rejecting the request before the handler runs;
  `input-too-large` is the service rejecting the decoded value. Both are real,
  and the route cap sits above the domain cap so the second one — which can name
  the limit and the size sent — is what a caller usually gets.

**A `false` answer is not an error.** `/crypto/verify` returns 200 with
`valid: false`: that is the question the endpoint exists to answer, and there is
no sub-reason a caller could act on. Only bytes that are not a signature at all
are a 400.

**A malformed *request* is 4xx; malformed *data* the request asked about is a
judgement call.** A broken script returns 200 with an `error` field, because
showing where it broke is the point. A broken transaction returns 400, because
once field boundaries stop lining up there is no partial answer.

## Secrets

An endpoint returns one only if producing it is its purpose: `/keys/generate`,
`/hd/mnemonic`, `/hd/derive`. What that forbids is handing a secret back merely
because one was given — `/keys/public` takes a private key and returns only
public data. Every endpoint that does return one sets `NO_STORE` and returns
`Secret<T>`; `keys_api` asserts `/keys/public` does *not*, which is what keeps
the header a statement rather than boilerplate.

**A type holding a secret writes its own `Debug`.** Requests as well as
responses. Core already hand-writes one for `PrivateKey`, `Mnemonic` and
`Xpriv`, and a server type that derives it undoes that. Request logging is a
planned feature, and the first `tracing` layer anyone adds formats an
extractor's output with `{:?}`.

**Only the leaves need writing.** A derived `Debug` calls each field's impl, so
redaction propagates through a composite for free. Ten types write their own:

| Where | Types |
|---|---|
| Requests | `SignRequest`, `DeriveRequest`, `GenerateMnemonicRequest`, `PublicKeyRequest` |
| Response views | `PrivateKeyView`, `MnemonicView`, `ExtendedKeyView`, `DerivedPrivateKeyView`, `GenerateMnemonicResponse` |
| Service value | `GeneratedMnemonic` — the one place a mnemonic, a seed and an `Xpriv` sit together, and the seed is a bare `[u8; 64]` that would print in full |

`GenerateKeyResponse`, `DerivedKeyView` and `DeriveResponse` hold secrets only
through those fields, so they still derive. Grep for `impl fmt::Debug` before
adding a type that holds one.

Each impl redacts the secret fields and keeps printing the rest, and each has a
test asserting *both* — a redaction that blanked everything would pass half a
test and lose the debugging value that is the only reason `Debug` is there.
`a_derived_debug_inherits_the_leafs_redaction` pins the propagation itself.

## Request conventions

- **camelCase on the wire, snake_case in Rust.** All request DTOs use
  `deny_unknown_fields` and live in their service; a request shape in a handler
  is drift, not variation.
- **Domain endpoints keep a self-documenting field name:** `{"script": "…"}`,
  `{"tx": "…"}`, `{"header": "…"}`. Generic `/tools` endpoints share
  `HexRequest` rather than each inventing a key.
- **Two endpoints over one input share one request struct**, in the service that
  validates it — `/blocks/hash` and `/blocks/header` both take
  `BlockHeaderRequest`. Two structs with identical fields would let the two
  drift apart while looking deliberate.
- **A field that names a notation is required, never defaulted.**
  `/tools/number` takes `base` and `/tools/units` takes `denomination`, both
  mandatory, for the reason `/transactions/builder` requires `type`: the answer
  changes. `10` is two, ten or sixteen. A default there would return a confident
  wrong answer rather than an error.
- **A value that must not be rounded arrives as a string** — and leaves as one.
  A JSON number is a double in most consumers, exact only below 2⁵³.
- **Where an enum names the answers, the response keys are its serde
  spellings.** `/tools/units` answers under `satoshi`/`microbitcoin`/
  `millibitcoin`/`bitcoin`, exactly the tokens `Denomination` deserializes from,
  so a client can feed a response key straight back in as a request value. That
  is why those keys are not camelCased: `microBitcoin` would be a *second*
  spelling of a value the request already names.
- **Some domain enums serialise straight to the wire on purpose.**
  `ScriptKind`, `ScriptFields`, `Category` and `DecodeError` are stable value
  types with explicit serde spellings, and those spellings *are* the published
  contract — changing one is an API break, not a refactor. `AnalyzedInstruction`
  gets a handler-side view instead, because it carries `Opcode` and `Vec<u8>`
  that have to be rendered as a name and hex. Follow that split: value enums may
  go direct, anything needing rendering gets a view.

## Tests

193 tests: 116 across nine integration suites, all driving `app()` at real URIs
through [`tests/common/mod.rs`](tests/common/mod.rs) — so a mistyped `nest`
prefix fails the suite instead of shipping — plus 76 unit tests beside the code
and one doctest.

| Suite | Covers |
|---|---|
| `tools_api.rs` | `/tools/reverse-bytes`, `/tools/number`, `/tools/units` |
| `keys_api.rs` | `/keys/generate`, `/keys/public`, and the `no-store` split |
| `hd_api.rs` | `/hd/mnemonic`, `/hd/derive` |
| `crypto_api.rs` | `/crypto/sign`, `/crypto/verify` |
| `blocks_api.rs` | `/blocks/hash`, `/blocks/header` |
| `script_api.rs`, `splitter_api.rs`, `builder_api.rs` | the three `/transactions` endpoints |
| `tx_vectors.rs` | the HTTP responses against the same vectors core decodes |

**Vectors come from the `bitcoin-tools-vectors` crate, never from a path or a
restated expectation.** Core asserts its decoder reproduces each vector; the
server asserts its HTTP response equals the same one. Where an endpoint has no
vectors of its own, the test asserts a *relation* to the rest of the API instead
of inventing one — `/tools/reverse-bytes` is pinned against the two byte orders
`/blocks/hash` already reports, over the ten mainnet headers in the shared
crate.

A suite asserts its own domain; the four transport assertions every JSON
endpoint owes a client are one line:

```rust
assert_transport_contract("/tools/units", &json!({"amount": "1", "denomination": "bitcoin"})).await;
```

## Open decisions

- **Path casing.** A multi-word path is kebab-case: `/tools/reverse-bytes` is
  the first one and settles that much. What is still open is the *existing*
  single-word paths (`/script`, `/splitter`, `/derive`) — they read the same
  under every convention, so renaming them buys nothing and is not to be done
  unilaterally. `the_multi_word_path_is_kebab_case` asserts the snake_case
  spelling 404s rather than quietly aliasing.
- **Trailing slashes 404** (`/transactions/script/`). Undecided whether to
  normalise.
- **`/hd/seed`** — words plus passphrase in, seed out. The missing direction:
  nothing in the API takes a mnemonic, so a caller who kept the sentence and the
  passphrase (which is what BIP39 trains people to keep) cannot get back to
  their wallet here, and `/hd/mnemonic`'s `passphrase` field cannot be exercised
  against a sentence the caller already has. Small, and it is what would make
  that field fully honest.
- **No env-based config, request logging, or graceful shutdown yet.** The port
  is hardcoded in `main.rs`.

## Review

Reviewed by the `rust-api-reviewer` agent, which is forbidden from reading
`crates/core` for critique — `rust-core-reviewer` owns that half. Do not
override either exclusion; they are what keep the two reviews independent.

## License

MIT. See [LICENSE-MIT](../../LICENSE-MIT).
