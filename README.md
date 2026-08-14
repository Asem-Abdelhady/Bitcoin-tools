# bitcoin-tools

Decode and inspect Bitcoin's data formats — transactions, scripts, keys,
addresses, HD wallets, and blocks — as a Rust library and as a JSON API over it.

Everything is pure computation over bytes. There is no node, no network, no
chain state: you hand it hex and it tells you what the hex means, with the
offsets and intermediate values that a tool exists to show. A P2PKH address is
returned alongside its version byte, its hash and its checksum, not just as a
finished string.

```console
$ curl -s localhost:3000/transactions/script -H 'content-type: application/json' \
      -d '{"script":"76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac"}'
{"hex":"76a914…88ac","sizeBytes":25,"kind":"P2PKH",
 "asm":"OP_DUP OP_HASH160 OP_PUSHBYTES_20 65ed36…797f OP_EQUALVERIFY OP_CHECKSIG",
 "fields":{"pubkeyHash":"65ed366110a6fe3132cc1f63d73d3bb5a658797f"},
 "hasDisabledOpcode":false,
 "instructions":[{"offset":0,"hex":"76","opcode":"OP_DUP","category":"stack",
                  "description":"Duplicate the top item"}, …]}
```

## Quick start

Requires Rust 1.87 or newer (edition 2024; `u64::is_multiple_of` sets the floor).

```console
$ cargo run -p bitcoin-tools-server     # listens on 0.0.0.0:3000
$ cargo test --workspace                # ~500 tests, mostly published vectors
```

There is no configuration, no database and no state — the process binds a port
and answers. Every endpoint is `POST` with a JSON body and returns JSON.

The library alone, without the server — it is a normal cargo crate and carries
no dependency on axum:

```toml
[dependencies]
bitcoin-tools-core = { git = "https://github.com/Asem-Abdelhady/Bitcoin-tools" }
```

```rust
use bitcoin_tools_core::transactions::script::{Script, ScriptKind};

let script = Script::from_hex("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac").unwrap();
assert_eq!(script.kind(), ScriptKind::P2PKH);

// Every step keeps the offset it came from.
for step in script.disassemble().0 {
    println!("{:>4}  {}", step.offset, step.instruction);
}
```

`cargo run -p bitcoin-tools-core --example disasm <hex>` does the same from a
terminal.

## Workspace

| Crate | Path | What it is |
|---|---|---|
| `bitcoin-tools-core` | [crates/core/](crates/core/) | The domain library, as a standalone publishable cargo package. No HTTP, no I/O, no framework. Its [README](crates/core/README.md) is the spec — feature status, layering, and the reasoning behind both. |
| `bitcoin-tools-server` | [crates/server/](crates/server/) | The axum JSON API. Not published. |
| `bitcoin-tools-vectors` | [crates/vectors/](crates/vectors/) | Known-good test vectors, shared by both test suites. Dev-dependency only. |

The split is load-bearing rather than cosmetic: core **cannot** reference the
server, because it is a separate crate and the compiler says so.

Inside core, modules are layered and nothing imports upward —
`hex`/`bytes`/`network` → `hashes`/`general` → `encoding`/`crypto` → `keys` →
`hd`/`transactions`/`blocks`. That one rule is what stops the same checksum loop
being written five times, and it is checkable with grep. The three edges the
obvious signature would create, and why each is forbidden, are written into the
module docs.

The server is three layers, in [crates/server/src/](crates/server/src/):

| Layer | Responsibility |
|---|---|
| [routes/](crates/server/src/routes/) | URL and method binding, transport limits |
| [handlers/](crates/server/src/handlers/) | Extraction, response views, status codes |
| [services/](crates/server/src/services/) | Use cases and input policy; no HTTP |

"DTO" splits along the same line. A **response** is a view — it renders domain
values into strings — so it lives with the handler. A **request shape** is input
policy — which fields exist, which are optional, `deny_unknown_fields` — so it
lives with the service that validates it.

## Endpoints

Fourteen, in six groups. All are `POST` and take `Content-Type: application/json`.

### General tools

| | Body | Returns |
|---|---|---|
| `/tools/reverse-bytes` | `{"hex"}` | The bytes flipped — wire order ⇄ the display order an explorer shows |
| `/tools/number` | `{"value", "base"}` | The same value in `binary`, `decimal`, `hexadecimal`, plus its width |
| `/tools/units` | `{"amount", "denomination"}` | The same amount in `satoshi`, `microbitcoin`, `millibitcoin`, `bitcoin` |

```console
$ … /tools/units -d '{"amount":"1.5","denomination":"bitcoin"}'
{"satoshi":"150000000","microbitcoin":"1500000","millibitcoin":"1500",
 "bitcoin":"1.5","isMoneyRange":true}
```

`base` and `denomination` are **required, never defaulted**. `10` is two, ten or
sixteen; `1` is a satoshi or a hundred million of them. A default there would
return a confident wrong answer rather than an error.

Both take their value as a **string** and answer in strings, including the
satoshi count. A JSON number is a double in most consumers, exact only below
2⁵³ — and `/tools/number` exists so a 256-bit key can be read in decimal, while
money is held in integer satoshis precisely so `0.1 + 0.2` cannot lose one.

### Keys and addresses

| | Body | Returns |
|---|---|---|
| `/keys/generate` | `{"network"?, "compressed"?}` | A new private key as hex, decimal, binary and WIF |
| `/keys/public` | `{"privateKey", "network"?, "compressed"?}` | The public key and **every** address it produces, each split into its parts |

```console
$ … /keys/public -d '{"privateKey":"0000…0001"}'
{"network":"mainnet","compressed":true,
 "publicKey":{"hex":"0279be66…","uncompressed":"0479be66…","xOnly":"79be66…",
              "x":"79be66…","y":"483ada77…","pubkeyHash":"751e76e8…"},
 "addresses":{
   "p2pkh":{"address":"1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH",
            "scriptPubkey":"76a914751e76e8…88ac",
            "base58":{"version":0,"versionHex":"00","hash":"751e76e8…",
                      "checksum":"510d1634"}},
   "p2shP2wpkh":{…},
   "p2wpkh":{"address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
             "bech32":{"hrp":"bc","witnessVersion":0,"program":"751e76e8…",
                       "checksum":"v8f3t4"}},
   "p2tr":{…}},
 "p2wpkhRedeemScript":"0014751e76e8…"}
```

`network` defaults to mainnet and `compressed` to true. The domain deliberately
gives `Network` no `Default` — picking one is a transport decision, not a domain
fact, so the API states it in one place rather than four.

### HD wallets

| | Body | Returns |
|---|---|---|
| `/hd/mnemonic` | `{"wordCount"?, "passphrase"?, "network"?}` | A BIP39 sentence with its entropy, indices and checksum, the seed it derives, and the BIP32 master key |
| `/hd/derive` | `{"seed", "path", "count"?, "startIndex"?, "network"?}` | The branch's extended keys, then each child with its private key, WIF, and full address set |

```console
$ … /hd/derive -d '{"seed":"000102030405060708090a0b0c0d0e0f",
                    "path":"m/84h/0h/0h/0","count":2}'
{"network":"mainnet","purpose":"bip84",
 "branch":{"path":"m/84'/0'/0'/0","depth":4,"fingerprint":"b1cc03eb",
           "parentFingerprint":"e889b6af","chainCode":"597354c4…",
           "xprv":"xprvA2Fgj…","xpub":"xpub6FF39…"},
 "keys":[{"index":0,"path":"m/84'/0'/0'/0/0",
          "privateKey":{"hex":"8d98d2f7…","wif":"L1xxTDd4RJ9GG7jZ…"},
          "publicKey":"02ce3088…","pubkeyHash":"0f0d117a…",
          "address":"bc1qpux3z758ulsxg69eptaakukraanqwtdxe5yy4c",
          "addresses":{…}}, …]}
```

Apostrophe or `h` marks a hardened step; `purpose` is inferred from the path.
BIP44/49/84/86 are what they are here — four purpose numbers over one algorithm,
not four code paths.

### Transactions

| | Body | Returns |
|---|---|---|
| `/transactions/script` | `{"script"}` | Template kind, ASM, extracted fields, and every instruction with its offset, category and description |
| `/transactions/splitter` | `{"tx"}` | Every wire field as the hex bytes it occupies, plus the txid |
| `/transactions/builder` | `{"type", "version"?, "lockTime"?, "inputs", "outputs"}` | The serialized transaction, its txid, and its size, weight and vsize |

```console
$ … /transactions/builder -d '{"type":"legacy",
      "inputs":[{"txid":"aa52ef52…","vout":0}],
      "outputs":[{"amount":100000,"scriptPubkey":"76a914751e76e8…88ac"}]}'
{"txid":"406f76f4d673e9031bd0d3d33cca9b916d87d659b3552a9e6c7117315bd1423b",
 "size":85,"weight":340,"vsize":85,"rawTx":"020000000160ae0e48…0000000000"}
```

`type` is the one builder field with no default, for the same reason `base` has
none: it changes the bytes, the txid, and whether a witness survives at all.
Everything else carries the domain's own default — version 2, locktime 0,
sequence `0xffffffff`, empty `scriptSig`.

The builder validates; it does not sign. A signature commits to a sighash, and a
sighash needs the value and script of every output being spent, which a raw
transaction does not carry. What it does refuse is the set of transactions that
serialize cleanly and are still rejected by every node — no inputs, no outputs, a
duplicated outpoint, the coinbase outpoint, an amount above 21 million, both
halves of BIP144's witness rule, and `bad-txns-oversize`. Each check cites the
Core rule it mirrors, and each gets its own error slug so a client can say which
field to fix.

### Blocks

| | Body | Returns |
|---|---|---|
| `/blocks/hash` | `{"header"}` | The block hash, in both display and wire order |
| `/blocks/header` | `{"header"}` | The eighty bytes as fields, with the target, difficulty, and whether the header meets it |

```console
$ … /blocks/header -d '{"header":"01000000…1dac2b7c"}'   # genesis
{"blockHash":"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
 "version":1,"versionHex":"00000001","prevBlock":"00000000…",
 "merkleRoot":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b",
 "time":1231006505,"bits":"1d00ffff","nonce":2083236893,
 "target":"00000000ffff0000000000000000000000000000000000000000000000000000",
 "difficulty":1.0,"meetsTarget":true}
```

`meetsTarget` closes the loop — it checks the header's own hash against the
target its `bits` expand to, rather than asking you to trust either.

### Cryptography

| | Body | Returns |
|---|---|---|
| `/crypto/sign` | `{"privateKey", "messageHash", "compressed"?}` | The signature in DER and compact form, with `r`, `s` and `isLowS` |
| `/crypto/verify` | `{"publicKey", "messageHash", "signature"}` | `valid`, the encoding the signature was read in, and the signature's parts |

Signing is RFC 6979 deterministic: no RNG, and a repeated nonce — which hands an
attacker the private key outright — is impossible unless the message repeats.
Output is always low-`s`.

A signature is read in whichever encoding its **length** says: exactly 64 bytes
is compact, anything else is DER. `/crypto/verify` reports `encoding` back,
because that rule is the server's inference rather than something the caller
stated.

A `false` answer is **not** an error. A signature that does not verify returns
200 with `valid: false` — that is the question the endpoint exists to answer, and
there is no sub-reason a caller could act on. Only bytes that are not a signature
at all are a 400.

## Errors

Every failure, including the 404 and 405 fallbacks, returns the same envelope:

```json
{"error": "amount-too-precise",
 "message": "sat has 0 decimal places; anything finer is not a whole number of satoshis"}
```

`error` is a stable kebab-case slug to branch on; `message` is for a human and
carries the specifics — the offset, the size actually sent, the step of the path
that failed, or which input of a build request was wrong. Slugs are shared across
endpoints, so a client learns one vocabulary:

| Slug | Status | Meaning |
|---|---|---|
| `empty-input` | 400 | Field was empty after trimming |
| `invalid-hex` | 400 | Not hex, or odd length |
| `input-too-large` | 413 | Past the domain size cap |
| `malformed-json` | 400 | Body is not JSON |
| `invalid-body` | 422 | Valid JSON, wrong shape or types |
| `unsupported-media-type` | 415 | Missing or wrong `Content-Type` |
| `unreadable-body` | 413 / 400 | Body could not be buffered — 413 past the route's transport cap, 400 if the stream failed |
| `not-found` / `method-not-allowed` | 404 / 405 | No endpoint here; or wrong method |

…plus one slug per domain failure, each named for what it parses:
`invalid-transaction`, `invalid-block-header`, `invalid-txid`,
`invalid-private-key`, `invalid-public-key`, `invalid-signature`,
`invalid-message-hash`, `invalid-word-count`, `invalid-seed`,
`invalid-derivation-path`, `index-out-of-range`, `too-many-keys`,
`invalid-number`, `invalid-amount`, `amount-too-precise`,
`amount-out-of-range`, and the builder's per-rule set (`no-inputs`,
`no-outputs`, `duplicate-input`, `null-prevout`, `segwit-without-witness`,
`witness-on-legacy`, `transaction-too-large`).

Two distinctions worth knowing when you write a client:

- **413 arrives under two slugs.** `unreadable-body` is the transport cap
  rejecting the request before the handler runs; `input-too-large` is the service
  rejecting the decoded value. The second one can tell you the limit and what you
  sent, so the route caps sit above the domain caps deliberately.
- **A cap on the input is `input-too-large`; a quantity that cannot exist is
  not.** 4097 digits is a size problem (413). More satoshis than fit in a `u64`
  is `amount-out-of-range` (400) — the *string* was an ordinary size, and it is
  the number that does not exist.

Malformed **data** the request asked about is a judgement call, and the two
endpoints answer differently on purpose: a broken script returns 200 with an
`error` field alongside everything that did decode, because showing where it
broke is the point; a broken transaction returns 400, because once field
boundaries stop lining up there is no partial answer.

## Secrets

Three endpoints return a secret — `/keys/generate`, `/hd/mnemonic`, `/hd/derive`
— because producing one is their purpose. Each sets `Cache-Control: no-store` and
returns a type that says so in its signature. No endpoint hands a secret back
merely because one was given: `/keys/public` takes a private key and returns only
public data, and a test asserts it does *not* set the header, which is what keeps
the header a statement rather than boilerplate.

Any type holding a secret hand-writes its own `Debug` and redacts those fields —
requests as well as responses, since the first `tracing` layer anyone adds will
format an extractor's output with `{:?}`. Each redaction has a test asserting
both that the secret is gone *and* that the rest still prints.

**A key from `/keys/generate` is generated on the server's machine, with that
machine's RNG, and travels back in a response body.** It is as private as the
process, the network hop, and anything logging either. That is fine for a locally
run inspection tool and it is what the endpoint is for; a key meant to hold value
should be generated on the device that will keep it.

Likewise, `/hd/derive` takes a **seed**, and nothing in this API takes a
mnemonic — so the BIP39-trained habit of writing down the words and the
passphrase will not get you back here. Keep the seed.

## Development

```console
$ cargo fmt --all
$ cargo clippy --workspace --all-targets
$ cargo test --workspace
$ cargo check -p bitcoin-tools-core --no-default-features   # `serde` is optional
```

Tests are vectors-first. Core asserts its decoder reproduces each published
vector; the server asserts its HTTP response equals the same one, from the same
[crates/vectors/](crates/vectors/) crate — never from a restated expectation.
BIP32, BIP39, BIP173 and BIP350 each publish inputs that must be **refused**, and
those are included: half of `hd_vectors.rs` is extended keys the decoder has to
reject, and 308 of Project Wycheproof's 476 ECDSA cases are refusals. A decoder
that accepts everything passes every other suite in the repository.

API tests go through the composed `app()` at real URIs, so a mistyped `nest`
prefix fails the suite instead of shipping.

Before adding an endpoint, read the building-blocks table in
[.claude/CLAUDE.md](.claude/CLAUDE.md). A new endpoint should add no new hex
parser, no new error envelope, and no fourth copy of "unknown field is 422" — its
entire error cost is one `impl ApiError` giving a status and a slug. That file is
also the project's conventions in full, and the contributor-facing half of it
applies whether or not you are using an agent.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
