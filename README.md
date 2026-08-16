# bitcoin-tools

Decode and inspect Bitcoin's data formats — transactions, scripts, keys,
addresses, HD wallets, and blocks — as a Rust library, a JSON API, and a
command-line tool.

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
$ cargo install bitcoin-tools           # the `bt` command
$ cargo run -p bitcoin-tools-server     # the API, on 0.0.0.0:3000
$ cargo run -p bitcoin-tools -- converter unit --bitcoin 1.5
$ cargo test --workspace                # ~680 tests, mostly published vectors
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
| `bitcoin-tools-server` | [crates/server/](crates/server/) | The axum JSON API. See its [README](crates/server/README.md). Not published. |
| `bitcoin-tools` | [crates/cli/](crates/cli/) | The clap command-line tool, installed as `bt`: formatted output, `--json` for machines, input from arguments or JSON files. Published. See its [README](crates/cli/README.md). |
| `bitcoin-tools-vectors` | [crates/vectors/](crates/vectors/) | Known-good test vectors, shared by the other crates' test suites — including the `tools` answers both front ends must agree on. Dev-dependency only. |

The split is load-bearing rather than cosmetic: core **cannot** reference either
front end, because they are separate crates and the compiler says so.

The server and the CLI are **peers**. Neither is the real interface, and where
they answer the same question they answer it identically. Their *surfaces* may
differ where the medium differs — the CLI says `converter base --hex ab12` where
the API takes `{"value": "ab12", "base": "hexadecimal"}` — but the answers are
pinned by shared vectors.

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

## The two front ends

The same fourteen operations, twice. Neither is the real interface: the core is
shaped by neither, and where they answer the same question they answer it
identically — pinned by shared vectors, not by intent.

| Group | Operations | HTTP | Command line |
|---|---|---|---|
| General tools | Byte order, number bases, units | `/tools/*` | `converter` |
| Keys | Generate a key; every address one produces | `/keys/*` | `keys` |
| HD wallets | BIP39 sentences, BIP32 derivation | `/hd/*` | `hd` |
| Transactions | Scripts, raw transactions, building one | `/transactions/*` | `transactions` |
| Blocks | Header hash, header fields | `/blocks/*` | `blocks` |
| Cryptography | ECDSA sign and verify | `/crypto/*` | `crypto` |

**The endpoint reference — request and response shapes, worked examples, and the
error-slug table a client branches on — is in
[crates/server/README.md](crates/server/README.md).** Every route is `POST`,
takes `Content-Type: application/json`, and returns JSON including its errors.

**The command reference — every command with a runnable example — is in
[crates/cli/README.md](crates/cli/README.md).**

Their *surfaces* may differ where the medium differs. The CLI says
`converter base --hex ab12` where the API takes
`{"value": "ab12", "base": "hexadecimal"}`, because a command line can put the
notation in the flag and a JSON body has no better option than a field. Their
answers do not differ:

```console
$ curl -s localhost:3000/tools/units -H 'content-type: application/json' \
      -d '{"amount":"1.5","denomination":"bitcoin"}' | jq -S .
$ bt converter unit --bitcoin 1.5 --json | jq -S .
```

Same object, both times. `crates/vectors/data/tools.json` holds the argv, the
request body and the one response both must produce.

### What the command line does that an HTTP body cannot

- **The notation is the flag.** `converter base --hex ab12`. A value cannot
  arrive without saying what it is written in, because no argument carries one
  without the other. A JSON body has no better option than a field.
- **A secret is never an argument.** There is no `--private-key`, no `--seed`
  and no `--passphrase` — the flag names a *file*, and `-` is stdin. Arguments
  are visible in `ps` to every user on the machine and land in shell history,
  and neither is something you can take back.
- **Two output modes, one value.** Formatted text for a terminal, or `--json`,
  which is the API's response shape. They are not two code paths: one type,
  whose `Serialize` is the JSON contract and whose `render` is the terminal one.

```console
$ bt blocks header 01000000…1dac2b7c
$ bt keys public --private-key-file key.hex
$ bt hd derive --seed-file seed.hex --path m/84h/0h/0h/0 --count 5
$ bt transactions splitter --input tx.json --json | jq .txid
```

Every command also reads its whole request from `--input <FILE>` in the API's
own request shape, so one file drives both front ends.

## Errors

Every failure, including the 404 and 405 fallbacks, returns the same envelope:

```json
{"error": "amount-too-precise",
 "message": "sat has 0 decimal places; anything finer is not a whole number of satoshis"}
```

`error` is a stable kebab-case slug to branch on; `message` is for a human and
carries the specifics — the offset, the size actually sent, the step of the path
that failed, or which input of a build request was wrong. Slugs are shared
across endpoints, so a client learns one vocabulary rather than one per route.
**The full table is in [crates/server/README.md](crates/server/README.md#errors).**

The CLI answers the same failures as exit codes: 0, 1 for bad input, and 2 for a
usage mistake, which clap owns.

Two distinctions worth knowing whichever front end you use:

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

The CLI inherits all of that and adds the problem a CLI has and an API does not:
**a secret is never an argument.** There is no `--private-key`, no `--seed` and
no `--passphrase` — arguments are visible in `ps` to every user on the machine
and land verbatim in shell history. The flag names a file instead, `-` means
stdin, and a test asserts the rule against the generated help rather than against
the documentation.

## Development

```console
$ cargo fmt --all
$ cargo clippy --workspace --all-targets
$ cargo test --workspace
$ cargo check -p bitcoin-tools-core --no-default-features   # `serde` is optional
```

Tests are vectors-first. Core asserts its decoder reproduces each published
vector; the server asserts its HTTP response equals the same one, and the CLI
asserts its `--json` does too — all from the same
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
