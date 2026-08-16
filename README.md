# bitcoin-tools

Decode and inspect Bitcoin's data formats — transactions, scripts, keys,
addresses, HD wallets, and blocks.

Everything is pure computation over bytes. There is no node, no network and no
chain state: you hand it hex and it tells you what the hex means, with the
offsets and intermediate values that a tool exists to show. A P2PKH address
comes back alongside its version byte, its hash and its checksum, not just as a
finished string.

```console
$ bt transactions script 76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac
kind            P2PKH
sizeBytes       25
asm             OP_DUP OP_HASH160 OP_PUSHBYTES_20 65ed36…797f OP_EQUALVERIFY OP_CHECKSIG
disabledOpcode  no
  pubkeyHash    65ed366110a6fe3132cc1f63d73d3bb5a658797f

offset  hex  opcode           category    description
0       76   OP_DUP           stack       Duplicate the top item
1       a9   OP_HASH160       crypto      RIPEMD-160 of the SHA-256 of the top item
…
```

## Which one do you want?

There are three ways to use this, and **you only need one of them**. They do the
same fourteen things and give the same answers.

| | Use this if | Start at |
|---|---|---|
| **Command line** | You want to inspect something now, or script it in a shell | [Step 1a](#1a-the-command-line) |
| **HTTP API** | You want it behind a JSON endpoint, for a web app or another language | [Step 1b](#1b-the-http-api) |
| **Rust library** | You are writing Rust and want the types directly, with no server | [Step 1c](#1c-the-rust-library) |

Everything needs **Rust 1.87 or newer** (edition 2024).

---

### 1a. The command line

Published on crates.io as `bitcoin-tools`; the command it installs is `bt`.

**Step 1 — install it.**

```console
$ cargo install bitcoin-tools
```

**Step 2 — check it works.**

```console
$ bt -V
bt 0.1.0
```

**Step 3 — run something.** Six groups, each with `--help`:

```console
$ bt converter unit --bitcoin 1.5          # units, bases, byte order
$ bt keys public --private-key-file key.hex
$ bt hd derive --seed-file seed.hex --path m/84h/0h/0h/0 --count 5
$ bt blocks header 01000000…1dac2b7c
$ bt transactions splitter <raw-tx-hex>
$ bt crypto sign --private-key-file key.hex --message-hash <32-byte-hex>
```

**Step 4 — add `--json` when a machine is reading.**

```console
$ bt converter unit --bitcoin 1.5 --json | jq .satoshi
"150000000"
```

Every command reads its whole request from a file instead, with
`--input <FILE>`, in the same shape the HTTP API takes — so one file drives
either front end. `-` means stdin.

→ **Every command with a runnable example: [crates/cli/README.md](crates/cli/README.md)**

---

### 1b. The HTTP API

Not published to crates.io — run it from a checkout.

**Step 1 — get the code.**

```console
$ git clone https://github.com/Asem-Abdelhady/Bitcoin-tools
$ cd Bitcoin-tools
```

**Step 2 — start it.**

```console
$ cargo run -p bitcoin-tools-server
```

It binds `0.0.0.0:3000`. There is no configuration, no database and no state —
the process binds a port and answers.

**Step 3 — call it.** Every route is `POST`, takes
`Content-Type: application/json`, and returns JSON including its errors.

```console
$ curl -s localhost:3000/tools/units -H 'content-type: application/json' \
      -d '{"amount":"1.5","denomination":"bitcoin"}'
{"satoshi":"150000000","microbitcoin":"1500000","millibitcoin":"1500",
 "bitcoin":"1.5","isMoneyRange":true}
```

→ **Every endpoint, with request/response shapes and the error table:
[crates/server/README.md](crates/server/README.md)**

---

### 1c. The Rust library

Published as `bitcoin-tools-core`. It is a normal cargo crate and carries no
dependency on axum, clap or any framework.

**Step 1 — add it.**

```console
$ cargo add bitcoin-tools-core
```

**Step 2 — use it.** Every step keeps the offset it came from:

```rust
use bitcoin_tools_core::transactions::script::{Script, ScriptKind};

let script = Script::from_hex("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac")?;
assert_eq!(script.kind(), ScriptKind::P2PKH);

for step in script.disassemble().0 {
    println!("{:>4}  {}", step.offset, step.instruction);
}
// 0  OP_DUP
// 1  OP_HASH160
// 2  OP_PUSHBYTES_20 65ed366110a6fe3132cc1f63d73d3bb5a658797f
// …
```

`serde` is an optional feature, on by default; turn it off with
`default-features = false` and the crate still does everything above.

→ **API docs: [docs.rs/bitcoin-tools-core](https://docs.rs/bitcoin-tools-core)** ·
**the feature set and layering: [crates/core/README.md](crates/core/README.md)**

## What it can do

Fourteen operations in six groups. The same set in all three, and the CLI's
`--json` is the API's response shape — pinned by shared test vectors, not by
intent.

| Group | Operations | Command | Endpoint |
|---|---|---|---|
| General tools | Byte order, number bases, units | `bt converter` | `/tools/*` |
| Keys | Generate a key; every address one produces | `bt keys` | `/keys/*` |
| HD wallets | BIP39 sentences, BIP32 derivation | `bt hd` | `/hd/*` |
| Transactions | Scripts, raw transactions, building one | `bt transactions` | `/transactions/*` |
| Blocks | Header hash, header fields | `bt blocks` | `/blocks/*` |
| Cryptography | ECDSA sign and verify | `bt crypto` | `/crypto/*` |

Their *surfaces* differ where the medium does — `converter base --hex ab12` on
the command line, `{"value": "ab12", "base": "hexadecimal"}` over HTTP. Their
answers do not: `crates/vectors/data/tools.json` holds the argv, the request
body, and the one response both must produce.

**Nothing here signs a transaction for you.** The builder validates and
serializes; signing needs the value and script of every output being spent,
which a raw transaction does not carry.

## What's in this repository

Four crates. As a user you interact with **one** of the first three; the fourth
is test data.

| Crate | What it is | On crates.io |
|---|---|---|
| [`bitcoin-tools-core`](crates/core/) | The domain library — all the actual Bitcoin logic | [crates.io](https://crates.io/crates/bitcoin-tools-core) |
| [`bitcoin-tools`](crates/cli/) | The command line, installed as `bt` | [crates.io](https://crates.io/crates/bitcoin-tools) |
| [`bitcoin-tools-server`](crates/server/) | The axum JSON API | no — run from a checkout |
| [`bitcoin-tools-vectors`](crates/vectors/) | Known-good test vectors, shared by every suite | no — dev-dependency only |

Two rules hold the shape:

- **Core cannot reference either front end.** They are separate crates, so this
  is a build error rather than a convention.
- **The server and the CLI are peers.** Neither is the real interface, the core
  is shaped by neither, and where they answer the same question they must not
  disagree.

Each crate's README covers its own internals — core's module layering, the
server's route/handler/service split, the CLI's argument and output contract.

## Errors

Every failure returns the same envelope, including the 404 and 405 fallbacks:

```json
{"error": "amount-too-precise",
 "message": "sat has 0 decimal places; anything finer is not a whole number of satoshis"}
```

`error` is a stable kebab-case slug to branch on; `message` is for a human and
carries the specifics — the offset, the size actually sent, or which input of a
build request was wrong. Slugs are shared across endpoints, so a client learns
one vocabulary rather than one per route.
**Full table: [crates/server/README.md](crates/server/README.md#errors).**

The CLI says the same things as exit codes: **0** answered, **1** bad input,
**2** a usage mistake, which clap owns. A failure writes nothing to stdout, so
`--json` stays parseable in a pipeline.

## Secrets

Three operations return a secret — `keys generate`, `hd mnemonic`, `hd derive` —
because producing one is their purpose. None hands a secret back merely because
one was given: `keys public` takes a private key and returns only public data.
Secrets are redacted from every `Debug`, and over HTTP they carry
`Cache-Control: no-store`.

Two things to know before trusting either front end with a real key:

- **A generated key is only as private as where it was generated.** Over HTTP it
  is made with the server's RNG and travels back in a response body — exposed to
  that machine, the network hop, and anything logging either. Fine for a local
  inspection tool; a key meant to hold value should be generated on the device
  that will keep it.
- **Keep the seed, not just the words.** `hd derive` takes a seed, and nothing
  here goes from a mnemonic back to one — so the BIP39 habit of writing down the
  sentence and the passphrase will not get you back in.

On the command line a secret is **never an argument**: there is no
`--private-key`, no `--seed` and no `--passphrase`, because arguments are visible
in `ps` and land in shell history. The flag names a *file*, and `-` means stdin.

## Development

```console
$ cargo fmt --all
$ cargo clippy --workspace --all-targets
$ cargo test --workspace                                    # 686 tests
$ cargo check -p bitcoin-tools-core --no-default-features   # `serde` is optional
```

Tests are vectors-first. Core asserts its decoder reproduces each published
vector; the server asserts its HTTP response equals the same one, and the CLI
asserts its `--json` does too — all from the same [crates/vectors/](crates/vectors/)
crate, never from a restated expectation.

The vectors that must be **refused** are included too — half of the HD vectors
are extended keys the decoder has to reject, and 308 of Project Wycheproof's 476
ECDSA cases are refusals. A decoder that accepts everything passes every other
suite in the repository.

Before adding an endpoint, read the building-blocks table in
[.claude/CLAUDE.md](.claude/CLAUDE.md) — a new endpoint should add no new hex
parser, no new error envelope and no fourth copy of "unknown field is 422". That
file is the project's conventions in full, and the contributor-facing half
applies whether or not you are using an agent.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
