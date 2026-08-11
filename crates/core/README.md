# bitcoin-tools-core

Decode and inspect Bitcoin's data formats: transactions, scripts, keys,
addresses, HD wallets, and blocks.

Pure computation over bytes — no I/O, no network, no framework. A CLI and the
axum server in this workspace both sit on top of it without either shaping it.

```rust
use bitcoin_tools_core::transactions::script::{Script, ScriptKind};

let script = Script::from_hex("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac").unwrap();

assert_eq!(script.kind(), ScriptKind::P2PKH);
assert_eq!(
    script.to_asm(),
    "OP_DUP OP_HASH160 OP_PUSHBYTES_20 65ed366110a6fe3132cc1f63d73d3bb5a658797f OP_EQUALVERIFY OP_CHECKSIG"
);

// Every step keeps the offset it came from — the point of a tools library.
for step in script.disassemble().0 {
    println!("{:>4}  {}", step.offset, step.instruction);
}
```

`cargo run -p bitcoin-tools-core --example disasm <hex>` does the same from a
terminal, with opcode categories and descriptions.

## Layers

Nothing imports upward. That single rule is what stops the same checksum loop
being written five times, and it is checkable with grep.

| | Modules | May depend on |
|---|---|---|
| L0 | `hex`, `bytes`, `network` | nothing |
| L1 | `hashes`, `general` | L0 |
| L2 | `encoding`, `crypto` | L1 |
| L3 | `keys` | L2 |
| L4 | `hd`, `transactions`, `blocks` | L3 |

`hex` and `bytes` sit at the root rather than under `general` because they are
primitives, not features: every consensus structure is a little-endian,
varint-prefixed byte stream, and `bytes::Reader` is the one thing that walks
one. `network` is at the root because four unrelated modules key tables off it
(WIF prefixes, address version bytes, BIP32 versions, Bech32 HRPs); under any
one of them the other three would import sideways.

## Layout

`✓` exists today; everything else is planned. Each feature-group directory
already carries a `mod.rs` documenting the files it will gain and why they are
split that way — read that first when picking up a group.

```
src/
├── lib.rs                ✓
├── parse.rs              ✓ private — `name_table!`, the one definition of
│                           as_str / Display / FromStr / Unknown… for a named enum
├── hex.rs                ✓ encode, decode, normalize, write, {write,encode,decode}_rev, HexError
├── bytes.rs              ✓ Reader, ReadError, varint  (Writer lands with 5.1)
├── network.rs            ✓ Network, UnknownNetwork
├── general/              ✓ § 1
│   ├── reverse.rs        ✓ 1.1  wire order ⇄ display order
│   ├── number.rs         ✓ 1.2  one value as binary, decimal, hex
│   └── units.rs          ✓ 1.3  Amount, sat/µBTC/mBTC/BTC
├── hashes/               ✓ § 2
│   ├── sha256.rs         ✓ 2.3
│   ├── hash256.rs        ✓ 2.1  double SHA-256
│   ├── hash160.rs        ✓ 2.2  RIPEMD160(SHA256)
│   ├── hash.rs             Hash<const N> newtype — lands with the second
│   │                       hash type, and ports Txid onto it
│   └── hmac.rs             HMAC-SHA512, PBKDF2 — for BIP32/39
├── encoding/               shared codecs
│   ├── base58.rs           Base58, Base58Check
│   └── bech32.rs           Bech32, Bech32m
├── crypto/                 § 7
│   ├── secp.rs             the one secp256k1 entry point
│   └── ecdsa.rs            7.1 sign, 7.2 verify, Signature
├── keys/                   § 3
│   ├── private.rs          3.1  PrivateKey, WIF
│   ├── public.rs           3.2  PublicKey: (x,y) / compressed / x-only
│   └── address.rs          3.2  Address, AddressParts
├── hd/                     § 4
│   ├── mnemonic.rs         4.1  BIP39
│   ├── wordlist.rs         4.1  the 2048 words
│   ├── xkey.rs             4.2  BIP32 Xpriv/Xpub
│   └── path.rs             4.2  DerivationPath, BIP44/49/84/86
├── transactions/         ✓ § 5
│   ├── tx.rs             ✓ 5.2  Tx, Txid, TxBreakdown
│   ├── builder.rs          5.1  TxBuilder
│   └── script/           ✓ 5.3  Script, Opcode, Instruction
└── blocks/                 § 6
    ├── header.rs           6.2  BlockHeader; 6.1 BlockHash
    └── merkle.rs           merkle root over Hash<32>
```

Three edges the layering forbids, each of which the obvious signature would
create — written into the module docs so they are decided before the code is:

- `merkle.rs` takes `hashes::Hash<32>` (L1), **not** `transactions::Txid`
  (L4→L4, sideways).
- `crypto::ecdsa` takes curve points from `crypto::secp` (L2), **not**
  `keys::PublicKey` (L2→L3, upward). `keys` wraps `crypto`, never the reverse.
- Reversal is a property of *reading and rendering hex*, not a byte operation
  of its own: it lives at L0 in `hex` as `write_rev`, `encode_rev` and
  `decode_rev`. There is no `bytes::reverse` — use std's `slice::reverse` if
  you hold bytes and want them flipped in place; a crate-level one would only
  make `reverse_hex` allocate a `Vec` it immediately re-encodes.
  `general/reverse.rs` (L1) is the feature-facing wrapper, so `hashes` (L1) is
  not importing sideways to render a hash.

## Status

**Done** — implemented and covered by tests. **Partial** — exists but not yet
exposed as the feature described. **Planned** — not written.

### 1. General

| | Feature | Status | Notes |
|---|---|---|---|
| 1.1 | Reverse Bytes | **Done** | Flip between internal (wire) and display order. Bitcoin shows hashes reversed; this is the operation behind that. `general::reverse_hex` is hex in, hex out; the flip itself is `hex::encode_rev` at L0, where `hashes` can reach it without importing sideways. |
| 1.2 | Number Converter | **Done** | A value in base 2, 10, or 16 → all three. `Number` is arbitrary-precision, held as big-endian bytes: 3.1 wants a 256-bit private key in decimal, so a `u64` converter would have made that feature write its own bignum renderer. Parsing does not go through `hex::decode`, because a number in hex may have an odd digit count — `fff` is 4095. |
| 1.3 | Unit Converter | **Done** | sats, µBTC, mBTC, BTC → all four. Integer satoshis internally, never floating point — converting moves a decimal point, it does not do arithmetic on a quantity. `Output::value` is now the `Amount` this yields. Precision past the unit is an error rather than a rounding, and the 21M cap is a question (`is_money_range`) rather than a constructor precondition, since a malformed transaction can declare any `u64` and the decoder has to show it. |

### 2. Hash Functions

| | Feature | Status | Notes |
|---|---|---|---|
| 2.1 | HASH256 | **Done** | Double SHA-256, in `hashes/hash256.rs`. Verified against the genesis block's coinbase txid. |
| 2.2 | HASH160 | **Done** | RIPEMD-160 of SHA-256, in `hashes/hash160.rs`. Verified against the published worked example — which includes the intermediate SHA-256, so the composition is pinned and not just the answer — and against five mainnet P2SH-P2WPKH inputs, where the redeem script commits to the hash of a pubkey in the same input's witness. Bare RIPEMD-160 is not exposed — not because the protocol lacks `OP_RIPEMD160`, but because it is not a listed feature and both steps of the composition are already reachable. |
| 2.3 | SHA-256 | **Done** | Single round, in `hashes/sha256.rs`. Verified against the FIPS 180-2 vectors, and against three mainnet P2SH-P2WSH inputs whose redeem script commits to a single SHA-256 of a witness script carried in the same transaction. |

### 3. Keys & Addresses

| | Feature | Status | Notes |
|---|---|---|---|
| 3.1 | Private Key | Planned | Random 256-bit key as binary, decimal, and hex, plus WIF. Must reject zero and anything at or above the secp256k1 group order. |
| 3.2 | Public Key | Planned | Derived from a private key: x and y; compressed with its `02`/`03` prefix; uncompressed `04`; x-only; Base58Check address; and P2PKH and P2SH per network, split into prefix, hash, and checksum. |

### 4. HD Wallets

| | Feature | Status | Notes |
|---|---|---|---|
| 4.1 | Mnemonic Seed | Planned | Random seed and sentence, optional passphrase. Given either a seed or a sentence, derive the rest. BIP39 vectors are the acceptance criteria. |
| 4.2 | Derivation Paths | Planned | BIP32, and BIP44/49/84/86 — which are four purpose numbers and four script types over one algorithm, not four algorithms. Given a path and a count, return that many private keys, public keys, and addresses. |

### 5. Transactions

| | Feature | Status | Notes |
|---|---|---|---|
| 5.1 | Transaction Builder | Planned | Type, version, inputs, outputs → raw hex a node accepts. `Tx::encode` is the serialization half already. |
| 5.2 | Transaction Splitter | **Done** | `Tx::decode` + `Tx::breakdown` — every wire field as the hex bytes it occupies. Verified against 22 mainnet vectors. `Output::value` is an `Amount` (1.3), unvalidated: the wire carries a `u64` and a malformed transaction may declare more than will ever exist. |
| 5.3 | Script | **Done** | All 256 opcodes, a lossless instruction decoder, template classification, field extraction. |

### 6. Blocks

| | Feature | Status | Notes |
|---|---|---|---|
| 6.1 | Block Hash | Planned | HASH256 of the 80-byte header, both byte orders. |
| 6.2 | Block Header | Planned | Hex → version, prev block, merkle root, time, bits, nonce. `bits` needs its own type; the raw `u32` is not the number anyone wants. |

### 7. Cryptography

| | Feature | Status | Notes |
|---|---|---|---|
| 7.1 | ECDSA Sign | Planned | Sign a message hash with a private key. |
| 7.2 | ECDSA Verify | Planned | Verify a signature against a public key. |

## Features

| Feature | Default | What it adds |
|---|---|---|
| `serde` | yes | `Serialize` on the value types a caller renders, plus `Deserialize` on the few that are *inputs* — `Network` and `Base` name a choice a request makes, so they have to be read as well as written. The web server needs this; a CLI turns it off and uses `FromStr`, which every one of those types also has. |

Anything gated must also compile without it:

```
cargo check -p bitcoin-tools-core --no-default-features
```

Planned: `rand`, gating private-key and mnemonic *generation*. Decoding has no
reason to link an RNG.

## Dependencies

Present: `sha2`, `ripemd`, `serde` (optional).

`ripemd` is pinned to the 0.2 line rather than 0.1 so it shares RustCrypto's
`digest` 0.11 with `sha2`; the 0.1 line is built on `digest` 0.10 and would put
two copies of it in the tree.

Planned: `secp256k1` (3.x, 7.x), and something for BIP39
PBKDF2 and Unicode NFKD normalization (4.1).

Base58 and Bech32 are **not** taken from `bs58` and `bech32`. Feature 3.2 calls
for addresses broken into prefix, hash, and checksum; a crate that hands back a
finished `String` has thrown away exactly the intermediate values this library
exists to show. See `encoding/mod.rs`.

The secp256k1 backend is the `secp256k1` crate — bindings to Bitcoin Core's
libsecp256k1. It pulls a C dependency, so a wasm build would need `crypto/secp.rs`
swapped for a pure-Rust backend. Keeping that surface to one module is the point
of having it.

## Conventions

- **Byte order is explicit in the type.** `Txid` stores wire order and its
  `Display` reverses, because that is what explorers show. Every new hash type
  does the same. A caller must not be able to print the wrong order by accident.
- **Hex is one codec.** `hex`. Do not hand-roll another.
- **A named enum is spelled once.** `Network`, `Base` and `Denomination` all
  name a small closed set, print one spelling, and read back several. That set
  — `as_str`, `Display`, `FromStr`, and an `Unknown…` error holding what
  failed — comes from `name_table!` in `parse.rs`. `AddressType` (3.2) and the
  BIP44 purpose (4.2) are the next two; neither should hand-write it.
- **Bytes are walked one way.** `bytes::Reader` bounds-checks every read,
  validates counts before allocating, rejects non-canonical varints, and never
  panics. Do not write another cursor.
- **No panics on public paths.** `unwrap`, `expect` and `panic!` are `warn` on
  the library target (see `lib.rs`) and allowed in tests, where a failed
  assertion is the point.
- **Errors carry offsets.** Decoders report *where* they failed, not just that
  they did. For a tools library that is most of the value.
- **Malformed input is data, not a crash.** Where a partial answer is useful,
  return it alongside the error, as `ScriptAnalysis` does. Where the structure
  has stopped making sense — a transaction whose field boundaries no longer
  line up — return an error.
- **Counts are validated before allocation.** A varint claiming `u64::MAX`
  elements is rejected against the remaining buffer, never handed to
  `Vec::with_capacity`.

## Tests

Vectors live in the `bitcoin-tools-vectors` workspace crate, a dev-only member
shared with the server so both assert against identical bytes. Official BIP32
and BIP39 vectors go there as those features land.

`tests/tx_vectors.rs` is the acceptance criteria for 5.2 and `script_vectors.rs`
for 5.3 — both assert against the vector files, never against a restated
expectation.

`Cargo.toml` sets `exclude = ["tests/**"]`, because `bitcoin-tools-vectors` is
a path-only dev-dependency that Cargo strips from the published manifest;
shipping the tests without it would give anyone who vendors this crate a suite
that cannot compile. Neither `cargo package` nor its verify step catches that —
they build lib and examples, not tests. Before a release, confirm the tarball
itself builds:

```
cargo package -p bitcoin-tools-core
cd target/package/bitcoin-tools-core-*/ && cargo test --no-run
```

## Review

Reviewed by the `rust-core-reviewer` agent, which judges this crate as a
standalone published library. It is forbidden from reviewing `crates/server`,
and `rust-api-reviewer` is forbidden from reviewing this crate.
