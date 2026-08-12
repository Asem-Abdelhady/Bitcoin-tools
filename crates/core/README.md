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
├── bytes.rs              ✓ Reader, ReadError, varint, pack_bits/unpack_bits
│                           (Writer lands with 5.1)
├── network.rs            ✓ Network, UnknownNetwork
├── general/              ✓ § 1
│   ├── reverse.rs        ✓ 1.1  wire order ⇄ display order
│   ├── number.rs         ✓ 1.2  one value as binary, decimal, hex
│   └── units.rs          ✓ 1.3  Amount, sat/µBTC/mBTC/BTC
├── hashes/               ✓ § 2
│   ├── sha256.rs         ✓ 2.3
│   ├── hash256.rs        ✓ 2.1  double SHA-256
│   ├── hash160.rs        ✓ 2.2  RIPEMD160(SHA256)
│   ├── hash.rs           ✓ Hash<const N> — storage, width, hex, both orders
│   ├── hmac.rs           ✓ HMAC-SHA512, PBKDF2 — for BIP32/39
│   └── tagged.rs         ✓ BIP340 tagged hashes — for taproot
├── encoding/             ✓ shared codecs
│   ├── base58.rs         ✓ Base58, Base58Check
│   └── bech32.rs         ✓ Bech32, Bech32m
├── crypto/                 § 7
│   ├── secp.rs           ✓ the one secp256k1 entry point, and the tweaks
│   └── ecdsa.rs            7.1 sign, 7.2 verify, Signature
├── keys/                 ✓ § 3
│   ├── private.rs        ✓ 3.1  PrivateKey, WIF
│   ├── public.rs         ✓ 3.2  PublicKey: (x,y) / compressed / x-only
│   └── address/          ✓ 3.2
│       ├── mod.rs        ✓      Address (enum), AddressKind, AddressError
│       ├── base58.rs     ✓      P2PKH, P2SH, Base58Parts
│       └── segwit.rs     ✓      P2WPKH, P2WSH, P2TR, SegwitParts
├── hd/                   ✓ § 4
│   ├── mnemonic.rs       ✓ 4.1  BIP39
│   ├── wordlist.rs       ✓ 4.1  the 2048 words
│   ├── xkey.rs           ✓ 4.2  BIP32 Xpriv/Xpub
│   └── path.rs           ✓ 4.2  DerivationPath, BIP44/49/84/86
├── transactions/         ✓ § 5
│   ├── tx.rs             ✓ 5.2  Tx, Txid, TxBreakdown
│   ├── builder.rs          5.1  TxBuilder
│   └── script/           ✓ 5.3  Script, Opcode, Instruction
└── blocks/                 § 6
    ├── header.rs           6.2  BlockHeader; 6.1 BlockHash
    └── merkle.rs           merkle root over Hash<32>
```

`pack_bits`/`unpack_bits` are the fourth thing at L0 for the same reason as the
other three: bech32 carries bytes as five-bit groups and BIP39 carries them as
eleven-bit word indices, and 8, 5 and 11 share no factors, so neither is a
reshape — every length has a remainder, and the remainder is where the bugs
are. Written per format it is the same accumulate-and-emit loop in `encoding`
and in `hd`, three layers apart, with two chances to get the bit order
backwards.

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
| 3.1 | Private Key | **Done** | The key as binary, decimal and hex (via `Number`), plus WIF carrying its network and compression flag. Zero and anything at or above the group order are rejected, as separate errors. Generation is behind the `rand` feature. Verified against the published WIF worked example. |
| 3.2 | Public Key | **Done** | x and y; compressed with its `02`/`03` prefix; uncompressed `04`; x-only; and all five address types per network, each split into its own parts — version/hash/checksum for Base58, prefix/version/program/checksum for Bech32. `Address` is an enum over the two formats. Verified against the generator point, the published key→address worked example, the genesis address, five mainnet public keys whose committed hash the crate reproduces, and BIP173/350's valid and invalid address vectors including every published `scriptPubKey`. |

### 4. HD Wallets

| | Feature | Status | Notes |
|---|---|---|---|
| 4.1 | Mnemonic Seed | **Done** | Entropy ⇄ sentence ⇄ seed, with an optional passphrase and NFKD normalisation. `Mnemonic` stores only the entropy, so the words and the bytes cannot disagree. Generation is behind the `rand` feature. Verified against all 24 English BIP39 vectors, and the wordlist itself against its published SHA-256. |
| 4.2 | Derivation Paths | **Done** | BIP32 `Xpriv`/`Xpub` with both derivation functions, plus BIP44/49/84/86 as what they are — four purpose numbers and four output types over the one algorithm, carried by `Purpose` rather than by four code paths. Verified against BIP32's four seeded vectors (17 derivations, both directions, both key types), its sixteen **invalid** keys, and BIP49/84/86's published addresses. SLIP-132 `ypub`/`zpub` are deliberately not read — see `hd/mod.rs`. |

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
| `rand` | no | `PrivateKey::generate`. Off by default: inspecting a key has no reason to link an RNG, and a tool that only decodes should not be able to mint a secret by accident. |
| `serde` | yes | `Serialize` on the value types a caller renders, plus `Deserialize` on the few that are *inputs* — `Network` and `Base` name a choice a request makes, so they have to be read as well as written. The web server needs this; a CLI turns it off and uses `FromStr`, which every one of those types also has. |

Anything gated must also compile without it:

```
cargo check -p bitcoin-tools-core --no-default-features
```

Planned: nothing further here — `rand` shipped with 3.1.

## Dependencies

Present: `sha2`, `ripemd`, `secp256k1`, `unicode-normalization`, `serde`
(optional), `rand` (optional).

`ripemd` is pinned to the 0.2 line rather than 0.1 so it shares RustCrypto's
`digest` 0.11 with `sha2`; the 0.1 line is built on `digest` 0.10 and would put
two copies of it in the tree.

`unicode-normalization` is BIP39's NFKD, and only that. It is not optional:
without it a passphrase containing composed accents derives a seed no other
wallet agrees with, which is a silently wrong answer rather than a missing
feature. HMAC-SHA512 and PBKDF2 are *not* taken from `hmac` and `pbkdf2` —
they are thirty lines between them, they are pinned to RFC 4231 and the
published PBKDF2 vectors, and two more crates pinned to `sha2`'s exact
`digest` major version buys nothing. See the note on `ripemd` above for what
that pinning costs when it goes wrong.

Planned: nothing further.

Base58 and Bech32 are **not** taken from `bs58` and `bech32`. Feature 3.2 calls
for addresses broken into prefix, hash, and checksum; a crate that hands back a
finished `String` has thrown away exactly the intermediate values this library
exists to show. See `encoding/mod.rs`.

The secp256k1 backend is the `secp256k1` crate — bindings to Bitcoin Core's
libsecp256k1. It pulls a C dependency, so a wasm build would need `crypto/secp.rs`
swapped for a pure-Rust backend. Keeping that surface to one module is the point
of having it.

## Conventions

- **Byte order belongs to the meaning, not the width.** A merkle root and a
  P2WSH commitment are both 32 bytes and only the first is shown reversed, so
  `Hash<N>` cannot decide this: it stores wire order, renders wire order, and
  offers the reversal by name. A type whose convention *is* reversed says so in
  its own one-line `Display` — `Txid` is the example. Write that line when you
  add a hash type, and never let a caller print the wrong order by accident.
- **Hex is one codec.** `hex`. Do not hand-roll another.
- **A named enum is spelled once.** `Network`, `Base`, `Denomination` and
  `Purpose` all name a small closed set, print one spelling, and read back
  several: `as_str`, `Display`, `FromStr` and an `Unknown…` error holding what
  failed, from `name_table!` in `parse.rs`. `AddressKind`, `Base58Kind` and
  `Variant` take the same macro's `spelling` form — `as_str`, `Display` and
  the serde `Serialize` that follows — because nothing parses one from text.
  An address is read from the address, not from someone naming its type. The
  point either way is that the spelling exists **once**, and not a second time
  inside `#[serde(rename_all)]`.
- **Bytes are walked one way.** `bytes::Reader` bounds-checks every read,
  validates counts before allocating, rejects non-canonical varints, and never
  panics. Do not write another cursor.
- **Every public item is documented.** `missing_docs` is on in `lib.rs`, so
  this is checked rather than hoped for.
- **A published vector is the acceptance criterion, and the invalid half
  counts.** BIP32, BIP39, BIP173 and BIP350 each publish inputs that must be
  refused, and those are the vectors that actually test a decoder.
- **A hash type is a newtype over `Hash<N>` plus a `Display`.** `Hash<N>`
  carries the storage, the width check and the hex codec, so a new one is two
  lines rather than seventy.
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

`tests/tx_vectors.rs` is the acceptance criteria for 5.2, `script_vectors.rs`
for 5.3, and `hd_vectors.rs` for all of § 4 — each asserts against the vector
files, never against a restated expectation.

`hd_vectors.rs` is worth reading for the shape: half of what it runs is
BIP32's list of extended keys that must be **rejected**. A decoder that
accepts everything passes every other suite in this repository.

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
