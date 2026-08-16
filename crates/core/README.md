# bitcoin-tools-core

Decode and inspect Bitcoin's data formats: transactions, scripts, keys,
addresses, HD wallets, and blocks.

Pure computation over bytes — no I/O, no network, no framework. A CLI and the
axum server in this workspace both sit on top of it without either shaping it.

What separates this from a wallet library is that it hands back the
*intermediate* values. An address is not an opaque string but a version byte, a
hash and a checksum; a script is not "P2PKH" but every instruction with the
offset it sits at; a transaction is not a struct but the exact hex each field
occupies.

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
//    0  OP_DUP
//    1  OP_HASH160
//    2  OP_PUSHBYTES_20 65ed366110a6fe3132cc1f63d73d3bb5a658797f
//   23  OP_EQUALVERIFY
//   24  OP_CHECKSIG
```

`cargo run -p bitcoin-tools-core --example disasm <hex>` does the same from a
terminal, with opcode categories and descriptions.

Requires Rust 1.87 (edition 2024, and `u64::is_multiple_of`).

## What is in it

| Area | What you get |
|---|---|
| **Transactions** | Decode to typed fields or to a byte-by-byte `TxBreakdown`; txid; `base_size`/`total_size`/`weight`/`vsize`; and `TxBuilder`, which assembles and validates but does not sign. |
| **Scripts** | All 256 opcodes with categories and descriptions, a lossless instruction decoder that reports where it broke, template classification, and field extraction. |
| **Keys** | `PrivateKey` with WIF and a decimal/binary/hex view; `PublicKey` as (x, y), compressed, uncompressed and x-only. |
| **Addresses** | P2PKH, P2SH, P2WPKH, P2WSH and P2TR, each parsed and each split into its parts — version/hash/checksum for Base58, prefix/version/program/checksum for Bech32 — plus the `scriptPubKey` each pays to. |
| **HD wallets** | BIP39 entropy ⇄ sentence ⇄ seed with an optional passphrase; BIP32 `Xpriv`/`Xpub` with both derivation functions; BIP44/49/84/86 as four purpose numbers over one algorithm. |
| **Blocks** | The eighty header bytes as fields; block hash; `CompactTarget` → `Target`, difficulty, and `meets_target`; merkle roots, with and without the CVE-2012-2459 check. |
| **Crypto** | ECDSA sign (RFC 6979 deterministic, always low-`s`) and verify; `Signature` reading strict DER (BIP66) and the 64-byte compact form. |
| **Encodings** | Base58 and Base58Check, Bech32 and Bech32m — each exposing the parts, not just the string. |
| **Hashes** | SHA-256, HASH256, HASH160, HMAC-SHA512, PBKDF2, BIP340 tagged hashes, and `Hash<N>` underneath them. |
| **Conversions** | Byte reversal (wire ⇄ display order), an arbitrary-precision number in base 2/10/16, and `Amount` in sat/µBTC/mBTC/BTC held as integer satoshis. |

Everything above is implemented and covered by tests.

## Examples

Each of these is checked output. Two long hex literals are elided as `RAW_TX`
and `HEADER` — both are the genesis block's.

**A transaction, both ways.** `Tx` is the structure; `TxBreakdown` is the byte
layout — every wire field as the literal hex it occupies, in serialization
order.

```rust
use bitcoin_tools_core::transactions::Tx;

let tx = Tx::from_hex(RAW_TX).unwrap();

assert_eq!(tx.txid().to_string(), "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");
assert_eq!(tx.vsize(), 204);
assert!(tx.is_coinbase());

let breakdown = tx.breakdown();
assert_eq!(breakdown.version, "01000000");
assert_eq!(breakdown.inputs[0].sequence, "ffffffff");
```

**A key and everything it pays to.**

```rust
use bitcoin_tools_core::keys::PrivateKey;
use bitcoin_tools_core::network::Network;

let hex = "0000000000000000000000000000000000000000000000000000000000000001";
let key = PrivateKey::from_hex(hex, Network::Mainnet, true).unwrap();
assert_eq!(key.to_wif(), "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn");

let public = key.public_key();
assert_eq!(
    public.p2pkh_address(Network::Mainnet).to_string(),
    "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"
);
assert_eq!(
    public.p2wpkh_address(Network::Mainnet).unwrap().to_string(),
    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
);
assert_eq!(
    public.p2tr_address(Network::Mainnet).unwrap().to_string(),
    "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9"
);
```

**An address taken apart**, which is the reason the address types exist:

```rust
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::address::Address;

let address: Address = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH".parse().unwrap();
let parts = address.as_base58().unwrap().parts();

assert_eq!(parts.version, 0x00);
assert_eq!(parts.hash.to_string(), "751e76e8199196d454941c45d1b3a323f1433bd6");
assert_eq!(hex::encode(&parts.checksum), "510d1634");
assert_eq!(
    hex::encode(&address.script_pubkey()),
    "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"
);
```

**A wallet branch**, mnemonic to address:

```rust
use bitcoin_tools_core::hd::{DerivationPath, Mnemonic, Xpriv};
use bitcoin_tools_core::network::Network;

let mnemonic = Mnemonic::from_entropy(&[0x0f; 16]).unwrap();
let seed = mnemonic.to_seed("");                   // "" or a BIP39 passphrase

let master = Xpriv::new_master(&seed, Network::Mainnet).unwrap();
let path: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
let child = master.derive_path(&path).unwrap();

let public = child.private_key().public_key();
assert_eq!(
    public.p2wpkh_address(Network::Mainnet).unwrap().to_string(),
    "bc1q5c9ey3p2n6d3nw5u2j4zkjynxg2q83nlgmylev"
);
```

**A block header**, including the check that closes the loop — the header's own
hash against the target its `bits` expand to:

```rust
use bitcoin_tools_core::blocks::BlockHeader;

let header = BlockHeader::from_hex(HEADER).unwrap();

assert_eq!(
    header.block_hash().to_string(),
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
);
assert_eq!(
    header.merkle_root.to_string(),
    "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
);
assert_eq!(header.bits.difficulty(), 1.0);
assert!(header.meets_target());
```

**Amounts and numbers**, both exact by construction:

```rust
use bitcoin_tools_core::general::{Amount, Base, Denomination, Number};

let amount = Amount::parse("1.5", Denomination::Bitcoin).unwrap();
assert_eq!(amount.to_sat(), 150_000_000);
assert_eq!(amount.to_string_in(Denomination::MilliBitcoin), "1500");

let n = Number::parse("255", Base::Decimal).unwrap();
assert_eq!(n.to_binary(), "11111111");
assert_eq!(n.to_hex(), "ff");
```

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

## Layout

Each feature-group directory carries a `mod.rs` documenting the files it holds
and why they are split that way — read that first when picking up a group.

```
src/
├── lib.rs
├── parse.rs              private — `name_table!`, the one definition of
│                           as_str / Display / FromStr / Unknown… for a named enum
├── hex.rs                encode, decode, normalize, write, {write,encode,decode}_rev, HexError
├── bytes.rs              Reader, ReadError, varint, pack_bits/unpack_bits
│                           (no Writer — see the note on write_varint)
├── network.rs            Network, UnknownNetwork
├── general/
│   ├── reverse.rs        wire order ⇄ display order
│   ├── number.rs         one value as binary, decimal, hex
│   └── units.rs          Amount, sat/µBTC/mBTC/BTC
├── hashes/
│   ├── sha256.rs
│   ├── hash256.rs        double SHA-256
│   ├── hash160.rs        RIPEMD160(SHA256)
│   ├── hash.rs           Hash<const N> — storage, width, hex, both orders,
│   │                       and reversed_hash! for the types that display flipped
│   ├── hmac.rs           HMAC-SHA512, PBKDF2 — for BIP32/39
│   └── tagged.rs         BIP340 tagged hashes — for taproot
├── encoding/
│   ├── base58.rs         Base58, Base58Check
│   └── bech32.rs         Bech32, Bech32m
├── crypto/
│   ├── secp.rs           the one secp256k1 entry point, and the tweaks
│   └── ecdsa.rs          sign, verify, Signature (DER and compact)
├── keys/
│   ├── private.rs        PrivateKey, WIF
│   ├── public.rs         PublicKey: (x,y) / compressed / x-only
│   └── address/
│       ├── mod.rs        Address (enum), AddressKind, AddressError
│       ├── base58.rs     P2PKH, P2SH, Base58Parts
│       └── segwit.rs     P2WPKH, P2WSH, P2TR, SegwitParts
├── hd/
│   ├── mnemonic.rs       BIP39
│   ├── wordlist.rs       the 2048 words
│   ├── xkey.rs           BIP32 Xpriv/Xpub
│   └── path.rs           DerivationPath, BIP44/49/84/86
├── transactions/
│   ├── tx.rs             Tx, Txid, TxBreakdown
│   ├── builder.rs        TxBuilder, TxKind, BuildError
│   └── script/           Script, Opcode, Instruction
└── blocks/
    ├── header.rs         BlockHeader, HeaderBreakdown, BlockHash
    ├── target.rs         CompactTarget, Target, difficulty
    └── merkle.rs         MerkleRoot over Hash<32>, and CVE-2012-2459
```

## Notes on the harder corners

**The builder validates; it does not sign.** A signature commits to a sighash,
and a sighash needs the value and script of every output being spent, which a
raw transaction does not carry. `TxBuilder` is also not a second encoder —
`Tx::encode` already serializes, so the builder assembles a `Tx` and returns it.
What it *does* is refuse the combinations that serialize cleanly and are still
rejected by every node: no inputs, no outputs, a duplicated outpoint, the null
(coinbase) outpoint, a value or total above 21 million, both halves of BIP144's
witness rule, and `bad-txns-oversize` — measured on the **witness-stripped**
size times four, so the ceiling is 1,000,000 base bytes rather than 4,000,000
total. Each check cites the Core rule it mirrors.

**`Signature` re-checks both scalars after parsing**, which is not
belt-and-braces: libsecp256k1's DER integer parser answers *success* for an
integer at or above the group order and substitutes **zero** for it, so a
signature parsed straight from the backend can carry an `r` the input never
contained.

**Verification answers the arithmetic question** and so normalises `s` first;
`Signature::is_low_s` answers Bitcoin's separate malleability policy. The two
are different questions and are kept apart.

**`Amount` does not enforce the 21-million cap.** It cannot: a malformed
transaction can declare any `u64` as an output value, and a tool that refused to
*represent* such a value could not show you the transaction containing it. The
cap is a question — `is_money_range` — rather than a constructor precondition.
Precision finer than the unit is an error rather than a rounding.

**`Number` is arbitrary-precision** because the numbers Bitcoin asks people to
read in more than one base are 256-bit: a private key in decimal, the group
order it must fall below, a difficulty target. A `u64` converter would have
forced `keys` to write its own decimal renderer. Parsing does not go through
`hex::decode`, because a number in hex may have an odd digit count — `fff` is
4095.

**`merkle::root` comes in two forms.** `root` is the consensus computation;
`root_checked` refuses a leaf list containing two identical siblings. That is
CVE-2012-2459: duplicating the last hash of an odd row means `[a, b, c]` and
`[a, b, c, c]` have the same root, so a root does not identify its list.
Validating a header needs the first; deriving a root from leaves you were handed
needs the second.

### Deliberately absent

- **No `Block` type, and no consensus validation beyond `meets_target`.**
  Retargeting, median-time-past and chain selection all need headers a single
  header does not carry, and a full block would mean `blocks` importing
  `transactions` sideways at L4.
- **No SLIP-132 `ypub`/`zpub`.** They encode an intended script type in a
  prefix that BIP32 gives no meaning to — see `hd/mod.rs`.
- **No low-`r` grinding and no lax DER** for pre-BIP66 scripts. The first is a
  wallet's fee optimisation and is not predicted by the RFC 6979 vectors; both
  are additive if wanted.
- **No bare RIPEMD-160.** Not because the protocol lacks `OP_RIPEMD160`, but
  because both steps of the composition are already reachable.

## Features

| Feature | Default | What it adds |
|---|---|---|
| `serde` | **on** | `Serialize` on the value types a caller renders, plus `Deserialize` on the five that are *inputs* — `Network`, `Base`, `Denomination`, `Purpose` and `TxKind` each name a choice a request makes, so they have to be read as well as written; each also has `FromStr`, which is how a consumer reads them with this feature off. Turn it off if you only format text. Keep it if you emit JSON, and especially if two front ends of yours have to agree on it: `Category`, `ScriptFields`, `DecodeError` and the field names of `BlockHeader`, `Tx`, `Input`, `Output` and `OutPoint` have no spelling outside their serde attributes — `Category` has no `Display` at all — so a hand-written copy is one release from disagreeing. Most types with a `Display` serialize as exactly that string, so those two renderings cannot drift. The exceptions are `Amount` and `WitnessVersion`, which are `serde(transparent)` over the integer they wrap — `Amount`'s `Display` says `1500 sat` where its JSON says `1500`. |
| `rand` | off | `PrivateKey::generate` and `Mnemonic::generate`. Off by default: inspecting a key has no reason to link an RNG, and a tool that only decodes should not be able to mint a secret by accident. |

Anything gated must also compile without it:

```console
$ cargo check -p bitcoin-tools-core --no-default-features
```

## Dependencies

`sha2`, `ripemd`, `secp256k1`, `unicode-normalization`, plus optional `serde`
and `rand`. Nothing further is planned.

`ripemd` is pinned to the 0.2 line rather than 0.1 so it shares RustCrypto's
`digest` 0.11 with `sha2`; the 0.1 line is built on `digest` 0.10 and would put
two copies of it in the tree.

`unicode-normalization` is BIP39's NFKD, and only that. It is not optional:
without it a passphrase containing composed accents derives a seed no other
wallet agrees with, which is a silently wrong answer rather than a missing
feature.

The secp256k1 backend is the `secp256k1` crate — bindings to Bitcoin Core's
libsecp256k1, which is constant-time and is what actually validates the chain.
It pulls a C dependency, so a wasm build would need `crypto/secp.rs` swapped for
a pure-Rust backend. Keeping that surface to one module is the point of having
it.

**What is deliberately not a dependency:**

- **`bs58` and `bech32`.** This crate exists to show addresses broken into
  prefix, hash and checksum; a crate that hands back a finished `String` has
  thrown away exactly the intermediate values that are the product. See
  `encoding/mod.rs`.
- **`hmac` and `pbkdf2`.** They are thirty lines between them, they are pinned
  to RFC 4231 and the published PBKDF2 vectors, and two more crates pinned to
  `sha2`'s exact `digest` major version buys nothing. See the `ripemd` note
  above for what that pinning costs when it goes wrong.

## Conventions

- **Byte order belongs to the meaning, not the width.** A merkle root and a
  P2WSH commitment are both 32 bytes and only the first is shown reversed, so
  `Hash<N>` cannot decide this: it stores wire order, renders wire order, and
  offers the reversal by name. A type whose convention *is* reversed declares
  it, and since three types declare the same one — `Txid`, `BlockHash`,
  `MerkleRoot` — the declaration is a `reversed_hash!` call in `hashes/hash.rs`
  rather than six impls copied per type. Use it when you add a hash Bitcoin
  displays flipped; write the impls yourself when it does not, and never let a
  caller print the wrong order by accident.
- **Hex is one codec.** `hex`. Do not hand-roll another.
- **A named enum is spelled once.** `Network`, `Base`, `Denomination` and
  `Purpose` all name a small closed set, print one spelling, and read back
  several: `as_str`, `Display`, `FromStr` and an `Unknown…` error holding what
  failed, from `name_table!` in `parse.rs`. `AddressKind`, `Base58Kind` and
  `Variant` take the same macro's `spelling` form — `as_str`, `Display` and the
  serde `Serialize` that follows — because nothing parses one from text. An
  address is read from the address, not from someone naming its type. The point
  either way is that the spelling exists **once**, and not a second time inside
  a `#[serde(rename_all)]`.
- **Bytes are walked one way.** `bytes::Reader` bounds-checks every read,
  validates counts before allocating, rejects non-canonical varints, and never
  panics. Do not write another cursor.
- **Every public item is documented.** `missing_docs` is on in `lib.rs`, so this
  is checked rather than hoped for.
- **No panics on public paths.** `unwrap`, `expect` and `panic!` are `warn` on
  the library target (see `lib.rs`) and allowed in tests, where a failed
  assertion is the point.
- **Errors carry offsets.** Decoders report *where* they failed, not just that
  they did. For a tools library that is most of the value.
- **Malformed input is data, not a crash.** Where a partial answer is useful,
  return it alongside the error, as `ScriptAnalysis` does. Where the structure
  has stopped making sense — a transaction whose field boundaries no longer line
  up — return an error.
- **Counts are validated before allocation.** A varint claiming `u64::MAX`
  elements is rejected against the remaining buffer, never handed to
  `Vec::with_capacity`.
- **A hash type is a newtype over `Hash<N>`.** `Hash<N>` carries the storage,
  the width check and the hex codec; the byte-order note above says where the
  `Display` comes from.

## Tests

Vectors live in the `bitcoin-tools-vectors` workspace crate, a dev-only member
shared with the server so both assert against identical bytes. Each suite
asserts against those files, never against a restated expectation.

**A published vector is the acceptance criterion, and the invalid half counts.**
BIP32, BIP39, BIP173 and BIP350 each publish inputs that must be *refused*, and
those are the vectors that actually test a decoder. `hd_vectors.rs` is worth
reading for the shape: half of what it runs is BIP32's list of extended keys
that must be rejected. A decoder that accepts everything passes every other
suite in this repository.

| Suite | What it pins |
|---|---|
| `tx_vectors.rs` | 22 mainnet transactions, decoded field by field — then fed back through `TxBuilder` and compared byte for byte, which is why the builder needs no vectors of its own. A builder that dropped a sequence number would still produce a decodable transaction; it would not produce *that* one. |
| `script_vectors.rs` | Classification and disassembly against the same transactions. |
| `hd_vectors.rs` | BIP32's four seeded vectors (17 derivations, both directions, both key types) and its sixteen invalid keys; all 24 English BIP39 vectors; the wordlist against its published SHA-256; BIP49/84/86's published addresses. |
| `block_vectors.rs` | Ten mainnet headers whose `bits` exponents cover `0x17`–`0x1d` without a gap, eight of them carrying their full transaction list so the merkle root is recomputed rather than believed; plus Core's `arith_uint256` cases for the negative, overflow and sub-3-exponent corners no real header reaches. |
| `crypto_vectors.rs` | Seven published signing vectors byte for byte, and Project Wycheproof's ECDSA suite — 476 cases, 308 of which must be refused. Vendored unchanged (copyright Google LLC and contributors, Apache-2.0). |
| `key_vectors.rs`, `hash_vectors.rs` | That the primitives agree with the hashes Bitcoin Core actually computed, in the compositions this crate claims they are used in — mainnet public keys and scripts whose committed hash the crate reproduces. The published worked examples, intermediates included so the composition is pinned and not just the answer, are unit tests inside `hashes/`. |

Where a BIP publishes vectors they are transcribed unchanged. Where it does not
— the chain itself is the vector for blocks — the data is real mainnet data, and
it is chosen rather than sampled.

## Packaging

`Cargo.toml` sets `exclude = ["tests/**"]`, because `bitcoin-tools-vectors` is a
path-only dev-dependency that Cargo strips from the published manifest; shipping
the tests without it would give anyone who vendors this crate a suite that
cannot compile. Neither `cargo package` nor its verify step catches that — they
build lib and examples, not tests. Before a release, confirm the tarball itself
builds:

```console
$ cargo package -p bitcoin-tools-core
$ cd target/package/bitcoin-tools-core-*/ && cargo test --no-run
```

## Review

Reviewed by the `rust-core-reviewer` agent, which judges this crate as a
standalone published library. It is forbidden from reviewing `crates/server`,
and `rust-api-reviewer` is forbidden from reviewing this crate. That exclusion
is what keeps the two reviews independent — do not override either.

## License

MIT. See [LICENSE-MIT](LICENSE-MIT).
