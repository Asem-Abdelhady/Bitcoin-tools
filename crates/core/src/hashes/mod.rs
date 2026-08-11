//! § 2 — Hash functions.
//!
//! A layer, not a leaf: [`encoding`](crate::encoding) needs HASH256 for its
//! Base58 checksum, [`keys`](crate::keys) needs HASH160 for addresses,
//! [`transactions`](crate::transactions) needs HASH256 for txids,
//! [`blocks`](crate::blocks) needs it for block hashes and merkle roots, and
//! [`hd`](crate::hd) needs HMAC-SHA512 and PBKDF2. It sits directly above
//! [`bytes`](crate::bytes) and below everything else.
//!
//! ## Planned
//!
//! | File | Feature |
//! |---|---|
//! | `hash.rs` | `Hash<const N>` newtype: `Display`, `FromStr`, explicit byte order |
//! | `hmac.rs` | HMAC-SHA512 and PBKDF2, for BIP32 and BIP39 |
//!
//! `Hash<N>` gets its own file rather than landing in `mod.rs`: it is a type
//! with `Display`, `FromStr`, byte-order-naming constructors and a parse
//! error, which is more code than the three functions combined, and `mod.rs`
//! holding wiring and prose is the only thing stopping it becoming a grab bag.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `sha256.rs` | 2.3 SHA-256 |
//! | `hash256.rs` | 2.1 HASH256 — double SHA-256 |
//! | `hash160.rs` | 2.2 HASH160 — RIPEMD-160 of SHA-256 |
//!
//! The three numbered features are complete. Each is one function in one file,
//! because each is one composition and there is nothing else to say about it;
//! what is worth saying — which order the rounds go in, which byte order comes
//! out, which script type uses which — lives on the function.
//!
//! These return `[u8; N]` for now. `Hash<const N>` will wrap them, adding the
//! byte-order-aware `Display` and `FromStr`; the functions stay, because a
//! caller who wants the raw digest should not have to unwrap a newtype.
//!
//! ## Only the compositions Bitcoin names are exposed
//!
//! `sha256` is public because it is a feature in its own right (2.3) and
//! because Bitcoin uses a single round alone in several places — the P2WSH
//! witness-program commitment, BIP143 sighash midstates, BIP340 tagged hashes.
//!
//! Bare RIPEMD-160 is private. Not because the protocol never uses it —
//! `OP_RIPEMD160` is a real opcode, sitting in this crate's own table beside
//! `OP_SHA1` — but because it is not one of the three listed features, and
//! because nothing is hidden by leaving it out: both steps of the composition
//! are already reachable, `sha256(x)` as the intermediate and [`hash160()`] as
//! the result. Publishing it later is additive; un-publishing it would be a
//! break. A script *interpreter* would change the answer, and would want
//! `sha1` too — but 5.3 stops at classification and does not execute.
//!
//! ## `Hash<N>` is what keeps L4 from importing sideways
//!
//! `Txid`, `BlockHash` and a merkle root are the same 32 bytes with different
//! meaning attached, and `Hash160` is 20. One generic newtype at L1 gives all
//! of them `Display` (reversed, Bitcoin's convention), `FromStr` that undoes
//! the reversal, and constructors that name their byte order — so a new hash
//! type cannot forget the flip the way a hand-written `impl` can.
//!
//! It also settles a dependency that would otherwise go sideways: merkle roots
//! live in [`blocks`](crate::blocks) and txids in
//! [`transactions`](crate::transactions), both L4. With `Hash<32>` the merkle
//! code takes hashes and never mentions transactions at all.
//!
//! ### When it lands
//!
//! Not yet, and deliberately: there is exactly one hash newtype in the crate
//! today, and a generic designed from one example is designed from nothing.
//! `blocks` is empty, so the sideways edge above is still hypothetical.
//!
//! It lands with whichever of `blocks::merkle` or `keys::address` is written
//! first — that is the second example — and **the same change ports
//! [`Txid`](crate::transactions::tx::Txid) onto it.** The duplication is
//! already sitting there in concrete form: `Txid` hand-writes a reversing
//! `Display`, a `FromStr` that undoes the reversal, a two-variant parse error
//! and a serde impl, and every one of those is what `Hash<N>` exists to
//! absorb. A *second* hand-written reversed `Display` is the defect to catch —
//! the first one is just a type that arrived early.

// Private, so each function has exactly one public path. A `pub mod` beside
// the re-export would publish `hashes::sha256` twice — once as a module and
// once as a function — which is the trap `transactions/mod.rs` documents, and
// it already cost this module disambiguating `super::sha256()` links. Opening
// one of these later is additive; closing it after publication would not be.
// `hmac.rs` may earn a `pub mod` when it lands, since it brings types.
mod hash160;
mod hash256;
mod sha256;

pub use hash160::hash160;
pub use hash256::hash256;
pub use sha256::sha256;
