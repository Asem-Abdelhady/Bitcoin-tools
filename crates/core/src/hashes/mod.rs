//! § 2 — Hash functions.
//!
//! A layer, not a leaf: [`encoding`](crate::encoding) needs HASH256 for its
//! Base58 checksum, [`keys`](crate::keys) needs HASH160 for addresses,
//! [`transactions`](crate::transactions) needs HASH256 for txids,
//! [`blocks`](crate::blocks) needs it for block hashes and merkle roots, and
//! [`hd`](crate::hd) needs HMAC-SHA512 and PBKDF2. It sits directly above
//! [`bytes`](crate::bytes) and below everything else.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `sha256.rs` | 2.3 SHA-256 |
//! | `hash256.rs` | 2.1 HASH256 — double SHA-256 |
//! | `hash160.rs` | 2.2 HASH160 — RIPEMD-160 of SHA-256 |
//! | `hmac.rs` | HMAC-SHA512 and PBKDF2, for BIP32 and BIP39 |
//! | `tagged.rs` | BIP340 tagged hashes, for taproot |
//! | `hash.rs` | `Hash<const N>` — storage, width, hex, and both byte orders |
//!
//! The three numbered features are complete. Each is one function in one file,
//! because each is one composition and there is nothing else to say about it;
//! what is worth saying — which order the rounds go in, which byte order comes
//! out, which script type uses which — lives on the function.
//!
//! The three functions return `[u8; N]` rather than [`struct@Hash`], and stay that
//! way: a caller who wants the raw digest — a Base58 checksum takes the first
//! four bytes of one — should not have to unwrap a newtype to get it.
//! [`struct@Hash`] is what a *semantic* hash type is built from.
//!
//! `hmac.rs` and `tagged.rs` are the two that are not features in their own
//! right. They are here because they are *hashes used by something above*:
//! BIP32 defines every derivation step as an HMAC-SHA512 and BIP39 a seed as
//! PBKDF2 over one, while taproot's tweak is a BIP340 tagged hash. Putting
//! them at L1 is what stops [`hd`](crate::hd) at L4 from growing its own
//! copies, and stops the taproot tweak from having to reach sideways.
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
//! meaning attached, and a pubkey hash is 20. One generic newtype at L1 gives
//! all of them the storage, the width check, the hex codec and the equality,
//! so a new hash type is a newtype plus a `Display` rather than seventy lines
//! that can each be got subtly wrong.
//!
//! ### It does *not* give them a byte order
//!
//! The plan here used to say `Hash<N>` would supply a reversed `Display`,
//! "Bitcoin's convention". Writing it disproved it: a merkle root and a P2WSH
//! script commitment are both thirty-two bytes and only the first is shown
//! reversed, so width does not predict order. Order is a property of the
//! meaning, not of the size.
//!
//! So [`struct@Hash`] stores wire order, offers both renderings by name, and makes
//! `Display` the forward one. A type that reverses says so in its own
//! `Display` — which is exactly one line in
//! [`Txid`](crate::transactions::tx::Txid), and that line is the whole
//! declaration of its convention rather than a behaviour inherited silently.
//!
//! It also settles a dependency that would otherwise go sideways: merkle roots
//! live in [`blocks`](crate::blocks) and txids in
//! [`transactions`](crate::transactions), both L4. With `Hash<32>` the merkle
//! code takes hashes and never mentions transactions at all.
//!
//! ### It landed with the second example, as planned
//!
//! The trigger written here was "with whichever of `blocks::merkle` or
//! `keys::address` comes first". `keys::address` came first, and the same
//! change ported [`Txid`](crate::transactions::tx::Txid) onto it — deleting a
//! hand-written parse error, a hand-written `FromStr`, and the width check,
//! and leaving the one `Display` line that is genuinely about transactions.
//! `keys` now names its twenty bytes
//! [`AddressHash`](crate::keys::AddressHash) rather than `[u8; 20]`.

// Private, so each function has exactly one public path. A `pub mod` beside
// the re-export would publish `hashes::sha256` twice — once as a module and
// once as a function — which is the trap `transactions/mod.rs` documents, and
// it already cost this module disambiguating `super::sha256()` links. Opening
// one of these later is additive; closing it after publication would not be.
// `hmac.rs` was flagged here as a candidate for `pub mod` "since it brings
// types". It landed carrying two functions and a size constant and no types at
// all, so it stayed private like the rest.
// `hash` is `pub mod` where the digest files are not: it carries a type
// with its own methods and error, not one function.
pub mod hash;
mod hash160;
mod hash256;
mod hmac;
mod sha256;
mod tagged;

pub use hash::{Hash, HashParseError};
pub use hash160::hash160;
pub use hash256::hash256;
pub use hmac::{SHA512_SIZE, hmac_sha512, pbkdf2_hmac_sha512};
pub use sha256::sha256;
pub use tagged::tagged_sha256;
