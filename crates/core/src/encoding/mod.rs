//! Address and key text encodings.
//!
//! This module exists to be written once. Base58Check appears in WIF private
//! keys (3.1), P2PKH and P2SH addresses (3.2), and BIP32 extended keys (4.2) —
//! three features, one algorithm, differing only in a version prefix. Bech32
//! appears in P2WPKH and P2WSH, and bech32m in P2TR. Written per-feature that
//! is five copies of a checksum loop.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `base58.rs` | Base58 and Base58Check, exposing the payload/checksum split |
//! | `bech32.rs` | Bech32 and Bech32m, exposing the HRP/data/checksum split |
//!
//! ## Neither codec knows what it is encoding
//!
//! `base58.rs` takes a payload and prepends nothing; `bech32.rs` takes a
//! prefix and five-bit groups. Which version byte an address uses, which
//! prefix a network has, and whether a witness version and a bech32 variant
//! agree are all [`keys::address`](crate::keys::address)' business one layer
//! up. That is what lets one Base58Check serve WIF keys, two address kinds
//! and BIP32 extended keys, and one bech32 serve three witness types.
//!
//! ## The base conversion is not written here
//!
//! Base 58 is a base, and [`Number`](crate::general::Number) already holds the
//! multiply-accumulate and repeated-division loops that convert one — verified
//! against an external oracle. `base58.rs` supplies the alphabet and the one
//! rule that is not arithmetic (a leading zero *byte* is not a leading zero
//! *digit*), and borrows the rest. A third hand-written bignum loop would have
//! been the thing to avoid.
//!
//! Both codecs are implemented here rather than pulled from `bs58` and
//! `bech32` because the feature spec calls for addresses "broken into prefix,
//! hash, and checksum". A crate that returns a finished `String` has thrown
//! away exactly the intermediate values this tool exists to show.

pub mod base58;
pub mod bech32;

pub use base58::{Base58Error, Parts};
pub use bech32::{Bech32Error, Decoded, Variant};
