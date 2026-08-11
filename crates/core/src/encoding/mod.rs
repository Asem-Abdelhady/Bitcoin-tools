//! Address and key text encodings.
//!
//! This module exists to be written once. Base58Check appears in WIF private
//! keys (3.1), P2PKH and P2SH addresses (3.2), and BIP32 extended keys (4.2) —
//! three features, one algorithm, differing only in a version prefix. Bech32
//! appears in P2WPKH and P2WSH, and bech32m in P2TR. Written per-feature that
//! is five copies of a checksum loop.
//!
//! ## Planned
//!
//! | File | Feature |
//! |---|---|
//! | `base58.rs` | Base58 and Base58Check, exposing the payload/checksum split |
//! | `bech32.rs` | Bech32 and Bech32m, exposing the HRP/data/checksum split |
//!
//! Both codecs are implemented here rather than pulled from `bs58` and
//! `bech32` because the feature spec calls for addresses "broken into prefix,
//! hash, and checksum". A crate that returns a finished `String` has thrown
//! away exactly the intermediate values this tool exists to show.
