//! § 3 — Keys and addresses.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `private.rs` | 3.1 Private Key — the key as binary/decimal/hex, plus WIF |
//! | `public.rs` | 3.2 Public Key — (x, y), compressed `02`/`03`, uncompressed `04`, x-only |
//! | `address/base58.rs` | 3.2 P2PKH and P2SH, split into prefix, hash, and checksum |
//! | `address/segwit.rs` | 3.2 P2WPKH, P2WSH, P2TR and later versions, split into prefix, version, program and checksum |
//!
//! A private key is rejected if it is zero or at or above the secp256k1 group
//! order; both are outside the valid scalar range and neither is caught by "is
//! it 32 bytes". [`ScalarError`](crate::crypto::secp::ScalarError) keeps them
//! apart, because "your key is zero" and "your key is too large" are different
//! mistakes. Generation is behind the `rand` cargo feature, since a decoder
//! has no reason to link an RNG.
//!
//! ## Compression is a property of the *key*, not of the encoding
//!
//! The same scalar has a 33-byte public key and a 65-byte one, and they hash
//! to different addresses. So both [`PrivateKey`] and [`PublicKey`] carry the
//! flag rather than deciding it at serialization time: a key that forgot it
//! would silently derive the wrong address, which is the one mistake in this
//! module that loses money rather than returning an error. WIF records the
//! same flag, in the trailing `0x01` byte, for the same reason.
//!
//! Segwit does not carry the flag, because it does not have the choice:
//! BIP143 requires a compressed key, and an uncompressed one in a witness is
//! simply invalid. [`PublicKey::p2wpkh_address`] therefore refuses an
//! uncompressed key rather than quietly compressing it — quietly compressing
//! would hand back an address for a key the caller does not think they have.
//!
//! ## The recorded break is paid
//!
//! This section used to record two debts. Both are now discharged.
//!
//! **`Address` became an enum**, with `encoding/bech32.rs`. It was a struct
//! holding a 20-byte hash and a version byte, which is exactly a Base58
//! address and nothing like a witness one; it is now
//! [`Address::Base58`] and [`Address::Segwit`], `version()`/`hash()` live on
//! [`Base58Address`] where they are always true, and the old `AddressKind`
//! split into [`Base58Kind`] — the version-byte table — and [`AddressKind`],
//! which names all five output types and returns `None` for a witness version
//! nobody has defined yet.
//!
//! **`Hash<20>`** replaced the bare `[u8; 20]`: [`AddressHash`] is
//! [`Hash<20>`](crate::hashes::Hash), and every signature that was pinned to
//! an array now names it.

pub mod address;
pub mod private;
pub mod public;

pub use address::{
    Address, AddressError, AddressHash, AddressKind, Base58Address, Base58Kind, Base58Parts,
    SegwitAddress, SegwitParts, WitnessVersion,
};
pub use private::{PrivateKey, PrivateKeyError};
pub use public::{PublicKey, PublicKeyError};
