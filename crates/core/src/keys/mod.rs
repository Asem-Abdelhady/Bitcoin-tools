//! § 3 — Keys and addresses.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `private.rs` | 3.1 Private Key — the key as binary/decimal/hex, plus WIF |
//! | `public.rs` | 3.2 Public Key — (x, y), compressed `02`/`03`, uncompressed `04`, x-only |
//! | `address.rs` | 3.2 Addresses — P2PKH and P2SH per [`Network`](crate::network), split into prefix, hash, and checksum |
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
//! ## One known break is owed before this crate is published
//!
//! Recorded rather than discovered later, and cheap now and expensive after a
//! version number exists.
//!
//! **`Address` becomes an enum.** It is a struct holding a 20-byte hash and
//! a version byte, which is exactly what a Base58 address is and nothing like
//! what a witness address is: a 32-byte P2WSH or P2TR program does not fit,
//! and [`AddressKind::version`] has no answer for a bech32 kind. When
//! `encoding/bech32.rs` lands, this becomes an enum over a Base58 arm and a
//! segwit arm, and `version()`/`hash()` move onto the Base58 arm.
//! [`AddressKind`] and [`AddressParts`] are `#[non_exhaustive]` so the variant
//! and field additions are not themselves breaking.
//!
//! The other debt this section used to carry — `Hash<20>` — is paid:
//! [`AddressHash`] is [`Hash<20>`](crate::hashes::Hash), and the three
//! signatures that were pinned to a bare `[u8; 20]` now name it.
//!
//! ## Only Base58 addresses live here
//!
//! P2PKH and P2SH are Base58Check and are done. The witness types — P2WPKH,
//! P2WSH, P2TR — are Bech32 and land with `encoding/bech32.rs`; their scripts
//! are already classified by [`ScriptKind`](crate::transactions::ScriptKind),
//! so what is missing is the address text, not the understanding.

pub mod address;
pub mod private;
pub mod public;

pub use address::{Address, AddressError, AddressHash, AddressKind, AddressParts};
pub use private::{PrivateKey, PrivateKeyError};
pub use public::{PublicKey, PublicKeyError};
