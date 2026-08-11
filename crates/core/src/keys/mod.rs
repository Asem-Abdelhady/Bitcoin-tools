//! § 3 — Keys and addresses.
//!
//! ## Planned
//!
//! | File | Feature |
//! |---|---|
//! | `private.rs` | 3.1 Private Key — random 256-bit key as binary/decimal/hex, plus WIF |
//! | `public.rs` | 3.2 Public Key — (x, y), compressed `02`/`03`, uncompressed `04`, x-only |
//! | `address.rs` | 3.2 Addresses — P2PKH and P2SH per [`Network`](crate::network), split into prefix, hash, and checksum |
//!
//! A private key must be rejected if it is zero or at or above the secp256k1
//! group order; both are outside the valid scalar range and neither is caught
//! by "is it 32 bytes". Generation is behind a cargo feature, since a decoder
//! has no reason to link an RNG.
