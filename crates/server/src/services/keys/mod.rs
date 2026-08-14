//! private keys, public keys and the addresses they derive.
//!
//! ## The two endpoints do not overlap on purpose
//!
//! `/keys/generate` mints a secret and shows it. `/keys/public` takes a secret
//! and shows only what is safe to publish — the public key, the hashes, the
//! addresses — and never echoes the key back.
//!
//! The rule that split enforces is *an endpoint returns a secret only if
//! producing one is its purpose*. `/keys/generate` qualifies, and so do both
//! `/hd` endpoints — a seed and a derived WIF are what those are for. What the
//! rule forbids is an endpoint handing a secret back merely because it was
//! given one, which is what `/keys/public` would be doing if it echoed the key
//! it derives from. Every endpoint that does return one sets `no-store`.

pub mod generate;
pub mod public;

use crate::services::error::ServiceError;
use crate::services::input::hex_bytes_exact;
use bitcoin_tools_core::crypto::secp::SCALAR_SIZE;
use bitcoin_tools_core::keys::{PrivateKey, PrivateKeyError};
use bitcoin_tools_core::network::Network;

/// The one definition of "read a private key from a request".
///
/// Shared by `/keys/public` and `/crypto/sign`, which have nothing else in
/// common but must agree on what 32 bytes have to satisfy — a value can be
/// exactly the right size and still be no key at all, and only one of the two
/// callers would remember that if each parsed its own.
///
/// # Errors
///
/// Anything other than 32 bytes, in either direction, and 32 bytes that are
/// not a scalar: zero, or at or above the group order.
pub(crate) fn private_key(
    hex: &str,
    network: Network,
    compressed: bool,
) -> Result<PrivateKey, ServiceError<PrivateKeyError>> {
    let bytes: [u8; SCALAR_SIZE] = hex_bytes_exact(hex, "private key", |got| {
        PrivateKeyError::WrongLength { got }
    })?;
    PrivateKey::from_be_bytes(&bytes, network, compressed).map_err(ServiceError::Domain)
}

/// Compressed unless a request says otherwise.
///
/// Everything since 2012 uses compressed keys. Uncompressed is still legal and
/// still reachable by asking, because keys from before then exist and hash to
/// different addresses — a tool that could not express one would be unable to
/// explain an old wallet.
pub(crate) const fn default_compressed() -> bool {
    true
}
