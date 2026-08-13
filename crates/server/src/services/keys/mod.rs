//! § 3 — private keys, public keys and the addresses they derive.
//!
//! ## The two endpoints do not overlap on purpose
//!
//! `/keys/generate` mints a secret and shows it. `/keys/public` takes a secret
//! and shows only what is safe to publish — the public key, the hashes, the
//! addresses — and never echoes the key back. That split is worth keeping: it
//! means exactly one response in this API can contain a private key, and it is
//! the one whose entire purpose is to.

pub mod generate;
pub mod public;

/// Mainnet unless a request says otherwise.
///
/// Not `Default::default()` on `Network`, which the domain deliberately does
/// not define — a network is a decision, and the crate is right to refuse to
/// pick one. Choosing here is a *transport* default for a tool whose users are
/// overwhelmingly looking at mainnet, and it is stated in one place so the two
/// endpoints cannot drift.
pub(crate) const fn default_network() -> bitcoin_tools_core::network::Network {
    bitcoin_tools_core::network::Network::Mainnet
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
