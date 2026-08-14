//! § 3 — private keys, public keys and the addresses they derive.
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

/// Compressed unless a request says otherwise.
///
/// Everything since 2012 uses compressed keys. Uncompressed is still legal and
/// still reachable by asking, because keys from before then exist and hash to
/// different addresses — a tool that could not express one would be unable to
/// explain an old wallet.
pub(crate) const fn default_compressed() -> bool {
    true
}
