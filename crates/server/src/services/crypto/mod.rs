//! § 7 — ECDSA signing and verification.
//!
//! ## Both endpoints take a *hash*, not a message
//!
//! ECDSA signs 32 bytes, and in Bitcoin those 32 bytes are a sighash: the
//! result of serializing a transaction a particular way and hashing it twice.
//! Which way is a property of the input being spent, not of the signature, so
//! an endpoint that took a message and hashed it would be picking a scheme on
//! the caller's behalf and quietly producing signatures for the wrong one.
//!
//! The cost is that signing arbitrary text takes two steps, and this API does
//! not yet expose the first — see `CLAUDE.md`'s open decisions.

pub mod sign;
pub mod verify;

use serde::Serialize;

use crate::services::error::ServiceError;
use crate::services::input::{InputError, hex_bytes, hex_bytes_exact};
use bitcoin_tools_core::crypto::ecdsa::{
    COMPACT_SIZE, MAX_DER_SIZE, MESSAGE_SIZE, Signature, SignatureError,
};

/// Which of the two encodings a signature was read as.
///
/// Reported back rather than inferred silently, because the two are told apart
/// by length and that rule should be visible in the answer — see
/// [`signature`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureEncoding {
    /// Strict DER, as BIP66 requires and as a `scriptSig` carries.
    Der,
    /// Sixty-four bytes: `r` then `s`, big-endian, no framing.
    Compact,
}

/// Read a 32-byte message hash.
///
/// `wrong_width` is the caller's own error, so `/crypto/sign` and
/// `/crypto/verify` each report the field in their own vocabulary while
/// sharing the rule.
///
/// # Errors
///
/// Anything other than 32 bytes, in either direction.
pub(crate) fn message_hash<E>(
    hex: &str,
    wrong_width: impl FnOnce(usize) -> E,
) -> Result<[u8; MESSAGE_SIZE], ServiceError<E>> {
    hex_bytes_exact(hex, "message hash", wrong_width)
}

/// Read a signature in whichever encoding it was written in.
///
/// # How the two are told apart
///
/// By length, and only by length: exactly 64 bytes is compact, anything else
/// is DER. The domain deliberately does not guess — [`Signature::from_hex`] is
/// DER-only and says so — but an endpoint that refused compact input would be
/// unable to read the form every RFC 6979 vector is published in, and one that
/// demanded an `encoding` field would ask the caller to state what the bytes
/// already say.
///
/// A 64-byte *DER* signature is possible in principle and would be read as
/// compact here. It needs `r` and `s` both around 29 bytes — each about a
/// 2⁻²⁴ event, so together roughly 2⁻⁴⁵ — and the response reports which
/// encoding was used, so a caller who hits it can see what happened rather
/// than being told a valid signature is invalid.
///
/// The obvious alternative — try DER first, fall back to compact — is *worse*,
/// which is worth stating because it is what a reader will propose. It
/// misreads a **compact** signature whose 64 bytes happen to parse as strict
/// DER, and that needs only a leading `30 3e 02 …` with a consistent inner
/// layout: around 2⁻³², a dozen-odd bits more likely than the case this rule
/// has. Preferring compact at exactly 64 bytes is the safer rule, not merely
/// the more convenient one.
///
/// # Length is checked before decoding
///
/// [`MAX_DER_SIZE`] is a hard ceiling — no signature in either encoding is
/// longer — so anything past it is refused on the hex length alone, without
/// allocating for it. Wycheproof publishes DER signatures of about four
/// kilobytes to test length-overflow handling, and those must reach an answer
/// about the *signature* rather than being turned away by a body limit; this
/// is what lets the route cap sit high enough for that.
///
/// The refusal is [`SignatureError::Der`] rather than an input error: past 72
/// bytes the bytes are not a signature in either encoding, which is a fact
/// about them and not a policy of this endpoint.
///
/// # Errors
///
/// [`SignatureError`] for bad hex, for bytes that are not strict DER, or for
/// an `r` or `s` that is not a scalar — which the backend would otherwise
/// accept as a zero.
pub(crate) fn signature(
    hex: &str,
) -> Result<(Signature, SignatureEncoding), ServiceError<SignatureError>> {
    let bytes = hex_bytes(hex, "signature", MAX_DER_SIZE).map_err(|e| match e {
        InputError::TooLarge { .. } => ServiceError::Domain(SignatureError::Der),
        other => ServiceError::Input(other),
    })?;

    let read = if bytes.len() == COMPACT_SIZE {
        Signature::from_compact_slice(&bytes).map(|s| (s, SignatureEncoding::Compact))
    } else {
        Signature::from_der(&bytes).map(|s| (s, SignatureEncoding::Der))
    };
    read.map_err(ServiceError::Domain)
}
