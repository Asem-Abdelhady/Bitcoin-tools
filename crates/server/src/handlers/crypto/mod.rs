//! HTTP surface for `/crypto`.

pub mod sign;
pub mod verify;

use serde::Serialize;

use bitcoin_tools_core::crypto::ecdsa::Signature;
use bitcoin_tools_core::hex;

/// A signature in both encodings, plus the pair it is.
///
/// Shared by both endpoints — one produces a signature and the other reads
/// one, and a caller moving between them should not have to translate.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureView {
    /// Strict DER, as BIP66 requires. This is the form a `scriptSig` carries —
    /// with a sighash byte appended, which belongs to the script rather than
    /// to the signature and is not added here.
    pub der: String,
    /// The 64-byte form: `r` then `s`, no framing. What the RFC 6979 vectors
    /// are published in.
    pub compact: String,
    /// The first half of the pair.
    pub r: String,
    /// The second half.
    pub s: String,
    /// Whether `s` is in the lower half of the range.
    ///
    /// A *policy* question, not an arithmetic one: `(r, s)` and `(r, n − s)`
    /// are the same signature, and both verify. Bitcoin Core enforces low-`s`
    /// as a standardness rule rather than a consensus one, so high-`s`
    /// signatures sit in mined blocks. Reported separately so a caller can
    /// apply the policy without the validity answer being bent to fit it.
    pub is_low_s: bool,
}

impl From<&Signature> for SignatureView {
    fn from(signature: &Signature) -> Self {
        let (r, s) = signature.parts();
        SignatureView {
            der: hex::encode(&signature.to_der()),
            compact: hex::encode(&signature.to_compact()),
            r: hex::encode(&r),
            s: hex::encode(&s),
            is_low_s: signature.is_low_s(),
        }
    }
}
