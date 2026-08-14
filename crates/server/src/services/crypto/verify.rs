//! 7.2 — verifying a signature, as a use case.

use std::fmt;

use serde::Deserialize;

use crate::services::crypto::{SignatureEncoding, message_hash, signature};
use crate::services::error::ServiceError;
use bitcoin_tools_core::crypto::ecdsa::{
    MESSAGE_SIZE, Signature, SignatureError, verify as verify_ecdsa,
};
use bitcoin_tools_core::keys::{PublicKey, PublicKeyError};

/// What `/crypto/verify` accepts.
///
/// Nothing here is secret, so [`Debug`] is derived — a public key, a hash and
/// a signature are exactly the three things a verifier is supposed to publish.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VerifyRequest {
    /// The public key, SEC1 hex — compressed (`02`/`03`) or uncompressed
    /// (`04`).
    pub public_key: String,
    /// The 32 bytes that were signed.
    pub message_hash: String,
    /// The signature, hex. Strict DER or the 64-byte compact form; which one
    /// is decided by length and reported back.
    pub signature: String,
}

/// Why a verification could not be attempted.
///
/// Note what is *not* here: a signature that does not verify. That is an
/// answer, not a failure — it is the answer this endpoint exists to give, and
/// it comes back as a 200 with `valid: false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The bytes are not a point on the curve.
    PublicKey(PublicKeyError),
    /// The bytes are not a signature.
    Signature(SignatureError),
    /// The hash was not 32 bytes.
    MessageHash {
        /// Bytes supplied.
        got: usize,
    },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::PublicKey(e) => write!(f, "{e}"),
            VerifyError::Signature(e) => write!(f, "{e}"),
            VerifyError::MessageHash { got } => {
                write!(f, "a message hash is {MESSAGE_SIZE} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VerifyError::PublicKey(e) => Some(e),
            VerifyError::Signature(e) => Some(e),
            VerifyError::MessageHash { .. } => None,
        }
    }
}

/// Bad input, or a field that is not the thing it claims to be.
pub type VerifyServiceError = ServiceError<VerifyError>;

/// The answer, and enough of the inputs to explain it.
///
/// Nothing here is secret: a public key, a signature and a boolean.
#[derive(Debug)]
pub struct Verification {
    /// Whether the signature verifies. The whole question.
    pub valid: bool,
    pub signature: Signature,
    /// Which encoding the signature was read as, since that was inferred.
    pub encoding: SignatureEncoding,
    pub key: PublicKey,
}

/// 7.2 — does this signature verify against this key and this hash?
///
/// # A high `s` verifies
///
/// `(r, s)` and `(r, n − s)` are the same signature mathematically, so the
/// domain normalises `s` before checking and this endpoint inherits that. Low-`s`
/// is Bitcoin's *malleability policy*, not a fact about ECDSA — 72 of the 168
/// valid signatures in Wycheproof's suite have high `s`, and every one was
/// produced by a correct signer. The response reports `isLowS` separately so a
/// caller can apply the policy without the arithmetic answer being bent to fit
/// it.
///
/// # Errors
///
/// [`VerifyServiceError`] for unusable hex, a key that is not a point, a
/// signature that is not strict DER or 64 bytes, or a hash that is not 32
/// bytes. Never for a signature that simply does not verify.
pub fn verify(request: &VerifyRequest) -> Result<Verification, VerifyServiceError> {
    let hash = message_hash(&request.message_hash, |got| VerifyError::MessageHash {
        got,
    })?;
    let key = PublicKey::from_hex(&request.public_key)
        .map_err(|e| ServiceError::Domain(VerifyError::PublicKey(e)))?;
    let (signature, encoding) =
        signature(&request.signature).map_err(|e| e.map_domain(VerifyError::Signature))?;

    Ok(Verification {
        valid: verify_ecdsa(&hash, &signature, &key.point()),
        signature,
        encoding,
        key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first RFC 6979 vector.
    const KEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const HASH: &str = "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456";
    const DER: &str = concat!(
        "3044022033a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
        "02206f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262",
    );
    const COMPACT: &str = concat!(
        "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9",
        "6f807982866f785d3f6418d24163ddae117b7db4d5fdf0071de069fa54342262",
    );

    fn request(public_key: &str, message_hash: &str, signature: &str) -> VerifyRequest {
        VerifyRequest {
            public_key: public_key.to_owned(),
            message_hash: message_hash.to_owned(),
            signature: signature.to_owned(),
        }
    }

    #[test]
    fn both_encodings_read_the_same_signature() {
        let der = verify(&request(KEY, HASH, DER)).unwrap();
        let compact = verify(&request(KEY, HASH, COMPACT)).unwrap();

        assert!(der.valid && compact.valid);
        assert_eq!(der.encoding, SignatureEncoding::Der);
        assert_eq!(compact.encoding, SignatureEncoding::Compact);
        assert_eq!(
            der.signature.to_der(),
            compact.signature.to_der(),
            "one signature, two spellings"
        );
    }

    /// A signature that does not verify is the answer, not an error.
    #[test]
    fn a_wrong_signature_is_a_valid_false_rather_than_a_failure() {
        let mut other_hash = HASH.to_owned();
        other_hash.replace_range(0..2, "ff");

        let answer = verify(&request(KEY, &other_hash, DER)).expect("this is not a failure");
        assert!(!answer.valid);
        assert_eq!(
            answer.signature.to_der(),
            verify(&request(KEY, HASH, DER)).unwrap().signature.to_der(),
            "…and the signature still parses and is reported"
        );
    }

    #[test]
    fn each_field_reports_its_own_failure() {
        assert!(matches!(
            verify(&request("02ff", HASH, DER)).unwrap_err(),
            ServiceError::Domain(VerifyError::PublicKey(_))
        ));
        assert!(matches!(
            verify(&request(KEY, HASH, "3044ff")).unwrap_err(),
            ServiceError::Domain(VerifyError::Signature(_))
        ));
        assert_eq!(
            verify(&request(KEY, &HASH[..62], DER)).unwrap_err(),
            ServiceError::Domain(VerifyError::MessageHash { got: 31 })
        );
    }

    /// Strict DER is BIP66's rule and the domain's default; anything merely
    /// *near* it is refused rather than repaired. A lax parser is what
    /// pre-2015 scripts would need, and is not what a verifier reaches for.
    #[test]
    fn a_signature_that_is_not_strict_der_is_refused() {
        for (label, malformed) in [
            ("truncated", DER[..DER.len() - 2].to_owned()),
            ("a byte too many", format!("{DER}00")),
            // The outer SEQUENCE tag replaced: still 71 bytes, still hex.
            ("wrong tag", format!("31{}", &DER[2..])),
        ] {
            assert_eq!(
                verify(&request(KEY, HASH, &malformed)).unwrap_err(),
                ServiceError::Domain(VerifyError::Signature(SignatureError::Der)),
                "{label}"
            );
        }
    }
}
