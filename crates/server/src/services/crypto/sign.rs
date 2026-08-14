//! signing a hash, as a use case.

use std::fmt;

use serde::Deserialize;

use crate::services::default_network;
use crate::services::error::ServiceError;
use crate::services::keys::{default_compressed, private_key};
use bitcoin_tools_core::crypto::ecdsa::{MESSAGE_SIZE, Signature};
use bitcoin_tools_core::keys::{PrivateKey, PrivateKeyError};

/// What `/crypto/sign` accepts.
///
/// [`Debug`] is hand-written so the key does not print — see
/// [`the convention`](crate::services::keys).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignRequest {
    /// The secret, as 64 hex digits.
    pub private_key: String,
    /// The 32 bytes to sign. A *hash*, not a message — see
    /// [the module note](crate::services::crypto).
    pub message_hash: String,
    /// Which serialization the public key is reported in. Cosmetic for the
    /// signature, which is over the scalar and identical either way.
    ///
    /// There is deliberately no `network` beside it. `PrivateKey` carries one,
    /// so the parser must be given something — but nothing in the response
    /// depends on it, and a field a caller can set and never observe is a
    /// promise this endpoint would not be keeping.
    #[serde(default = "default_compressed")]
    pub compressed: bool,
}

impl fmt::Debug for SignRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignRequest")
            .field("private_key", &"<redacted>")
            .field("message_hash", &self.message_hash)
            .field("compressed", &self.compressed)
            .finish()
    }
}

/// Why a request could not be signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The key was not 32 bytes, or not a scalar.
    Key(PrivateKeyError),
    /// The hash was not 32 bytes. Not a `PrivateKeyError` wearing another
    /// name: the two fields fail for unrelated reasons and a caller fixing one
    /// should not be told about the other.
    MessageHash {
        /// Bytes supplied, where [`MESSAGE_SIZE`] were required.
        got: usize,
    },
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Key(e) => write!(f, "{e}"),
            SignError::MessageHash { got } => write!(
                f,
                "a message hash is {MESSAGE_SIZE} bytes, got {got}; ECDSA signs a \
                 digest, not a message"
            ),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignError::Key(e) => Some(e),
            SignError::MessageHash { .. } => None,
        }
    }
}

/// Bad input, or a key and hash that are not what they claim.
pub type SignServiceError = ServiceError<SignError>;

/// A signature and the key that will verify it.
///
/// `Debug` is derived, and that is safe by the rule rather than by luck:
/// `PrivateKey` hand-writes a redacting impl, so the composite inherits it.
#[derive(Debug)]
pub struct Signed {
    pub signature: Signature,
    pub key: PrivateKey,
    /// The digest actually signed.
    ///
    /// Carried so the response reports the *value* rather than the spelling it
    /// arrived in — an uppercase request would otherwise echo back uppercase,
    /// alone among this API's hex fields.
    pub hash: [u8; MESSAGE_SIZE],
}

/// sign a hash with a private key.
///
/// Deterministic: RFC 6979 derives the nonce from the key and the hash, so the
/// same request always produces the same signature. That is not a convenience
/// — a repeated nonce across two different messages hands an attacker the
/// private key outright, and deriving it removes the RNG that could repeat
/// one. It is also what makes this endpoint testable against published
/// vectors byte for byte.
///
/// # Errors
///
/// [`SignServiceError`] for unusable hex in either field, a key that is not 32
/// bytes or not a scalar, or a hash that is not 32 bytes.
pub fn sign(request: &SignRequest) -> Result<Signed, SignServiceError> {
    let key = private_key(&request.private_key, default_network(), request.compressed)
        .map_err(|e| e.map_domain(SignError::Key))?;
    let hash = super::message_hash(&request.message_hash, |got| SignError::MessageHash { got })?;

    Ok(Signed {
        signature: key.sign(&hash),
        key,
        hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::input::InputError;
    use bitcoin_tools_core::hex;

    /// The first RFC 6979 vector: private key 1, and the hash of a sentence
    /// every published set uses.
    const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
    const HASH: &str = "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456";
    const R: &str = "33a69cd2065432a30f3d1ce4eb0d59b8ab58c74f27c41a7fdb5696ad4e6108c9";

    fn request(private_key: &str, message_hash: &str) -> SignRequest {
        SignRequest {
            private_key: private_key.to_owned(),
            message_hash: message_hash.to_owned(),
            compressed: true,
        }
    }

    #[test]
    fn signs_the_published_vector() {
        let signed = sign(&request(KEY, HASH)).unwrap();
        assert_eq!(hex::encode(&signed.signature.r()), R);
        assert!(signed.signature.is_low_s(), "output is always low-s");
    }

    /// The property that makes RFC 6979 worth having, and the one an RNG-based
    /// signer cannot offer.
    #[test]
    fn the_same_request_always_signs_the_same() {
        let a = sign(&request(KEY, HASH)).unwrap();
        let b = sign(&request(KEY, HASH)).unwrap();
        assert_eq!(a.signature.to_der(), b.signature.to_der());
    }

    /// The digest is carried out, not re-read from the request, so the
    /// spelling a caller used cannot reach the response.
    #[test]
    fn the_hash_carried_out_is_the_one_that_was_signed() {
        let upper = sign(&request(KEY, &HASH.to_uppercase())).unwrap();
        assert_eq!(hex::encode(&upper.hash), HASH);
        assert_eq!(
            upper.signature.to_der(),
            sign(&request(KEY, HASH)).unwrap().signature.to_der(),
            "…and the case never reached the digest in the first place"
        );
    }

    #[test]
    fn the_two_fields_fail_separately() {
        assert_eq!(
            sign(&request(&KEY[..62], HASH)).unwrap_err(),
            ServiceError::Domain(SignError::Key(PrivateKeyError::WrongLength { got: 31 }))
        );
        assert_eq!(
            sign(&request(KEY, &HASH[..62])).unwrap_err(),
            ServiceError::Domain(SignError::MessageHash { got: 31 })
        );
        assert_eq!(
            sign(&request(KEY, &format!("{HASH}00"))).unwrap_err(),
            ServiceError::Domain(SignError::MessageHash { got: 33 }),
            "both directions of the width, as everywhere else"
        );
    }

    #[test]
    fn unusable_input_stays_an_input_error() {
        assert!(matches!(
            sign(&request("zz", HASH)).unwrap_err(),
            ServiceError::Input(InputError::Hex(_))
        ));
        assert_eq!(
            sign(&request(KEY, "  ")).unwrap_err(),
            ServiceError::Input(InputError::Empty {
                subject: "message hash"
            })
        );
    }

    #[test]
    fn the_key_does_not_appear_in_debug_output() {
        let rendered = format!("{:?}", request(KEY, HASH));
        assert!(!rendered.contains(KEY), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains(HASH),
            "…and the hash, which is not secret, still prints: {rendered}"
        );
    }
}
