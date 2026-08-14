//! HTTP surface for verification.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::crypto::SignatureView;
use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::crypto::SignatureEncoding;
use crate::services::crypto::verify::{VerifyError, VerifyRequest, VerifyServiceError, verify};
use bitcoin_tools_core::keys::PublicKeyError;

/// The answer, and what it was read from.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    /// Whether the signature verifies against the key and the hash.
    ///
    /// `false` is a 200, not an error: a signature that does not verify is the
    /// answer this endpoint exists to give, and there is no sub-reason a
    /// caller could act on. Bytes that are not a signature *at all* fail
    /// earlier, with a 400 that says why.
    pub valid: bool,
    /// Which encoding the signature was read as — inferred from its length,
    /// so reported rather than assumed.
    pub encoding: SignatureEncoding,
    pub signature: SignatureView,
    /// The key, normalised to the serialization it was given in.
    pub public_key: String,
}

/// `POST /crypto/verify`
pub async fn post_verify(
    payload: Result<Json<VerifyRequest>, JsonRejection>,
) -> Result<Json<VerifyResponse>, ApiRejection<VerifyServiceError>> {
    let Json(request) = payload?;
    let verification = verify(&request).map_err(ApiRejection::Domain)?;

    Ok(Json(VerifyResponse {
        valid: verification.valid,
        encoding: verification.encoding,
        signature: (&verification.signature).into(),
        public_key: verification.key.to_string(),
    }))
}

/// Three fields, three slugs — a client branching on them can say which one to
/// fix, which one `invalid-input` could not.
impl ApiError for VerifyError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            VerifyError::PublicKey(e) => e.slug(),
            VerifyError::Signature(_) => "invalid-signature",
            VerifyError::MessageHash { .. } => "invalid-message-hash",
        }
    }
}

/// Beside its one user: only this endpoint reads a public key.
impl ApiError for PublicKeyError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            PublicKeyError::Hex(_) => "invalid-hex",
            // `PublicKeyError` is #[non_exhaustive]. Every other variant means
            // the same thing to a caller: those bytes are not a public key.
            _ => "invalid-public-key",
        }
    }
}
