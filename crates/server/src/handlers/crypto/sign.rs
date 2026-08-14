//! HTTP surface for signing.
//!
//! The request carries a private key and the response carries none — a
//! signature and a public key are exactly what signing is for producing. So
//! this endpoint does *not* set `NO_STORE`, unlike `/keys/generate`: the rule
//! is about what comes back, not what goes in.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::crypto::SignatureView;
use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::crypto::sign::{SignError, SignRequest, SignServiceError, sign};

/// A signature, and the public key that will verify it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    pub signature: SignatureView,
    /// The public key for the private key that signed, in whichever
    /// serialization `compressed` asked for. Returned so a caller can take the
    /// response straight to `/crypto/verify` without deriving it first.
    pub public_key: String,
    /// Echoed back so a caller comparing two responses can see which hash each
    /// belongs to. Not a secret: it is the thing being published.
    pub message_hash: String,
}

/// `POST /crypto/sign`
pub async fn post_sign(
    payload: Result<Json<SignRequest>, JsonRejection>,
) -> Result<Json<SignResponse>, ApiRejection<SignServiceError>> {
    let Json(request) = payload?;
    let signed = sign(&request).map_err(ApiRejection::Domain)?;

    Ok(Json(SignResponse {
        signature: (&signed.signature).into(),
        public_key: signed.key.public_key().to_string(),
        message_hash: bitcoin_tools_core::hex::encode(&signed.hash),
    }))
}

/// Each field names itself, so a caller knows which one to fix.
impl ApiError for SignError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            // Delegated, so a bad key reports the same slug here as at
            // `/keys/public`.
            SignError::Key(e) => e.slug(),
            SignError::MessageHash { .. } => "invalid-message-hash",
        }
    }
}
