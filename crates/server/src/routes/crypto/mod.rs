//! The `/crypto` URL space.

use axum::extract::DefaultBodyLimit;
use axum::{Router, routing::post};

use crate::handlers::crypto::{sign, verify};
use crate::routes::body_limit;
/// How much signature this endpoint will read far enough to *reject*.
///
/// Not the domain's ceiling — that is `MAX_DER_SIZE`, 72 bytes, and the
/// service refuses anything past it on the hex length alone. This is the
/// transport budget above it, and it exists because a caller who pastes
/// something far too long deserves to hear `invalid-signature` rather than
/// `unreadable-body`. Wycheproof's length-overflow cases are about four
/// kilobytes; this leaves room for them and for the other two fields.
const MAX_SIGNATURE_FIELD: usize = 8 * 1024;

/// Routes mounted under `/crypto`.
///
/// Sized so the *domain* answers for a signature of any plausible length —
/// see [`MAX_SIGNATURE_FIELD`]. The keys and hashes beside it are 32 or 65
/// bytes and fit many times over.
pub fn router() -> Router {
    Router::new()
        .route(
            "/sign",
            post(sign::post_sign).layer(DefaultBodyLimit::max(body_limit(MAX_SIGNATURE_FIELD))),
        )
        .route(
            "/verify",
            post(verify::post_verify).layer(DefaultBodyLimit::max(body_limit(MAX_SIGNATURE_FIELD))),
        )
}
