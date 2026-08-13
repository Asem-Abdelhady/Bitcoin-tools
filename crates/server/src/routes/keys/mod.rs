//! The `/keys` URL space.

use axum::extract::DefaultBodyLimit;
use axum::{Router, routing::post};

use crate::handlers::keys::{generate, public};
use crate::routes::body_limit;
use bitcoin_tools_core::crypto::secp::SCALAR_SIZE;

/// Routes mounted under `/keys`.
///
/// Both bodies are tiny — two flags, or two flags and 64 hex digits — so both
/// get the cap a private key's width implies. `/keys/generate` takes no hex at
/// all and would be fine with less; sizing it the same way keeps one rule
/// here rather than an exception to explain.
pub fn router() -> Router {
    Router::new()
        .route(
            "/generate",
            post(generate::post_generate_key).layer(DefaultBodyLimit::max(body_limit(SCALAR_SIZE))),
        )
        .route(
            "/public",
            post(public::post_public_key).layer(DefaultBodyLimit::max(body_limit(SCALAR_SIZE))),
        )
}
