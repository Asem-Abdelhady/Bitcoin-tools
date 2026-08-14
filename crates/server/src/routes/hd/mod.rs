//! The `/hd` URL space.

use axum::extract::DefaultBodyLimit;
use axum::{Router, routing::post};

use crate::handlers::hd::{derive, mnemonic};
use crate::routes::body_limit;
use bitcoin_tools_core::hd::xkey::MAX_SEED_SIZE;

/// Routes mounted under `/hd`.
///
/// Sized from the seed, which is the only payload either takes — `/hd/mnemonic`
/// takes none at all and inherits the same cap so there is one rule here
/// rather than an exception. A derivation path adds a few dozen characters,
/// which the envelope allowance in [`body_limit`] already covers.
pub fn router() -> Router {
    Router::new()
        .route(
            "/mnemonic",
            post(mnemonic::post_generate_mnemonic)
                .layer(DefaultBodyLimit::max(body_limit(MAX_SEED_SIZE))),
        )
        .route(
            "/derive",
            post(derive::post_derive).layer(DefaultBodyLimit::max(body_limit(MAX_SEED_SIZE))),
        )
}
