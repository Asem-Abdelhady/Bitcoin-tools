//! The `/transactions` URL space.
//!
//! Every transaction endpoint is listed here, so adding one is a single
//! `.route(...)` line next to its siblings rather than a new file plus a
//! `nest` call somewhere else.

use axum::extract::DefaultBodyLimit;
use axum::{Router, routing::post};

use crate::handlers::transactions::{builder, script, splitter};
use crate::routes::body_limit;
use bitcoin_tools_core::transactions::script::Script;
use bitcoin_tools_core::transactions::tx::Tx;

/// Routes mounted under `/transactions`.
pub fn router() -> Router {
    Router::new()
        .route("/builder", post(builder::post_tx_builder))
        .route(
            "/script",
            post(script::post_analyze_script)
                .layer(DefaultBodyLimit::max(body_limit(Script::MAX_SIZE))),
        )
        .route(
            "/splitter",
            post(splitter::post_split_tx).layer(DefaultBodyLimit::max(body_limit(Tx::MAX_SIZE))),
        )
}
