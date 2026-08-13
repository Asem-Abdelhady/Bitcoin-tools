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
        .route(
            "/builder",
            post(builder::post_build_tx)
                // A build request is hex inside JSON keys, quotes and commas,
                // so it is strictly larger than the transaction it produces:
                // this is a transport budget, not the domain's ceiling. What
                // is buildable is capped by `Tx::MAX_WEIGHT` on the
                // witness-stripped size — 1,000,000 bytes, which a request of
                // roughly 2 MB reaches, comfortably inside this. That headroom
                // is the point: it lets the domain answer
                // `transaction-too-large` rather than the transport answering
                // `unreadable-body`, which
                // `both_size_limits_report_which_one_was_hit` asserts.
                .layer(DefaultBodyLimit::max(body_limit(Tx::MAX_SIZE))),
        )
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
