//! The `/blocks` URL space.

use axum::extract::DefaultBodyLimit;
use axum::{Router, routing::post};

use crate::handlers::blocks::{hash, header};
use crate::routes::body_limit;
use bitcoin_tools_core::blocks::BlockHeader;

/// Routes mounted under `/blocks`.
///
/// Both take one header, so both get the same cap — and it is a small one: a
/// header is a fixed eighty bytes, so there is no reason to buffer a megabyte
/// before finding that out.
pub fn router() -> Router {
    Router::new()
        .route(
            "/hash",
            post(hash::post_block_hash).layer(DefaultBodyLimit::max(body_limit(BlockHeader::SIZE))),
        )
        .route(
            "/header",
            post(header::post_block_header)
                .layer(DefaultBodyLimit::max(body_limit(BlockHeader::SIZE))),
        )
}
