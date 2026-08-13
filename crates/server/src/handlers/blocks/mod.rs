//! HTTP surface for `/blocks`.
//!
//! Two endpoints over one input, so the failure vocabulary is stated here
//! rather than in either of them.

pub mod hash;
pub mod header;

use axum::http::StatusCode;

use crate::handlers::error::ApiError;
use bitcoin_tools_core::blocks::HeaderDecodeError;

/// Shared by both block endpoints, which take the same eighty bytes.
///
/// A header has no counts, lengths or nesting, so there is only one way for
/// usable hex to fail to be one: the wrong number of bytes. That is a
/// malformed *request* rather than malformed data the request asked about —
/// there is no partial answer to give, exactly as with a transaction — so it
/// is a 400 and not a 200 with an `error` field.
impl ApiError for HeaderDecodeError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            // Only reachable through `BlockHeader::from_hex`, which the
            // service does not call — it decodes hex through the shared input
            // policy first. Mapped anyway, and to the slug every other
            // endpoint gives for the same mistake, so the arm cannot become
            // the odd one out if a future caller does take that path.
            HeaderDecodeError::Hex(_) => "invalid-hex",
            // `HeaderDecodeError` is #[non_exhaustive]: a variant added
            // upstream lands here rather than failing to compile.
            _ => "invalid-block-header",
        }
    }
}
