//! HTTP surface for the block hash.
//!
//! Transport only, and the whole of the view is deciding which byte order to
//! show — which is the one thing about a block hash that trips people up, so
//! this endpoint shows both.

use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::ApiRejection;
use crate::services::blocks::header::{BlockHeaderRequest, HeaderServiceError, decode};
use bitcoin_tools_core::hex;

/// One hash, both ways round.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHashResponse {
    /// The standard form: what an explorer shows, what `getblockhash`
    /// returns, and what anyone means by "the block hash". It is the bytes
    /// below reversed, which is why a block hash appears to begin with zeros
    /// while the header's own bytes end with them.
    pub block_hash: String,
    /// The same thirty-two bytes in the order HASH256 produced them.
    ///
    /// Not a curiosity: this is the literal byte string the *next* block's
    /// header carries in its previous-block field, so it is the form to
    /// compare against raw header bytes.
    ///
    /// Named for the hash and then the ordering, rather than `wireOrder`,
    /// because sitting beside [`block_hash`](BlockHashResponse::block_hash) a
    /// bare "wire order" reads as a different value when it is the same one.
    pub block_hash_wire_order: String,
}

/// `POST /blocks/hash`
pub async fn post_block_hash(
    payload: Result<Json<BlockHeaderRequest>, JsonRejection>,
) -> Result<Json<BlockHashResponse>, ApiRejection<HeaderServiceError>> {
    let Json(request) = payload?;
    let header = decode(&request).map_err(ApiRejection::Domain)?;

    let hash = header.block_hash();
    Ok(Json(BlockHashResponse {
        block_hash: hash.to_string(),
        block_hash_wire_order: hex::encode(&hash.to_wire()),
    }))
}
