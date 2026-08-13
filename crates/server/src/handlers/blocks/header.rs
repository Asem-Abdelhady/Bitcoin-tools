//! HTTP surface for the block header.
//!
//! Transport only. The response is the *semantic* view — the six fields as the
//! values they mean, not as the bytes they occupy. Core carries a
//! [`HeaderBreakdown`](bitcoin_tools_core::blocks::HeaderBreakdown) for the
//! byte layout, which is what `/transactions/splitter` renders for a
//! transaction; a header equivalent would be its own endpoint, not a second
//! shape from this one.

use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::ApiRejection;
use crate::services::blocks::header::{BlockHeaderRequest, HeaderServiceError, decode};
use bitcoin_tools_core::blocks::{BlockHeader, Target};

/// A header's six fields, plus what they imply.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeaderResponse {
    /// The header's own identity, in the standard displayed order. Returned
    /// for the same reason `/transactions/splitter` returns a txid: it is the
    /// name of the thing being described, and a caller should not have to make
    /// a second request to learn it.
    ///
    /// Only the displayed order. The wire order is what `/blocks/hash` exists
    /// to show, and that endpoint would have nothing of its own left if this
    /// one carried both.
    pub block_hash: String,
    /// The version as a number, which is how it is compared.
    pub version: u32,
    /// …and in hex, which is how it is *read*. BIP9 reads the low bits as
    /// soft-fork signals and BIP320 lets miners roll sixteen more, so a modern
    /// version is a bitfield and `536870912` says nothing while `20000000`
    /// says everything. Bitcoin Core's `getblockheader` returns both fields
    /// for this reason and spells them the same way.
    ///
    /// Note this is the *value* in hex, big-endian, not the four bytes as
    /// serialized — the header stores them little-endian.
    pub version_hex: String,
    /// The previous block's hash, in displayed order.
    ///
    /// The header carries it in wire order; showing it that way would print
    /// the one field a caller is most likely to paste into a search box
    /// backwards.
    pub prev_block: String,
    /// The merkle root of the block's transactions, in displayed order — the
    /// same convention, for the same reason.
    pub merkle_root: String,
    /// The miner's claimed time, seconds since the Unix epoch. Claimed rather
    /// than measured: consensus allows two hours of slack, so headers out of
    /// order in time are normal.
    pub time: u32,
    /// The target in its compact four-byte encoding, spelled as
    /// `getblockheader` prints it (`1d00ffff`) rather than as the header
    /// stores it (`ffff001d`, little-endian).
    pub bits: String,
    /// The field miners varied searching for a hash under the target.
    pub nonce: u32,
    /// The 256-bit threshold `bits` expands to, big-endian.
    ///
    /// `null` when the four bytes encode no target — a negative mantissa, or
    /// one shifted past the top of 256 bits. No real header does that; any
    /// eighty bytes can. Rendered as null rather than omitted, because the
    /// absence *is* the answer here and a GUI should have a row to show it in.
    pub target: Option<String>,
    /// Why [`target`](BlockHeaderResponse::target) is null, present only when
    /// it is.
    ///
    /// A null with no reason leaves a debugging tool silent about the one
    /// field it could not explain, which is the same argument that makes a
    /// broken script return 200 with an `error`: showing where it broke is the
    /// point.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_error: Option<String>,
    /// How much harder this target is than difficulty 1, as every explorer
    /// prints it. `null` where the ratio is not a finite number, which is the
    /// degenerate `bits` above plus a zero mantissa.
    pub difficulty: Option<f64>,
    /// Whether the header's own hash comes in under the target the header
    /// itself states.
    ///
    /// Narrower than "the proof of work is valid", and deliberately so: eighty
    /// bytes cannot say whether `bits` is the value the retargeting rules
    /// require at this height, which needs the previous 2,015 headers. This is
    /// the part a single header can answer.
    pub meets_target: bool,
}

impl From<BlockHeader> for BlockHeaderResponse {
    fn from(header: BlockHeader) -> Self {
        let difficulty = header.bits.difficulty();
        let target = header.target();
        BlockHeaderResponse {
            block_hash: header.block_hash().to_string(),
            version: header.version,
            version_hex: format!("{:08x}", header.version),
            prev_block: header.prev_block.to_string(),
            merkle_root: header.merkle_root.to_string(),
            time: header.time,
            bits: header.bits.to_string(),
            nonce: header.nonce,
            target: target.as_ref().ok().map(Target::to_hex),
            target_error: target.as_ref().err().map(ToString::to_string),
            // JSON has no infinity, and serde_json writes a non-finite float
            // as `null` regardless — so the choice is between saying that on
            // purpose and having it happen silently.
            difficulty: difficulty.is_finite().then_some(difficulty),
            meets_target: header.meets_target(),
        }
    }
}

/// `POST /blocks/header`
pub async fn post_block_header(
    payload: Result<Json<BlockHeaderRequest>, JsonRejection>,
) -> Result<Json<BlockHeaderResponse>, ApiRejection<HeaderServiceError>> {
    let Json(request) = payload?;
    let header = decode(&request).map_err(ApiRejection::Domain)?;
    Ok(Json(header.into()))
}
