//! HTTP surface for 1.1.

use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::ApiRejection;
use crate::services::input::InputError;
use crate::services::tools::HexRequest;
use crate::services::tools::reverse::decode;
use bitcoin_tools_core::hex;

/// The same bytes, both ways round.
///
/// Both strings are rendered here rather than in the service, because that is
/// what reversal *is*: one encoding of the bytes and one encoding of them
/// backwards. `/blocks/hash` renders its two byte orders the same way.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseResponse {
    /// The input as the server read it: `0x` and whitespace gone, lowercase.
    /// The value, not the spelling — so feeding `reversed` back in returns
    /// exactly this string.
    ///
    /// Echoing it makes the response about twice the size of the request,
    /// which at this endpoint's cap is the largest amplification in the API.
    /// Worth it: without it, a caller cannot tell what the server actually
    /// decoded, and `/transactions/splitter` already re-emits its input.
    pub input: String,
    /// The same bytes, last first.
    pub reversed: String,
    /// How many bytes were flipped.
    pub bytes: usize,
}

/// `POST /tools/reverse-bytes`
///
/// The rejection type is [`InputError`] rather than the
/// [`ServiceError`](crate::services::error::ServiceError) every other endpoint
/// declares, and that is the signature telling the truth: reversing decoded
/// bytes cannot fail, so there is no domain half to name. The day this grows
/// one, this line stops compiling.
pub async fn post_reverse_bytes(
    payload: Result<Json<HexRequest>, JsonRejection>,
) -> Result<Json<ReverseResponse>, ApiRejection<InputError>> {
    let Json(request) = payload?;
    let bytes = decode(&request).map_err(ApiRejection::Domain)?;

    Ok(Json(ReverseResponse {
        input: hex::encode(&bytes),
        reversed: hex::encode_rev(&bytes),
        bytes: bytes.len(),
    }))
}
