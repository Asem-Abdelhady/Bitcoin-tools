//! HTTP surface for 1.2.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::tools::number::{NumberRequest, convert};
use bitcoin_tools_core::general::{Number, ParseNumberError};

/// One value, in every base this converter reads.
///
/// The three keys are [`Base`](bitcoin_tools_core::general::Base)'s own serde
/// spellings — see [the module note](super).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NumberResponse {
    /// Base 2, no `0b`, no leading zeros.
    pub binary: String,
    /// Base 10.
    pub decimal: String,
    /// Base 16, lowercase, no `0x`, no leading zero digit.
    pub hexadecimal: String,
    /// Significant bits — the width of `binary`, and 1 for zero.
    pub bits: usize,
    /// Bytes the value occupies in minimal big-endian form.
    ///
    /// Not `bits` divided by eight and rounded: leading zeros carry no
    /// information about a value, so both numbers describe the *value* rather
    /// than any particular field it was written into. A 256-bit key that
    /// happens to start with a zero byte is 31 bytes here, and that is not a
    /// bug — it is the same number.
    pub bytes: usize,
}

/// By reference, where [`UnitsResponse`](super::units::UnitsResponse) takes
/// its `Amount` by value: `Amount` is `Copy` and `Number` owns a `Vec`, so
/// this is the ordinary Rust distinction rather than two conventions.
impl From<&Number> for NumberResponse {
    fn from(n: &Number) -> Self {
        NumberResponse {
            binary: n.to_binary(),
            decimal: n.to_decimal(),
            hexadecimal: n.to_hex(),
            bits: n.bits(),
            bytes: n.as_be_bytes().len(),
        }
    }
}

/// `POST /tools/number`
pub async fn post_number(
    payload: Result<Json<NumberRequest>, JsonRejection>,
) -> Result<Json<NumberResponse>, ApiRejection<ParseNumberError>> {
    let Json(request) = payload?;
    let number = convert(&request).map_err(ApiRejection::Domain)?;

    Ok(Json(NumberResponse::from(&number)))
}

/// Two of these are the shared vocabulary and one is this endpoint's own.
///
/// An empty value and an oversized one mean at `/tools/number` exactly what
/// they mean at every hex endpoint, so they keep the shared slugs rather than
/// teaching a client a second word for a failure it already handles — the
/// digit cap in particular is a size cap like any other, and 413 is what a
/// size cap answers. Only "that is not a digit in this base" is new.
impl ApiError for ParseNumberError {
    fn status(&self) -> StatusCode {
        match self {
            ParseNumberError::TooManyDigits { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    fn slug(&self) -> &'static str {
        match self {
            ParseNumberError::Empty { .. } => "empty-input",
            ParseNumberError::TooManyDigits { .. } => "input-too-large",
            // `ParseNumberError` is #[non_exhaustive]. `InvalidDigit` is the
            // only other variant today, and any future one would still mean
            // the same thing to a caller: that string is not a number in the
            // base you named.
            _ => "invalid-number",
        }
    }
}
