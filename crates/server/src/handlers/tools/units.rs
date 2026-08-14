//! HTTP surface for 1.3.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::tools::units::{UnitsRequest, convert};
use bitcoin_tools_core::general::{Amount, Denomination, ParseAmountError};

/// One amount, in every unit.
///
/// The four keys are
/// [`Denomination`](bitcoin_tools_core::general::Denomination)'s own serde
/// spellings — see [the module note](super).
///
/// Every value is a **string**, including the satoshi count. That is the same
/// decision the request makes and for the same reason: an amount from a
/// malformed transaction can be past 2^53, where a JSON number stops being
/// exact in most consumers, and this endpoint would be the one place a value
/// changed on its way through a *converter*.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UnitsResponse {
    /// Satoshis. Always a whole number — nothing divides one.
    pub satoshi: String,
    /// µBTC, also called bits. 100 satoshis.
    pub microbitcoin: String,
    /// mBTC. 100 000 satoshis.
    pub millibitcoin: String,
    /// BTC. 100 000 000 satoshis.
    pub bitcoin: String,
    /// Whether this is an amount Bitcoin can actually hold: at or below 21
    /// million BTC.
    ///
    /// A field rather than a rejection. The domain declines to enforce the cap
    /// because a malformed transaction may declare any `u64` and a tool has to
    /// be able to show it — so the question gets answered instead of being
    /// turned into a refusal.
    pub is_money_range: bool,
}

impl From<Amount> for UnitsResponse {
    fn from(amount: Amount) -> Self {
        // Each field names the unit it renders, so no ordering assumption can
        // put an answer under the wrong key. That the set is *complete* is the
        // other half, and it is asserted against `Denomination::all` in
        // `tools_api` rather than by eye.
        UnitsResponse {
            satoshi: amount.to_string_in(Denomination::Satoshi),
            microbitcoin: amount.to_string_in(Denomination::MicroBitcoin),
            millibitcoin: amount.to_string_in(Denomination::MilliBitcoin),
            bitcoin: amount.to_string_in(Denomination::Bitcoin),
            is_money_range: amount.is_money_range(),
        }
    }
}

/// `POST /tools/units`
pub async fn post_units(
    payload: Result<Json<UnitsRequest>, JsonRejection>,
) -> Result<Json<UnitsResponse>, ApiRejection<ParseAmountError>> {
    let Json(request) = payload?;
    let amount = convert(&request).map_err(ApiRejection::Domain)?;

    Ok(Json(amount.into()))
}

/// Three slugs, because a caller fixes these three mistakes three ways.
///
/// `amount-too-precise` is its own rather than folded into `invalid-amount`:
/// the string *is* a number, and the fix is to drop digits or change unit
/// rather than to retype it. `amount-out-of-range` is borrowed from the
/// builder deliberately — an amount past what an amount can be is one sentence
/// to a client, whether the ceiling it passed was 21 million or `u64`.
impl ApiError for ParseAmountError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            ParseAmountError::Empty => "empty-input",
            ParseAmountError::TooPrecise { .. } => "amount-too-precise",
            ParseAmountError::TooLarge => "amount-out-of-range",
            // `ParseAmountError` is #[non_exhaustive]. The rest — negative, a
            // stray character, a second point, an unknown unit — are all "that
            // is not an amount", and each message says which.
            _ => "invalid-amount",
        }
    }
}
