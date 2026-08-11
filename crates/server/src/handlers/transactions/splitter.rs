//! HTTP surface for transaction splitting.
//!
//! Transport only. The response mirrors the vectors in `vectors/`:
//! every field as the hex bytes it occupies, in serialization order.

use axum::{Json, extract::rejection::JsonRejection};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use axum::http::StatusCode;

use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::transactions::tx::{TxServiceError, split_hex};
use bitcoin_tools_core::transactions::tx::{
    InputBreakdown, OutputBreakdown, TxBreakdown, TxDecodeError, WitnessBreakdown,
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitTxRequest {
    /// The raw transaction, hex-encoded.
    pub tx: String,
}

/// Field order here is the serialization order, so reading the JSON top to
/// bottom walks the raw bytes left to right.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTxResponse {
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wtxid: Option<String>,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marker: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flag: Option<String>,
    pub input_count: String,
    pub inputs: Vec<InputView>,
    pub output_count: String,
    pub outputs: Vec<OutputView>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<Vec<WitnessView>>,
    pub locktime: String,
    pub raw_tx: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputView {
    pub txid: String,
    pub vout: String,
    pub script_sig_size: String,
    pub script_sig: String,
    pub sequence: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputView {
    pub amount: String,
    pub script_pubkey_size: String,
    pub script_pubkey: String,
}

#[derive(Debug, Serialize)]
struct WitnessItemView<'a> {
    size: &'a str,
    item: &'a str,
}

/// One input's witness, rendered as `stackItems` plus the stack indexed by
/// position: `{"stackItems":"02","0":{…},"1":{…}}`.
///
/// Numeric keys alongside a named one is not a shape `derive(Serialize)` can
/// produce, hence the hand-written map.
#[derive(Debug)]
pub struct WitnessView(WitnessBreakdown);

impl Serialize for WitnessView {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(1 + self.0.items.len()))?;
        map.serialize_entry("stackItems", &self.0.stack_items)?;
        for (i, item) in self.0.items.iter().enumerate() {
            map.serialize_entry(
                &i.to_string(),
                &WitnessItemView {
                    size: &item.size,
                    item: &item.item,
                },
            )?;
        }
        map.end()
    }
}

impl From<InputBreakdown> for InputView {
    fn from(i: InputBreakdown) -> Self {
        InputView {
            txid: i.txid,
            vout: i.vout,
            script_sig_size: i.script_sig_size,
            script_sig: i.script_sig,
            sequence: i.sequence,
        }
    }
}

impl From<OutputBreakdown> for OutputView {
    fn from(o: OutputBreakdown) -> Self {
        OutputView {
            amount: o.amount,
            script_pubkey_size: o.script_pubkey_size,
            script_pubkey: o.script_pubkey,
        }
    }
}

impl From<TxBreakdown> for SplitTxResponse {
    fn from(b: TxBreakdown) -> Self {
        SplitTxResponse {
            txid: b.txid,
            wtxid: b.wtxid,
            version: b.version,
            marker: b.marker,
            flag: b.flag,
            input_count: b.input_count,
            inputs: b.inputs.into_iter().map(Into::into).collect(),
            output_count: b.output_count,
            outputs: b.outputs.into_iter().map(Into::into).collect(),
            witness: b
                .witness
                .map(|ws| ws.into_iter().map(WitnessView).collect()),
            locktime: b.locktime,
            raw_tx: b.raw_tx,
        }
    }
}

/// `POST /transactions/splitter`
pub async fn post_split_tx(
    payload: Result<Json<SplitTxRequest>, JsonRejection>,
) -> Result<Json<SplitTxResponse>, ApiRejection<TxServiceError>> {
    let Json(req) = payload?;
    let breakdown = split_hex(&req.tx).map_err(ApiRejection::Domain)?;
    Ok(Json(breakdown.into()))
}

/// The only endpoint-specific error mapping this handler needs; everything
/// else comes from `ApiError for ServiceError<E>`.
impl ApiError for TxDecodeError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        "invalid-transaction"
    }
}
