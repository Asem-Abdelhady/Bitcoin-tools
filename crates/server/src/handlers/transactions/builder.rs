//! HTTP surface for the transaction builder.
//!
//! Transport only, and thinner than its siblings: the request shape is the
//! service's [`TxSpec`], since what a request may contain is input policy. See
//! that module's note. What lives here is the *response* — a view, which
//! renders ids and bytes into strings — and the status-and-slug table.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::transactions::builder::{BuildFailure, TxSpec, build_tx};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::transactions::builder::BuildError;

/// The finished transaction.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildTxResponse {
    /// The id, as an explorer shows it.
    pub txid: String,
    /// Segwit transactions only — the id over the serialization including
    /// witnesses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wtxid: Option<String>,
    /// Serialized size in bytes, witness included.
    pub size: usize,
    /// BIP141 weight: base bytes counted four times, witness bytes once.
    pub weight: usize,
    /// Virtual size, `weight / 4` rounded up.
    ///
    /// Reported beside `size` because for a segwit transaction they differ and
    /// it is this one a fee rate is quoted against. A response carrying only
    /// `size` would be handing a caller the number *not* used to price their
    /// transaction.
    pub vsize: usize,
    /// The consensus serialization, hex. This is the field to broadcast.
    pub raw_tx: String,
}

/// `POST /transactions/builder`
pub async fn post_build_tx(
    payload: Result<Json<TxSpec>, JsonRejection>,
) -> Result<Json<BuildTxResponse>, ApiRejection<BuildFailure>> {
    let Json(spec) = payload?;
    let tx = build_tx(&spec).map_err(ApiRejection::Domain)?;

    let raw = tx.encode();
    Ok(Json(BuildTxResponse {
        txid: tx.txid().to_string(),
        wtxid: tx.segwit.then(|| tx.wtxid().to_string()),
        size: raw.len(),
        weight: tx.weight(),
        vsize: tx.vsize(),
        raw_tx: hex::encode(&raw),
    }))
}

/// The status and slug for each way a build can fail.
///
/// Located field errors delegate to the
/// [`InputError`](crate::services::input::InputError) inside them, so a bad
/// script reports `invalid-hex` here exactly as it does at
/// `/transactions/script`; only the message gains the position.
impl ApiError for BuildFailure {
    fn status(&self) -> StatusCode {
        match self {
            BuildFailure::Txid { .. } => StatusCode::BAD_REQUEST,
            BuildFailure::Field { error, .. } => error.status(),
            BuildFailure::Rules(e) => match e {
                BuildError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
                _ => StatusCode::BAD_REQUEST,
            },
        }
    }

    fn slug(&self) -> &'static str {
        match self {
            BuildFailure::Txid { .. } => "invalid-txid",
            BuildFailure::Field { error, .. } => error.slug(),
            BuildFailure::Rules(e) => match e {
                BuildError::NoInputs => "no-inputs",
                BuildError::NoOutputs => "no-outputs",
                BuildError::DuplicateInput { .. } => "duplicate-input",
                BuildError::NullPrevout { .. } => "null-prevout",
                BuildError::AmountOutOfRange { .. } | BuildError::TotalOutOfRange { .. } => {
                    "amount-out-of-range"
                }
                BuildError::SegwitWithoutWitness => "segwit-without-witness",
                BuildError::WitnessOnLegacy { .. } => "witness-on-legacy",
                BuildError::TooLarge { .. } => "transaction-too-large",
                // `BuildError` is #[non_exhaustive]: a variant added upstream
                // lands here rather than failing to compile, and the generic
                // slug is the signal that this table needs an arm.
                _ => "invalid-transaction",
            },
        }
    }
}
