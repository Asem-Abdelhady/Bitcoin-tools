use axum::Json;
use serde::Serialize;

use crate::types::transactions::Tx;

#[derive(Serialize)]
pub struct TxBuilderResponse<'a> {
    tx: Tx,
    tx_raw: &'a str,
}

pub async fn get_tx_builder() -> Json<TxBuilderResponse<'static>> {
    Json(TxBuilderResponse {
        tx: Tx::default(),
        tx_raw: "This is the transaction builder endpoint",
    })
}
