use axum::{Router, routing::get};

use crate::handlers::transactions::builder::get_tx_builder;

pub fn transactions_builder_router() -> Router {
    Router::new().route("/", get(get_tx_builder))
}
