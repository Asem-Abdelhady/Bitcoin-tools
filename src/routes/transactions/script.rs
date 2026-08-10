use axum::{Router, routing::post};

use crate::handlers::transactions::script::post_split_script;

pub fn transactions_script_router() -> Router {
    Router::new().route("/", post(post_split_script))
}
