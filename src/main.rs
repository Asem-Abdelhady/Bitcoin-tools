use axum::Router;

use bitcoin_tools_web_server::routes::transactions::builder::transactions_builder_router;
use bitcoin_tools_web_server::routes::transactions::script::transactions_script_router;

#[tokio::main]
async fn main() {
    let transactions_router = Router::new()
        .nest("/builder", transactions_builder_router())
        .nest("/script", transactions_script_router());
    let router = Router::new().nest("/transactions", transactions_router);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind 0.0.0.0:3000");

    axum::serve(listener, router).await.expect("server error");
}
