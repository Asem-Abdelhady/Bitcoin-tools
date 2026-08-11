use bitcoin_tools_web_server::app;

#[tokio::main]
async fn main() {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("failed to bind 0.0.0.0:3000");

    axum::serve(listener, app()).await.expect("server error");
}
