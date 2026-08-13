//! Shared test harness.
//!
//! Requests go through `app()` at the real URI a client would use, so a
//! mistyped `nest` prefix fails a test instead of shipping.

// Each test binary includes this module and uses only part of it.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use bitcoin_tools_web_server::app;
use serde_json::Value;
use tower::ServiceExt;

/// One vector out of a set, by index. The sets themselves come from
/// `bitcoin_tools_vectors`, so the server and the core assert against the
/// identical bytes.
pub fn vector(mut set: Vec<Value>, i: usize) -> Value {
    set.swap_remove(i)
}

/// Drive the composed application and parse whatever comes back.
pub async fn send(request: Request<Body>) -> (StatusCode, Value) {
    let response = app().oneshot(request).await.expect("router responds");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body reads");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// `POST uri` with a JSON body and the correct content type.
pub async fn post_json(uri: &str, body: &str) -> (StatusCode, Value) {
    send(
        Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_owned()))
            .unwrap(),
    )
    .await
}

/// `POST uri` with a JSON body, requiring 200 and returning the response.
///
/// Every endpoint's happy path is this same three lines, and the failure
/// message has to carry the body or a red test says only "expected 200, got
/// 400" about an endpoint whose whole job is explaining what was wrong.
pub async fn post_ok(uri: &str, body: &Value) -> Value {
    let (status, body) = post_json(uri, &body.to_string()).await;
    assert_eq!(status, StatusCode::OK, "unexpected status; body = {body}");
    body
}

/// `POST uri` with no `Content-Type`, which axum rejects with 415.
pub async fn post_without_content_type(uri: &str, body: &str) -> (StatusCode, Value) {
    send(
        Request::builder()
            .method("POST")
            .uri(uri)
            .body(Body::from(body.to_owned()))
            .unwrap(),
    )
    .await
}

pub async fn get(uri: &str) -> (StatusCode, Value) {
    send(
        Request::builder()
            .method("GET")
            .uri(uri)
            .body(Body::empty())
            .unwrap(),
    )
    .await
}
