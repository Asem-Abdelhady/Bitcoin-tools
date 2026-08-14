//! Shared test harness.
//!
//! Requests go through `app()` at the real URI a client would use, so a
//! mistyped `nest` prefix fails a test instead of shipping.

// Each test binary includes this module and uses only part of it.
#![allow(dead_code)]

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use bitcoin_tools_server::app;
use serde_json::{Value, json};
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

/// The response *headers* for a POST, which `send` otherwise discards.
///
/// Almost every endpoint's contract is entirely in its body. `/keys/generate`
/// is the exception — its body is a credential, so `Cache-Control` is part of
/// what it promises, and a header is exactly the kind of thing that gets
/// refactored away without anyone noticing.
pub async fn post_json_headers(uri: &str, body: &Value) -> HeaderMap {
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let response = app().oneshot(request).await.expect("router responds");
    assert_eq!(response.status(), StatusCode::OK, "{uri} did not succeed");
    response.headers().clone()
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

/// A failure's status and slug together, since one without the other is half
/// an assertion — and the body goes in the message, because an endpoint whose
/// job is explaining what was wrong should say so in its own red test.
///
/// Returns the body, so a test that also checks the *message* — which field,
/// which input — reads as one statement instead of asserting the slug by hand
/// to keep hold of it.
pub fn assert_error(response: (StatusCode, Value), status: StatusCode, slug: &str) -> Value {
    let (got, body) = response;
    assert_eq!(got, status, "body = {body}");
    assert_eq!(body["error"], slug, "body = {body}");
    body
}

/// The `message` of a failed response, for the checks that go past the slug.
pub fn message(body: &Value) -> &str {
    body["message"]
        .as_str()
        .expect("every error carries a message")
}

/// The transport contract every JSON endpoint owes a client, given a body of
/// the right *shape* — every case here fails before the service runs, so the
/// body need only have the endpoint's fields, not values it would accept.
///
/// Four assertions that have nothing to do with any endpoint's domain: an
/// unknown field is a typo rather than something to ignore, a broken body is
/// not JSON, a missing `Content-Type` is not JSON either, and GET is not a
/// method these endpoints have. Every suite was writing all four, so a new
/// endpoint's cost included pasting them a fifth time — which is exactly what
/// the shared building blocks exist to prevent.
pub async fn assert_transport_contract(uri: &str, valid: &Value) {
    let mut unknown = valid.clone();
    unknown["definitelyNotAField"] = json!(1);
    assert_error(
        post_json(uri, &unknown.to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
    assert_error(
        post_json(uri, "{").await,
        StatusCode::BAD_REQUEST,
        "malformed-json",
    );
    assert_error(
        post_without_content_type(uri, &valid.to_string()).await,
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "unsupported-media-type",
    );
    assert_error(
        get(uri).await,
        StatusCode::METHOD_NOT_ALLOWED,
        "method-not-allowed",
    );
}
