//! End-to-end tests for `POST /transactions/splitter`.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_vectors::{legacy, segwit};
use common::{get, post_json, vector};
use serde_json::{Value, json};

const URI: &str = "/transactions/splitter";

async fn split(tx: &str) -> Value {
    let (status, body) = post_json(URI, &json!({ "tx": tx }).to_string()).await;
    assert_eq!(status, StatusCode::OK, "unexpected status; body = {body}");
    body
}

#[tokio::test]
async fn segwit_response_equals_the_vector() {
    let expected = vector(segwit(), 0);
    let got = split(expected["rawTx"].as_str().unwrap()).await;
    assert_eq!(got, expected);
}

#[tokio::test]
async fn legacy_response_equals_the_vector() {
    let expected = vector(legacy(), 0);
    let got = split(expected["rawTx"].as_str().unwrap()).await;
    assert_eq!(got, expected);
    assert!(got.get("wtxid").is_none());
    assert!(got.get("marker").is_none());
    assert!(got.get("witness").is_none());
}

#[tokio::test]
async fn witness_uses_indexed_keys() {
    let v = vector(segwit(), 0);
    let got = split(v["rawTx"].as_str().unwrap()).await;
    let w = &got["witness"][0];
    assert_eq!(w["stackItems"], "02");
    assert!(w["0"]["size"].is_string());
    assert!(w["0"]["item"].is_string());
    assert!(w["1"]["size"].is_string());
}

#[tokio::test]
async fn accepts_a_0x_prefix_and_whitespace() {
    let v = vector(legacy(), 0);
    let raw = v["rawTx"].as_str().unwrap();
    let got = split(&format!("  0x{raw}  ")).await;
    assert_eq!(got["txid"], v["txid"]);
}

#[tokio::test]
async fn rejects_an_empty_transaction() {
    let (status, body) = post_json(URI, &json!({ "tx": "" }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "empty-input");
}

#[tokio::test]
async fn rejects_invalid_hex() {
    let (status, body) = post_json(URI, &json!({ "tx": "zzzz" }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid-hex");
}

/// A truncated transaction has no meaningful partial answer — unlike a
/// script, where the decoded prefix is still useful.
#[tokio::test]
async fn rejects_a_truncated_transaction() {
    let v = vector(legacy(), 0);
    let raw = v["rawTx"].as_str().unwrap();
    let (status, body) = post_json(URI, &json!({ "tx": &raw[..raw.len() - 20] }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid-transaction");
    // Where the cut lands decides which guard trips: inside a field it is
    // "unexpected end", at a length prefix it is the implausible-count check.
    let message = body["message"].as_str().unwrap();
    assert!(
        message.contains("unexpected end") || message.contains("cannot fit"),
        "message was {message}"
    );
}

#[tokio::test]
async fn rejects_trailing_bytes() {
    let v = vector(legacy(), 0);
    let raw = format!("{}ff", v["rawTx"].as_str().unwrap());
    let (status, body) = post_json(URI, &json!({ "tx": raw }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid-transaction");
    assert!(
        body["message"].as_str().unwrap().contains("trailing"),
        "message was {}",
        body["message"]
    );
}

#[tokio::test]
async fn body_problems_keep_their_own_status() {
    let (status, body) = post_json(URI, "{ not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "malformed-json");

    let (status, _) = post_json(URI, &json!({ "transaction": "01" }).to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "wrong field name");
}

#[tokio::test]
async fn wrong_method_uses_the_error_envelope() {
    let (status, body) = get(URI).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"], "method-not-allowed");
}

/// The builder route is wired up but honest about not existing yet.
#[tokio::test]
async fn builder_is_not_implemented() {
    let (status, body) = post_json("/transactions/builder", "{}").await;
    assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    assert_eq!(body["error"], "not-implemented");
}
