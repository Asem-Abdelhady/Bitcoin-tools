//! End-to-end tests for `POST /transactions/splitter`.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_vectors::{legacy, segwit};
use common::{assert_error, assert_transport_contract, post_json, post_ok, vector};
use serde_json::{Value, json};

const URI: &str = "/transactions/splitter";

async fn split(tx: &str) -> Value {
    post_ok(URI, &json!({ "tx": tx })).await
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

/// The shared transport contract, plus this endpoint's own field name: `tx`
/// is not a synonym for `transaction`.
#[tokio::test]
async fn the_request_shape_is_enforced() {
    let real = vector(legacy(), 0);
    assert_transport_contract(URI, &json!({ "tx": real["rawTx"] })).await;

    assert_error(
        post_json(URI, &json!({ "transaction": "01" }).to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}

/// The two endpoints are inverses, and this is the seam between them: what the
/// builder produced, the splitter takes apart into the fields it was built
/// from. `builder_api.rs` drives the same property from the other side.
#[tokio::test]
async fn what_the_builder_produces_the_splitter_reads_back() {
    let (status, built) = post_json(
        "/transactions/builder",
        &json!({
            "type": "legacy",
            "inputs": [{
                "txid": "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7",
                "vout": 1,
            }],
            "outputs": [{
                "amount": 54_697u64,
                "scriptPubkey": "0014275b468073affad6c1b2833d026416ec07392b7f",
            }],
        })
        .to_string(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{built}");

    let split = split(built["rawTx"].as_str().expect("raw hex")).await;
    assert_eq!(split["txid"], built["txid"]);
    assert_eq!(split["rawTx"], built["rawTx"]);
    assert_eq!(
        split["version"], "02000000",
        "the builder's default version"
    );
    assert_eq!(
        split["inputs"][0]["sequence"], "ffffffff",
        "not replaceable"
    );
    assert_eq!(split["outputs"][0]["amount"], "a9d5000000000000");
}
