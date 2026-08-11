//! End-to-end tests for `POST /transactions/script`.

mod common;

use axum::http::StatusCode;
use common::{get, post_json, post_without_content_type};
use serde_json::{Value, json};

const URI: &str = "/transactions/script";

async fn analyze(script: &str) -> Value {
    let (status, body) = post_json(URI, &json!({ "script": script }).to_string()).await;
    assert_eq!(status, StatusCode::OK, "unexpected status; body = {body}");
    body
}

#[tokio::test]
async fn analyses_a_p2pkh() {
    let v = analyze("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac").await;

    assert_eq!(v["kind"], "P2PKH");
    assert_eq!(v["sizeBytes"], 25);
    assert_eq!(
        v["asm"],
        "OP_DUP OP_HASH160 OP_PUSHBYTES_20 65ed366110a6fe3132cc1f63d73d3bb5a658797f \
         OP_EQUALVERIFY OP_CHECKSIG"
    );
    assert_eq!(
        v["fields"]["pubkeyHash"],
        "65ed366110a6fe3132cc1f63d73d3bb5a658797f"
    );
    assert_eq!(v["hasDisabledOpcode"], false);
    assert!(v.get("error").is_none(), "clean script must omit `error`");

    let ins = v["instructions"].as_array().unwrap();
    assert_eq!(ins.len(), 5);
    assert_eq!(ins[0]["opcode"], "OP_DUP");
    assert_eq!(ins[0]["category"], "stack");
    assert_eq!(ins[0]["offset"], 0);
    assert_eq!(ins[2]["opcode"], "OP_PUSHBYTES_20");
    assert_eq!(ins[2]["category"], "push-bytes");
    assert_eq!(ins[2]["dataSize"], 20);
    assert_eq!(
        ins[4]["description"],
        "Verify a signature against a public key"
    );
}

#[tokio::test]
async fn analyses_a_taproot_output() {
    let v = analyze("512050a50a97836860d6a71463ac8e244751f2db62dd02348470f27158c927a439cc").await;
    assert_eq!(v["kind"], "P2TR");
    assert_eq!(v["fields"]["witnessVersion"], 1);
    assert_eq!(
        v["fields"]["witnessProgram"],
        "50a50a97836860d6a71463ac8e244751f2db62dd02348470f27158c927a439cc"
    );
}

#[tokio::test]
async fn analyses_a_multisig() {
    let v =
        analyze("5121034d31a1a1622a3c3902370d0f47b531e2b16b1f90d13e86a707dfb4114603f19451ae").await;
    assert_eq!(v["kind"], "P2MS");
    assert_eq!(v["fields"]["required"], 1);
    assert_eq!(v["fields"]["total"], 1);
    assert_eq!(v["fields"]["pubkeys"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn analyses_an_op_return() {
    let v = analyze("6a5d2a0108020303c00204f4e1fcf9a386e2e75105e0ef0708c0de810a0a010cc0a2330ecffca6037f8190e912").await;
    assert_eq!(v["kind"], "OP_RETURN");
    let data = v["fields"]["data"].as_array().unwrap();
    assert_eq!(data.len(), 1);
    assert_eq!(data[0].as_str().unwrap().len(), 42 * 2);
}

#[tokio::test]
async fn accepts_a_0x_prefix_and_whitespace() {
    let v = analyze("  0x0014275b468073affad6c1b2833d026416ec07392b7f  ").await;
    assert_eq!(v["kind"], "P2WPKH");
    assert_eq!(v["fields"]["witnessVersion"], 0);
}

/// A broken script is a successful analysis of a broken script.
#[tokio::test]
async fn malformed_script_is_200_with_an_error_field() {
    let v = analyze("7605aabb").await;
    assert_eq!(v["instructions"].as_array().unwrap().len(), 1);
    assert_eq!(v["instructions"][0]["opcode"], "OP_DUP");
    assert_eq!(v["error"]["error"], "truncated");
    assert_eq!(v["error"]["declared"], 5);
    assert_eq!(v["error"]["available"], 2);
}

#[tokio::test]
async fn rejects_invalid_hex() {
    let (status, body) = post_json(URI, &json!({ "script": "zzzz" }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid-hex");
}

#[tokio::test]
async fn rejects_odd_length_hex() {
    let (status, body) = post_json(URI, &json!({ "script": "76a9" }).to_string()).await;
    assert_eq!(status, StatusCode::OK, "even-length hex is fine");
    assert_eq!(body["kind"], "NONSTANDARD");

    let (status, body) = post_json(URI, &json!({ "script": "76a" }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid-hex");
}

#[tokio::test]
async fn rejects_an_empty_script() {
    let (status, body) = post_json(URI, &json!({ "script": "" }).to_string()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "empty-input");
}

#[tokio::test]
async fn rejects_a_script_past_the_consensus_limit() {
    let too_big = "00".repeat(10_001);
    let (status, body) = post_json(URI, &json!({ "script": too_big }).to_string()).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "input-too-large");
}

/// Each body problem keeps the status axum determined, rather than being
/// flattened into one indistinguishable 400.
#[tokio::test]
async fn body_problems_keep_their_own_status() {
    let (status, body) = post_json(URI, "{ not json").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "malformed-json");

    let (status, body) = post_json(URI, &json!({ "script": 76 }).to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "wrong field type");
    assert_eq!(body["error"], "invalid-body");

    let (status, body) = post_json(URI, &json!({ "scrpit": "76" }).to_string()).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "unknown field");
    assert_eq!(body["error"], "invalid-body");

    let (status, body) = post_without_content_type(URI, r#"{"script":"76"}"#).await;
    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(body["error"], "unsupported-media-type");
}

#[tokio::test]
async fn wrong_method_and_unknown_path_use_the_error_envelope() {
    let (status, body) = get(URI).await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body["error"], "method-not-allowed");

    let (status, body) = get("/transactions/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["error"], "not-found");
}
