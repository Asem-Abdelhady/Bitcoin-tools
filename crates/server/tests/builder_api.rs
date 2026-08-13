//! End-to-end tests for `POST /transactions/builder`.
//!
//! The suite that matters here is [`rebuilds_the_vectors_byte_for_byte`]: it
//! takes the splitter's own vectors, feeds the *fields* back in as a build
//! request, and asserts the endpoint returns the identical raw transaction.
//! The two endpoints are inverses, so the vectors verify both from one set of
//! bytes.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_core::general::{Amount, reverse_hex};
use bitcoin_tools_vectors::{legacy, segwit};
use common::{assert_error, assert_transport_contract, message, post_json, post_ok};
use serde_json::{Value, json};

const URI: &str = "/transactions/builder";

/// A funding transaction id, in the displayed order a request carries.
const FUNDING: &str = "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7";
const P2WPKH: &str = "0014275b468073affad6c1b2833d026416ec07392b7f";

async fn build(request: Value) -> (StatusCode, Value) {
    post_json(URI, &request.to_string()).await
}

async fn built(request: Value) -> Value {
    post_ok(URI, &request).await
}

fn minimal(kind: &str) -> Value {
    json!({
        "type": kind,
        "inputs": [{ "txid": FUNDING, "vout": 1 }],
        "outputs": [{ "amount": 54_697u64, "scriptPubkey": P2WPKH }],
    })
}

/// A little-endian hex field of the splitter's breakdown, as the number a
/// build request carries.
fn number(hex: &str) -> u64 {
    let big_endian = reverse_hex(hex).expect("the splitter emits whole bytes");
    u64::from_str_radix(&big_endian, 16).expect("a field that fits")
}

#[tokio::test]
async fn builds_a_legacy_transaction() {
    let body = built(minimal("legacy")).await;

    assert!(body["rawTx"].is_string());
    assert!(body["txid"].is_string());
    assert!(
        body.get("wtxid").is_none(),
        "a legacy transaction has one id"
    );
    let size = body["size"].as_u64().expect("a size");
    assert_eq!(size, body["rawTx"].as_str().expect("hex").len() as u64 / 2);
    // With no witness there is no discount: every byte is a base byte.
    assert_eq!(body["weight"], json!(size * 4));
    assert_eq!(body["vsize"], json!(size));
    // Version 2 and a final sequence are the defaults, so they appear in the
    // bytes without the request naming them.
    let raw = body["rawTx"].as_str().expect("hex");
    assert!(raw.starts_with("02000000"), "{raw}");
    assert!(raw.ends_with("00000000"), "locktime zero: {raw}");
}

#[tokio::test]
async fn a_segwit_build_carries_both_ids() {
    let mut request = minimal("segwit");
    request["inputs"][0]["witness"] = json!(["30".repeat(71), "02".repeat(33)]);
    let body = built(request).await;

    assert_ne!(
        body["txid"], body["wtxid"],
        "the witness is in one id and not the other"
    );
    let raw = body["rawTx"].as_str().expect("hex");
    assert_eq!(&raw[8..12], "0001", "marker and flag: {raw}");

    // The discount, which is the whole reason `vsize` is reported beside
    // `size`: witness bytes weigh a quarter of what base bytes do.
    let (size, weight, vsize) = (
        body["size"].as_u64().expect("a size"),
        body["weight"].as_u64().expect("a weight"),
        body["vsize"].as_u64().expect("a vsize"),
    );
    assert!(vsize < size, "a witness is discounted: {size} vs {vsize}");
    assert!(
        weight < size * 4,
        "witness bytes weigh one, not four: {weight} against {}",
        size * 4
    );
    assert_eq!(vsize, weight.div_ceil(4), "vsize is the weight, rounded up");
}

/// The endpoint against the splitter's vectors: every field of a real mainnet
/// transaction, fed back in, has to produce the same bytes it came from.
#[tokio::test]
async fn rebuilds_the_vectors_byte_for_byte() {
    for (label, set) in [("legacy", legacy()), ("segwit", segwit())] {
        assert!(!set.is_empty(), "{label} vectors are empty");
        for (i, vector) in set.iter().enumerate() {
            let at = format!("{label}[{i}]");
            let witnesses = vector["witness"].as_array();

            let inputs: Vec<Value> = vector["inputs"]
                .as_array()
                .expect("inputs")
                .iter()
                .enumerate()
                .map(|(n, input)| {
                    // The breakdown shows a previous txid in *wire* order,
                    // which is the reverse of how a request names one.
                    let txid =
                        reverse_hex(input["txid"].as_str().expect("txid")).expect("whole bytes");
                    let witness = witnesses.map(|w| {
                        let stack = &w[n];
                        let items =
                            usize::try_from(number(stack["stackItems"].as_str().expect("a count")))
                                .expect("a small count");
                        (0..items)
                            .map(|item| stack[item.to_string()]["item"].clone())
                            .collect::<Vec<Value>>()
                    });
                    json!({
                        "txid": txid,
                        "vout": number(input["vout"].as_str().expect("vout")),
                        "scriptSig": input["scriptSig"],
                        "sequence": number(input["sequence"].as_str().expect("sequence")),
                        "witness": witness.unwrap_or_default(),
                    })
                })
                .collect();

            let outputs: Vec<Value> = vector["outputs"]
                .as_array()
                .expect("outputs")
                .iter()
                .map(|output| {
                    json!({
                        "amount": number(output["amount"].as_str().expect("amount")),
                        "scriptPubkey": output["scriptPubkey"],
                    })
                })
                .collect();

            let body = built(json!({
                "type": if witnesses.is_some() { "segwit" } else { "legacy" },
                "version": number(vector["version"].as_str().expect("version")),
                "lockTime": number(vector["locktime"].as_str().expect("locktime")),
                "inputs": inputs,
                "outputs": outputs,
            }))
            .await;

            assert_eq!(body["rawTx"], vector["rawTx"], "{at}");
            assert_eq!(body["txid"], vector["txid"], "{at}");
            if let Some(wtxid) = vector.get("wtxid") {
                assert_eq!(&body["wtxid"], wtxid, "{at}");
            }
        }
    }
}

#[tokio::test]
async fn the_domain_rules_reach_the_client_with_their_own_slugs() {
    // Segwit asked for, nothing to put in the witness section.
    assert_error(
        build(minimal("segwit")).await,
        StatusCode::BAD_REQUEST,
        "segwit-without-witness",
    );

    // The same outpoint twice.
    let mut duplicate = minimal("legacy");
    duplicate["inputs"] = json!([
        { "txid": FUNDING, "vout": 1 },
        { "txid": FUNDING, "vout": 1 },
    ]);
    let body = assert_error(
        build(duplicate).await,
        StatusCode::BAD_REQUEST,
        "duplicate-input",
    );
    assert!(
        message(&body).contains("input 1"),
        "the message names which input: {body}"
    );

    // Nothing to pay.
    let mut no_outputs = minimal("legacy");
    no_outputs["outputs"] = json!([]);
    assert_error(
        build(no_outputs).await,
        StatusCode::BAD_REQUEST,
        "no-outputs",
    );

    // More than will ever exist.
    let mut too_much = minimal("legacy");
    too_much["outputs"][0]["amount"] = json!(Amount::MAX_MONEY.to_sat() + 1);
    assert_error(
        build(too_much).await,
        StatusCode::BAD_REQUEST,
        "amount-out-of-range",
    );
}

#[tokio::test]
async fn a_bad_field_is_reported_with_its_position() {
    let mut bad_txid = minimal("legacy");
    bad_txid["inputs"] = json!([
        { "txid": FUNDING, "vout": 0 },
        { "txid": "not-a-txid", "vout": 1 },
    ]);
    let body = assert_error(
        build(bad_txid).await,
        StatusCode::BAD_REQUEST,
        "invalid-txid",
    );
    assert!(message(&body).contains("input 1"), "{body}");

    // A hex problem in a script reports the same slug it reports everywhere
    // else, with the position added to the message.
    let mut bad_script = minimal("legacy");
    bad_script["outputs"][0]["scriptPubkey"] = json!("zz");
    let body = assert_error(
        build(bad_script).await,
        StatusCode::BAD_REQUEST,
        "invalid-hex",
    );
    assert!(message(&body).contains("scriptPubkey"), "{body}");
}

/// The shared transport contract, plus the one shape rule this endpoint adds:
/// `type` is required and closed.
#[tokio::test]
async fn the_request_shape_is_enforced() {
    assert_transport_contract(URI, &minimal("legacy")).await;

    assert_error(
        build(json!({
            "type": "taproot",
            "inputs": [{ "txid": FUNDING, "vout": 1 }],
            "outputs": [{ "amount": 1u64, "scriptPubkey": P2WPKH }],
        }))
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}

/// Both size ceilings, which is the one place this endpoint's two limits
/// interact. A field is capped at a script's size; the finished transaction is
/// capped by consensus at a quarter of the block weight — and the transport
/// cap has to sit far enough above both that the *domain* is what answers.
#[tokio::test]
async fn both_size_limits_report_which_one_was_hit() {
    // One field past `Script::MAX_SIZE`: the shared input policy answers, with
    // the same slug every other endpoint gives.
    let mut oversized_field = minimal("legacy");
    oversized_field["outputs"][0]["scriptPubkey"] = json!("00".repeat(10_001));
    let (status, body) = build(oversized_field).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body["error"], "input-too-large");

    // Enough legal fields to push the transaction itself past the consensus
    // limit. `bad-txns-oversize` is measured on the witness-stripped size, so
    // 101 outputs of 10,000 bytes clears 1,000,000 with nothing else needed.
    let mut oversized_tx = minimal("legacy");
    oversized_tx["outputs"] = json!(
        (0..101)
            .map(|_| json!({ "amount": 1u64, "scriptPubkey": "00".repeat(10_000) }))
            .collect::<Vec<Value>>()
    );
    let (status, body) = build(oversized_tx).await;
    assert_eq!(
        status,
        StatusCode::PAYLOAD_TOO_LARGE,
        "the domain limit has to be reachable through the transport one: {body}"
    );
    assert_eq!(
        body["error"], "transaction-too-large",
        "a request that fits the body cap and builds an impossible transaction \
         must hear about the transaction, not the body"
    );
}
