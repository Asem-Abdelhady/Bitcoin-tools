//! Feeds each vector's `rawTx` back through the decoder and requires the
//! produced JSON to equal the vector itself — every field, nothing extra,
//! nothing missing. The vectors are real mainnet transactions, so a
//! disagreement is a bug in the decoder.

mod common;

use bitcoin_tools_server::handlers::transactions::splitter::SplitTxResponse;
use bitcoin_tools_server::services::transactions::tx::split_hex;
use bitcoin_tools_vectors::{legacy, segwit};
use serde_json::Value;

fn split_to_json(raw_tx: &str) -> Value {
    let breakdown = split_hex(raw_tx).expect("vector decodes");
    let response: SplitTxResponse = breakdown.into();
    serde_json::to_value(&response).expect("response serializes")
}

fn check_all(vectors: &[Value], label: &str) {
    for (i, expected) in vectors.iter().enumerate() {
        let raw_tx = expected["rawTx"].as_str().unwrap();
        let got = split_to_json(raw_tx);
        assert_eq!(
            &got,
            expected,
            "{label}[{i}] (txid {}) did not reproduce its vector",
            expected["txid"].as_str().unwrap()
        );
    }
}

#[test]
fn reproduces_every_legacy_vector() {
    let v = legacy();
    assert_eq!(v.len(), 10);
    check_all(&v, "legacy");
}

#[test]
fn reproduces_every_segwit_vector() {
    let v = segwit();
    assert_eq!(v.len(), 12);
    check_all(&v, "segwit");
}

/// `Value` equality ignores key order, so pin the field order separately —
/// reading the JSON top to bottom should walk the raw bytes left to right.
#[test]
fn field_order_follows_the_wire() {
    let segwit = &segwit()[0];
    let json = serde_json::to_string(&{
        let b = split_hex(segwit["rawTx"].as_str().unwrap()).unwrap();
        SplitTxResponse::from(b)
    })
    .unwrap();
    assert_eq!(
        top_level_keys(&json),
        [
            "txid",
            "wtxid",
            "version",
            "marker",
            "flag",
            "inputCount",
            "inputs",
            "outputCount",
            "outputs",
            "witness",
            "locktime",
            "rawTx",
        ]
    );

    let legacy = &legacy()[0];
    let json = serde_json::to_string(&{
        let b = split_hex(legacy["rawTx"].as_str().unwrap()).unwrap();
        SplitTxResponse::from(b)
    })
    .unwrap();
    assert_eq!(
        top_level_keys(&json),
        [
            "txid",
            "version",
            "inputCount",
            "inputs",
            "outputCount",
            "outputs",
            "locktime",
            "rawTx",
        ],
        "legacy transactions must omit wtxid, marker, flag and witness"
    );
}

/// Every mixed witness/non-witness transaction must emit one witness entry
/// per input, including the empty ones.
#[test]
fn witness_arity_matches_input_count() {
    let mut mixed = 0;
    for tx in segwit() {
        let got = split_to_json(tx["rawTx"].as_str().unwrap());
        let inputs = got["inputs"].as_array().unwrap().len();
        let witness = got["witness"].as_array().unwrap();
        assert_eq!(witness.len(), inputs, "arity mismatch for {}", got["txid"]);
        if witness.iter().any(|w| w["stackItems"] == "00") {
            mixed += 1;
        }
    }
    assert!(mixed >= 2, "expected mixed-witness vectors, found {mixed}");
}

/// Extract the keys of the outermost JSON object, in the order emitted.
fn top_level_keys(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let (mut keys, mut cur) = (Vec::new(), String::new());
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for (i, &b) in bytes.iter().enumerate() {
        let c = b as char;
        if in_str {
            if esc {
                esc = false;
                cur.push(c);
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
                let next = bytes[i + 1..].iter().find(|c| !c.is_ascii_whitespace());
                if depth == 1 && next == Some(&b':') {
                    keys.push(std::mem::take(&mut cur));
                }
                cur.clear();
            } else {
                cur.push(c);
            }
        } else {
            match c {
                '"' => {
                    in_str = true;
                    cur.clear();
                }
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
        }
    }
    keys
}
