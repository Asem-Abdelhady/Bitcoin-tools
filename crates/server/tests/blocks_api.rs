//! End-to-end tests for `POST /blocks/hash` and `POST /blocks/header`.
//!
//! Both endpoints run against the same ten mainnet headers `core` verifies
//! itself with, from the shared vectors crate — so a disagreement between the
//! two suites is a bug in the layer between them, not in the expectations.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_core::general::reverse_hex;
use bitcoin_tools_vectors::{blocks, field, number};
use common::{assert_error, assert_transport_contract, message, post_json, post_ok};
use serde_json::{Value, json};

const HASH_URI: &str = "/blocks/hash";
const HEADER_URI: &str = "/blocks/header";

/// The genesis header, for the cases that do not need ten of them.
const GENESIS: &str = concat!(
    "0100000000000000000000000000000000000000000000000000000000000000",
    "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
    "4b1e5e4a29ab5f49ffff001d1dac2b7c",
);

fn request(header: &str) -> Value {
    json!({ "header": header })
}

/// The vector at a given height, which is how the blocks file is meaningfully
/// indexed — a position in the array says nothing.
fn at_height(height: u64) -> Value {
    blocks()
        .into_iter()
        .find(|b| b["height"].as_u64() == Some(height))
        .unwrap_or_else(|| panic!("no vector for block {height}"))
}

fn number_f64(vector: &Value, name: &str, at: &str) -> f64 {
    vector[name]
        .as_f64()
        .unwrap_or_else(|| panic!("{at} has no {name}"))
}

#[tokio::test]
async fn hashes_every_vector_in_both_byte_orders() {
    for vector in blocks() {
        let at = format!("block {}", vector["height"]);
        let body = post_ok(HASH_URI, &request(field(&vector, "header", &at))).await;

        assert_eq!(body["blockHash"], vector["hash"], "{at}");
        assert_eq!(
            body["blockHashWireOrder"].as_str().expect("hex"),
            reverse_hex(field(&vector, "hash", &at)).expect("whole bytes"),
            "{at}: the wire order is the displayed one reversed"
        );
    }
}

/// The reason the endpoint returns both orders at all: the wire form is not a
/// curiosity, it is the literal byte string the *next* header carries.
#[tokio::test]
async fn the_wire_order_is_what_the_next_header_carries() {
    let genesis = post_ok(HASH_URI, &request(GENESIS)).await;
    let block_one = at_height(1);
    let header = field(&block_one, "header", "block 1");

    // Bytes 4..36 of a header are its previous-block field.
    assert_eq!(
        genesis["blockHashWireOrder"].as_str().expect("hex"),
        &header[8..72],
        "the genesis hash, in wire order, is spelled out inside block 1's header"
    );
    assert_ne!(
        genesis["blockHash"], genesis["blockHashWireOrder"],
        "the two orders differ, which is the whole point of showing both"
    );
}

#[tokio::test]
async fn decodes_every_field_of_every_vector() {
    for vector in blocks() {
        let at = format!("block {}", vector["height"]);
        let body = post_ok(HEADER_URI, &request(field(&vector, "header", &at))).await;

        assert_eq!(body["blockHash"], vector["hash"], "{at}");
        assert_eq!(body["version"], vector["version"], "{at}");
        assert_eq!(body["prevBlock"], vector["prevBlock"], "{at}");
        assert_eq!(body["merkleRoot"], vector["merkleRoot"], "{at}");
        assert_eq!(body["time"], vector["time"], "{at}");
        assert_eq!(body["nonce"], vector["nonce"], "{at}");
        assert_eq!(body["target"], vector["target"], "{at}");

        // The vector stores `bits` as the u32 a header carries; the response
        // spells it the way `getblockheader` prints it.
        assert_eq!(
            body["bits"].as_str().expect("bits"),
            format!("{:08x}", number(&vector, "bits", &at)),
            "{at}"
        );
        assert_eq!(
            body["versionHex"].as_str().expect("versionHex"),
            format!("{:08x}", number(&vector, "version", &at)),
            "{at}"
        );

        // A ratio of two 256-bit numbers evaluated in f64, so compared the way
        // `core`'s own vector suite compares it.
        let (got, expected) = (
            body["difficulty"].as_f64().expect("a difficulty"),
            number_f64(&vector, "difficulty", &at),
        );
        assert!(
            (got - expected).abs() <= expected * 1e-12,
            "{at}: difficulty {got} is not {expected}"
        );

        assert_eq!(
            body["meetsTarget"],
            json!(true),
            "{at}: a mined header meets the target it states"
        );
        assert!(
            body.get("targetError").is_none(),
            "{at}: a real header's bits expand"
        );
    }
}

/// Every field's byte order, on the one header where the orders are visibly
/// different and independently checkable.
#[tokio::test]
async fn the_hashes_are_shown_the_way_they_are_read() {
    let vector = at_height(1);
    let body = post_ok(HEADER_URI, &request(field(&vector, "header", "block 1"))).await;

    assert_eq!(
        body["prevBlock"],
        at_height(0)["hash"],
        "the previous-block field is displayed, not left in wire order"
    );
    assert_eq!(
        body["versionHex"],
        json!("00000001"),
        "the value in hex, big-endian — not the 01000000 the header stores"
    );
}

/// A header whose `bits` encode nothing still has six readable fields. Eighty
/// arbitrary bytes are a valid header; whether they describe a valid *block*
/// is a different question, and the nullable fields are where the API says so.
#[tokio::test]
async fn a_header_with_impossible_bits_still_decodes() {
    // The genesis header with `bits` replaced by 0xffffffff: an overflowing
    // target, and eighty perfectly well-formed bytes.
    let broken = format!("{}ffffffff{}", &GENESIS[..144], &GENESIS[152..]);
    let body = post_ok(HEADER_URI, &request(&broken)).await;

    assert_eq!(body["version"], json!(1), "the readable fields still read");
    assert_eq!(body["bits"], json!("ffffffff"));
    assert_eq!(
        body["target"],
        Value::Null,
        "no target: null is the answer, not a missing key"
    );
    assert!(
        body["targetError"].is_string(),
        "…and the null says why: {body}"
    );
    assert_eq!(
        body["meetsTarget"],
        json!(false),
        "a threshold that cannot be represented cannot be met"
    );
}

/// Eighty bytes, in both directions, from both endpoints. A byte over and a
/// byte under are one mistake, so they are one status and one slug — see the
/// service's own note.
#[tokio::test]
async fn the_width_is_one_error_in_both_directions() {
    for uri in [HASH_URI, HEADER_URI] {
        for (label, header, got) in [
            ("one short", request(&GENESIS[..158]), 79),
            ("one long", request(&format!("{GENESIS}00")), 81),
            // Odd digits are not whole bytes, and the size is reported before
            // decoding — rounded down it read "got 80" while rejecting the
            // input for not being 80 bytes.
            ("half a byte long", request(&format!("{GENESIS}0")), 81),
        ] {
            let body = assert_error(
                post_json(uri, &header.to_string()).await,
                StatusCode::BAD_REQUEST,
                "invalid-block-header",
            );
            let message = message(&body);
            assert!(
                message.contains("80") && message.contains(&format!("got {got}")),
                "{uri} {label}: the message names the width and the size sent: {message}"
            );
        }
    }
}

/// The route's own cap, which is the smaller of the two 413s: past it the body
/// is never buffered, so the service never runs and the slug is the
/// transport's rather than the domain's.
#[tokio::test]
async fn the_transport_cap_rejects_before_the_service_does() {
    let huge = request(&"00".repeat(2000));
    for uri in [HASH_URI, HEADER_URI] {
        assert_error(
            post_json(uri, &huge.to_string()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "unreadable-body",
        );
    }
}

#[tokio::test]
async fn unusable_input_gets_the_shared_vocabulary() {
    for uri in [HASH_URI, HEADER_URI] {
        assert_error(
            post_json(uri, &request("   ").to_string()).await,
            StatusCode::BAD_REQUEST,
            "empty-input",
        );
        assert_error(
            post_json(uri, &request("zz").to_string()).await,
            StatusCode::BAD_REQUEST,
            "invalid-hex",
        );
    }
}

#[tokio::test]
async fn the_request_shape_is_enforced() {
    for uri in [HASH_URI, HEADER_URI] {
        assert_transport_contract(uri, &request(GENESIS)).await;

        // The field is named for the domain, so `tx` is not a synonym.
        assert_error(
            post_json(uri, &json!({ "tx": GENESIS }).to_string()).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid-body",
        );
    }
}
