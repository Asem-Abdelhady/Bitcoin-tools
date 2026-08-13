//! End-to-end tests for `POST /keys/generate` and `POST /keys/public`.
//!
//! The two P2PKH addresses are computed independently of this workspace:
//! scalar multiplication, HASH160 and Base58Check, done from scratch, because
//! asserting that a generator agrees with itself would prove nothing.
//!
//! The rest are pinned by *relation* rather than by a copied string — that a
//! P2WPKH program is the same twenty bytes P2PKH commits to, that a taproot
//! program is not the internal key, that a BIP49 address commits to the redeem
//! script instead of the key, and that `/transactions/script` recognises every
//! `scriptPubKey` this endpoint emits. Those hold for any key, so they catch a
//! wrong address without a table of addresses to maintain.

mod common;

use axum::http::StatusCode;
use common::{
    assert_error, assert_transport_contract, message, post_json, post_json_headers, post_ok,
};
use serde_json::{Value, json};

const GENERATE_URI: &str = "/keys/generate";
const PUBLIC_URI: &str = "/keys/public";

/// The published key→address worked example.
const KEY: &str = "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd";
const COMPRESSED_ADDRESS: &str = "1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy";
const UNCOMPRESSED_ADDRESS: &str = "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x";

async fn public_key(request: Value) -> Value {
    post_ok(PUBLIC_URI, &request).await
}

fn for_key(private_key: &str) -> Value {
    json!({ "privateKey": private_key })
}

#[tokio::test]
async fn generates_a_key_with_every_rendering_of_it() {
    let body = post_ok(GENERATE_URI, &json!({})).await;

    assert_eq!(body["network"], "mainnet", "the documented default");
    assert_eq!(body["compressed"], json!(true), "the documented default");

    let key = &body["privateKey"];
    let hex = key["hex"].as_str().expect("hex");
    assert_eq!(hex.len(), 64, "the 32-byte field, zero-padded: {hex}");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

    // A compressed mainnet WIF starts with K or L, always — the payload's
    // fixed length and version byte leave no room for anything else.
    let wif = key["wif"].as_str().expect("a wif");
    assert!(
        wif.starts_with('K') || wif.starts_with('L'),
        "a compressed mainnet WIF: {wif}"
    );

    // The numeric views are the same value in another base, so they have to
    // agree with the field.
    let decimal = key["decimal"].as_str().expect("decimal");
    assert!(decimal.chars().all(|c| c.is_ascii_digit()) && !decimal.is_empty());
    let binary = key["binary"].as_str().expect("binary");
    assert!(binary.chars().all(|c| c == '0' || c == '1'));
    assert!(
        binary.len() <= 256 && binary.len() > 200,
        "256 bits less the leading zeros a number drops: {}",
        binary.len()
    );
}

/// The body is a credential, so it must not be stored. This is the only
/// header in the API that is part of an endpoint's contract, and the only
/// control the API itself can assert over a response that carries a secret.
#[tokio::test]
async fn the_secret_response_forbids_caching() {
    let headers = post_json_headers(GENERATE_URI, &json!({})).await;
    assert_eq!(
        headers
            .get("cache-control")
            .map(|v| v.to_str().expect("ascii")),
        Some("no-store")
    );

    // …and its sibling does not need it, which is the whole point of the
    // split: nothing in that response is secret.
    let headers = post_json_headers(PUBLIC_URI, &for_key(KEY)).await;
    assert!(
        headers.get("cache-control").is_none(),
        "a public response has nothing to withhold"
    );
}

/// Not a test of the RNG — that is not this suite's to prove. It rules out the
/// failure that would matter: an endpoint that returns a constant.
#[tokio::test]
async fn two_calls_return_two_keys() {
    let a = post_ok(GENERATE_URI, &json!({})).await;
    let b = post_ok(GENERATE_URI, &json!({})).await;
    assert_ne!(a["privateKey"]["hex"], b["privateKey"]["hex"]);
    assert_ne!(a["privateKey"]["wif"], b["privateKey"]["wif"]);
}

#[tokio::test]
async fn the_flags_change_what_is_generated() {
    let body = post_ok(
        GENERATE_URI,
        &json!({ "network": "testnet", "compressed": false }),
    )
    .await;

    assert_eq!(body["network"], "testnet");
    assert_eq!(body["compressed"], json!(false));
    let wif = body["privateKey"]["wif"].as_str().expect("a wif");
    assert!(
        wif.starts_with('9'),
        "an uncompressed testnet WIF starts with 9: {wif}"
    );
}

/// A generated key has to be readable by the other endpoint. The two are only
/// useful together, and this is the seam.
#[tokio::test]
async fn a_generated_key_derives_through_the_other_endpoint() {
    let generated = post_ok(GENERATE_URI, &json!({ "network": "testnet" })).await;
    let hex = generated["privateKey"]["hex"].as_str().expect("hex");

    let derived = public_key(json!({ "privateKey": hex, "network": "testnet" })).await;
    assert_eq!(derived["network"], "testnet");
    assert!(
        derived["addresses"]["p2pkh"]["address"]
            .as_str()
            .expect("an address")
            .starts_with('m')
            || derived["addresses"]["p2pkh"]["address"]
                .as_str()
                .expect("an address")
                .starts_with('n'),
        "a testnet P2PKH address: {derived}"
    );
}

#[tokio::test]
async fn derives_the_worked_example() {
    let body = public_key(for_key(KEY)).await;

    assert_eq!(
        body["publicKey"]["compressed"],
        "03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a"
    );
    assert_eq!(
        body["publicKey"]["uncompressed"],
        "04f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a\
         07cf33da18bd734c600b96a72bbc4749d5141c90ec8ac328ae52ddfe2e505bdb"
    );
    assert_eq!(
        body["publicKey"]["hex"], body["publicKey"]["compressed"],
        "compressed is the default, so it is the serialization in use"
    );
    assert_eq!(
        body["publicKey"]["xOnly"],
        "f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a"
    );
    assert_eq!(body["publicKey"]["x"], body["publicKey"]["xOnly"]);
    assert_eq!(
        body["publicKey"]["y"],
        "07cf33da18bd734c600b96a72bbc4749d5141c90ec8ac328ae52ddfe2e505bdb"
    );
    assert_eq!(body["addresses"]["p2pkh"]["address"], COMPRESSED_ADDRESS);
}

/// The secret goes in and does not come back. One endpoint in this API returns
/// a private key in a *success* response, and it is not this one.
///
/// The narrow exception, which is why that sentence says "success": send the
/// key as a JSON number and axum's 422 echoes the value it could not parse. A
/// 256-bit key cannot survive a JSON number anyway, so what leaks is a
/// truncated integer the caller already holds — but the property is written
/// down in several places, so the exception belongs beside it.
#[tokio::test]
async fn the_response_contains_no_secret() {
    let body = public_key(for_key(KEY)).await;
    let rendered = body.to_string();

    assert!(!rendered.contains(KEY), "the key itself came back: {body}");
    assert!(
        body.get("privateKey").is_none() && !rendered.contains("wif"),
        "no private key field, under any name: {body}"
    );
}

/// The same scalar, two flags, two sets of addresses — the mistake this
/// endpoint exists to make visible.
#[tokio::test]
async fn compression_changes_every_address() {
    let compressed = public_key(for_key(KEY)).await;
    let uncompressed = public_key(json!({ "privateKey": KEY, "compressed": false })).await;

    assert_eq!(
        compressed["addresses"]["p2pkh"]["address"],
        COMPRESSED_ADDRESS
    );
    assert_eq!(
        uncompressed["addresses"]["p2pkh"]["address"],
        UNCOMPRESSED_ADDRESS
    );
    assert_eq!(
        uncompressed["publicKey"]["hex"], uncompressed["publicKey"]["uncompressed"],
        "the serialization in use follows the flag"
    );
}

/// BIP143 makes an uncompressed key invalid inside a v0 witness, so those two
/// addresses do not exist — and the response says which and why rather than
/// leaving two bare nulls.
#[tokio::test]
async fn an_uncompressed_key_has_no_segwit_v0_address() {
    let body = public_key(json!({ "privateKey": KEY, "compressed": false })).await;
    let addresses = &body["addresses"];

    assert!(addresses["p2pkh"]["address"].is_string());
    assert_eq!(addresses["p2wpkh"], Value::Null);
    assert_eq!(addresses["p2shP2wpkh"], Value::Null);
    assert_eq!(
        body["p2wpkhRedeemScript"],
        Value::Null,
        "the redeem script goes with them, and says so the same way"
    );
    assert!(
        addresses["note"]
            .as_str()
            .expect("a note explaining the nulls")
            .contains("BIP143"),
        "{addresses}"
    );

    // Taproot uses only the x coordinate, so the flag has nothing to say
    // about it — this one is still here.
    assert!(
        addresses["p2tr"]["address"]
            .as_str()
            .expect("a taproot address")
            .starts_with("bc1p"),
        "{addresses}"
    );
    assert!(
        compressed_note_absent(&public_key(for_key(KEY)).await),
        "a compressed key has nothing to explain"
    );
}

fn compressed_note_absent(body: &Value) -> bool {
    body["addresses"].get("note").is_none()
}

/// Every address is shown as its pieces, which is the point of the tool: an
/// address is not an opaque string.
#[tokio::test]
async fn every_address_is_split_into_its_parts() {
    let body = public_key(for_key(KEY)).await;
    let addresses = &body["addresses"];

    let p2pkh = &addresses["p2pkh"];
    assert_eq!(p2pkh["base58"]["version"], json!(0), "mainnet P2PKH");
    assert_eq!(p2pkh["base58"]["versionHex"], "00");
    assert_eq!(
        p2pkh["base58"]["hash"], body["publicKey"]["pubkeyHash"],
        "a P2PKH address commits to exactly the key's hash"
    );
    assert_eq!(
        p2pkh["base58"]["checksum"]
            .as_str()
            .expect("a checksum")
            .len(),
        8,
        "four bytes"
    );
    assert!(p2pkh.get("bech32").is_none(), "base58 is not bech32");

    // A P2SH-wrapped witness program is a P2SH address and nothing else from
    // outside — version 5, and a hash of the redeem script rather than of the
    // key.
    let nested = &addresses["p2shP2wpkh"];
    assert_eq!(nested["base58"]["version"], json!(5));
    assert!(
        nested["address"]
            .as_str()
            .expect("an address")
            .starts_with('3'),
        "{nested}"
    );
    assert_ne!(
        nested["base58"]["hash"], body["publicKey"]["pubkeyHash"],
        "it commits to the redeem script, not to the key"
    );

    let native = &addresses["p2wpkh"];
    assert_eq!(native["bech32"]["hrp"], "bc");
    assert_eq!(native["bech32"]["witnessVersion"], json!(0));
    assert_eq!(
        native["bech32"]["program"], body["publicKey"]["pubkeyHash"],
        "the witness program is the same twenty bytes P2PKH commits to"
    );
    assert_eq!(
        native["bech32"]["checksum"]
            .as_str()
            .expect("a checksum")
            .len(),
        6,
        "six characters, not bytes"
    );
    assert!(native.get("base58").is_none());

    let taproot = &addresses["p2tr"];
    assert_eq!(taproot["bech32"]["witnessVersion"], json!(1));
    assert_eq!(
        taproot["bech32"]["program"]
            .as_str()
            .expect("a program")
            .len(),
        64,
        "thirty-two bytes"
    );
    assert_ne!(
        taproot["bech32"]["program"], body["publicKey"]["xOnly"],
        "the output key is the internal key tweaked, not the internal key"
    );
}

/// Each address carries the `scriptPubKey` it is a way of writing, and the
/// script endpoint has to recognise every one of them.
#[tokio::test]
async fn the_script_pubkeys_are_what_the_script_endpoint_reads_back() {
    let body = public_key(for_key(KEY)).await;

    for (name, kind) in [
        ("p2pkh", "P2PKH"),
        ("p2shP2wpkh", "P2SH"),
        ("p2wpkh", "P2WPKH"),
        ("p2tr", "P2TR"),
    ] {
        let script = body["addresses"][name]["scriptPubkey"]
            .as_str()
            .unwrap_or_else(|| panic!("{name} has no scriptPubkey: {body}"));
        let analysed = post_ok("/transactions/script", &json!({ "script": script })).await;
        assert_eq!(analysed["kind"], kind, "{name} -> {script}");
    }
}

/// BIP49's redeem script is not recoverable from the address — the address is
/// its hash — so a tool showing one without the other shows half of what is
/// needed to spend.
#[tokio::test]
async fn the_bip49_redeem_script_is_returned_beside_the_address() {
    let body = public_key(for_key(KEY)).await;
    let redeem = body["p2wpkhRedeemScript"]
        .as_str()
        .expect("a redeem script");

    assert!(redeem.starts_with("0014"), "OP_0, push 20: {redeem}");
    assert_eq!(
        &redeem[4..],
        body["publicKey"]["pubkeyHash"].as_str().expect("a hash"),
        "…pushing exactly the pubkey hash"
    );
}

#[tokio::test]
async fn a_private_key_is_thirty_two_bytes_in_both_directions() {
    for (label, key, got) in [
        ("one short", &KEY[..62], 31),
        ("one long", &format!("{KEY}00")[..], 33),
    ] {
        let body = assert_error(
            post_json(PUBLIC_URI, &for_key(key).to_string()).await,
            StatusCode::BAD_REQUEST,
            "invalid-private-key",
        );
        assert!(
            message(&body).contains("32") && message(&body).contains(&format!("got {got}")),
            "{label}: {}",
            message(&body)
        );
    }
}

/// The right size and still not a key. A length check does not see this, and
/// the endpoint has to say something other than "wrong length".
#[tokio::test]
async fn thirty_two_bytes_can_still_be_no_key_at_all() {
    for (label, key) in [
        ("zero", "00".repeat(32)),
        (
            "the group order",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141".to_owned(),
        ),
    ] {
        let body = assert_error(
            post_json(PUBLIC_URI, &for_key(&key).to_string()).await,
            StatusCode::BAD_REQUEST,
            "invalid-private-key",
        );
        assert!(
            !message(&body).contains("32 bytes"),
            "{label}: the size was right; the message must not blame it: {}",
            message(&body)
        );
    }
}

/// The route's own cap, which fires before anything else can — including
/// `deny_unknown_fields`, since the body is never buffered to be parsed.
#[tokio::test]
async fn the_transport_cap_rejects_before_the_service_does() {
    let huge = for_key(&"00".repeat(2000));
    for uri in [GENERATE_URI, PUBLIC_URI] {
        assert_error(
            post_json(uri, &huge.to_string()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "unreadable-body",
        );
    }
}

#[tokio::test]
async fn unusable_input_gets_the_shared_vocabulary() {
    assert_error(
        post_json(PUBLIC_URI, &for_key("   ").to_string()).await,
        StatusCode::BAD_REQUEST,
        "empty-input",
    );
    assert_error(
        post_json(PUBLIC_URI, &for_key("zz").to_string()).await,
        StatusCode::BAD_REQUEST,
        "invalid-hex",
    );
}

#[tokio::test]
async fn the_request_shapes_are_enforced() {
    assert_transport_contract(GENERATE_URI, &json!({})).await;
    assert_transport_contract(PUBLIC_URI, &for_key(KEY)).await;

    // A network nobody has heard of is a typo, not something to default away.
    assert_error(
        post_json(GENERATE_URI, &json!({ "network": "mainet" }).to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );

    // `/keys/public` needs the one field it cannot default.
    assert_error(
        post_json(PUBLIC_URI, &json!({ "network": "mainnet" }).to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}
