//! End-to-end tests for `POST /crypto/sign` and `POST /crypto/verify`.
//!
//! Signing is pinned byte for byte against the seven published RFC 6979
//! vectors — deterministic signing is what makes that possible at all.
//!
//! Verification runs the whole Wycheproof suite through the endpoint: 476
//! cases, 308 of which must be refused. `core` already proves its verifier
//! against them, so what this adds is a test of the *server's* own decision —
//! the length rule that tells a compact signature from a DER one. That rule is
//! this layer's invention, and 308 adversarial encodings are exactly what
//! would catch it routing one of them to the wrong parser.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_core::hashes::sha256;
use bitcoin_tools_core::hex;
use bitcoin_tools_vectors as vectors;
use bitcoin_tools_vectors::field;
use common::{
    assert_error, assert_transport_contract, message, post_json, post_json_headers, post_ok,
};
use serde_json::json;

const SIGN_URI: &str = "/crypto/sign";
const VERIFY_URI: &str = "/crypto/verify";

/// The first RFC 6979 vector, for the cases that do not need all seven.
const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const HASH: &str = "06ef2b193b83b3d701f765f1db34672ab84897e1252343cc2197829af3a30456";

/// Every published signing vector, byte for byte.
///
/// The DER *and* the compact form, because the endpoint reports both and a
/// caller may take either to a different tool.
#[tokio::test]
async fn signs_every_published_vector() {
    let set = vectors::ecdsa();
    assert_eq!(set.len(), 7, "the published RFC 6979 set");

    for (i, vector) in set.iter().enumerate() {
        let at = format!("ecdsa[{i}]");
        let body = post_ok(
            SIGN_URI,
            &json!({
                "privateKey": field(vector, "privateKey", &at),
                "messageHash": field(vector, "messageHash", &at),
            }),
        )
        .await;

        assert_eq!(body["signature"]["der"], vector["der"], "{at}");
        assert_eq!(body["signature"]["compact"], vector["compact"], "{at}");
        assert_eq!(body["signature"]["r"], vector["r"], "{at}");
        assert_eq!(body["signature"]["s"], vector["s"], "{at}");
        assert_eq!(body["publicKey"], vector["publicKey"], "{at}");
        assert_eq!(
            body["signature"]["isLowS"],
            json!(true),
            "{at}: this signer always emits low-s"
        );
    }
}

/// RFC 6979's whole point, over HTTP: no RNG, so the same request is the same
/// answer. An endpoint that signed with entropy could not promise this, and a
/// repeated nonce hands over the private key.
#[tokio::test]
async fn signing_is_deterministic() {
    let request = json!({ "privateKey": KEY, "messageHash": HASH });
    let a = post_ok(SIGN_URI, &request).await;
    let b = post_ok(SIGN_URI, &request).await;
    assert_eq!(a["signature"], b["signature"]);
}

/// Every hex field this API returns is lowercase, and the echoed hash is no
/// exception — it is the digest that was signed, not the spelling it arrived
/// in.
#[tokio::test]
async fn the_echoed_hash_is_canonical_not_the_callers_spelling() {
    let body = post_ok(
        SIGN_URI,
        &json!({ "privateKey": KEY, "messageHash": HASH.to_uppercase() }),
    )
    .await;

    assert_eq!(body["messageHash"], HASH);
    assert_eq!(
        body["signature"],
        post_ok(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await["signature"],
        "…and the case never reached the digest"
    );
}

/// A field a caller can set and never observe is a promise this endpoint does
/// not make, so `network` is not accepted at all.
#[tokio::test]
async fn signing_has_no_network_field() {
    assert_error(
        post_json(
            SIGN_URI,
            &json!({ "privateKey": KEY, "messageHash": HASH, "network": "testnet" }).to_string(),
        )
        .await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}

/// The two endpoints are a pair: what one produces, the other has to accept.
#[tokio::test]
async fn what_signing_produces_verification_accepts() {
    let signed = post_ok(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await;

    for form in ["der", "compact"] {
        let body = post_ok(
            VERIFY_URI,
            &json!({
                "publicKey": signed["publicKey"],
                "messageHash": HASH,
                "signature": signed["signature"][form],
            }),
        )
        .await;
        assert_eq!(body["valid"], json!(true), "{form}");
        assert_eq!(body["encoding"], form, "the length rule read it back");
        assert_eq!(
            body["signature"]["der"], signed["signature"]["der"],
            "{form}: one signature, whichever way it was written"
        );
    }
}

/// The compression flag changes the key that is reported and nothing else —
/// ECDSA signs with the scalar.
#[tokio::test]
async fn the_signature_does_not_depend_on_the_key_encoding() {
    let compressed = post_ok(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await;
    let uncompressed = post_ok(
        SIGN_URI,
        &json!({ "privateKey": KEY, "messageHash": HASH, "compressed": false }),
    )
    .await;

    assert_eq!(compressed["signature"], uncompressed["signature"]);
    assert_ne!(compressed["publicKey"], uncompressed["publicKey"]);
    assert!(
        uncompressed["publicKey"]
            .as_str()
            .expect("a key")
            .starts_with("04")
    );
}

/// The whole Wycheproof suite, through the endpoint.
///
/// 168 signatures that must verify and 308 that must be refused — either as
/// `valid: false` or as a 400, since "not a signature" and "not *this*
/// signature" are different answers and the endpoint distinguishes them.
#[tokio::test]
async fn the_wycheproof_suite_runs_through_the_endpoint() {
    let document = vectors::wycheproof_ecdsa();
    let groups = document["testGroups"].as_array().expect("test groups");
    let (mut valid, mut refused) = (0, 0);

    for group in groups {
        let key = field(&group["publicKey"], "uncompressed", "a wycheproof group");

        for test in group["tests"].as_array().expect("tests") {
            let id = test["tcId"].as_u64().expect("a case id");
            let at = format!("wycheproof[{id}]");
            let expected_valid = field(test, "result", &at) == "valid";
            let message = hex::decode(field(test, "msg", &at)).expect("hex");

            let (status, body) = post_json(
                VERIFY_URI,
                &json!({
                    "publicKey": key,
                    "messageHash": hex::encode(&sha256(&message)),
                    "signature": field(test, "sig", &at),
                })
                .to_string(),
            )
            .await;

            if expected_valid {
                assert_eq!(status, StatusCode::OK, "{at}: {body}");
                assert_eq!(body["valid"], json!(true), "{at}: must verify");
                valid += 1;
            } else {
                // Either answer is correct and they mean different things: a
                // 400 says the bytes are not a signature, a `valid: false`
                // says they are a signature that does not match.
                let rejected = status == StatusCode::BAD_REQUEST
                    || (status == StatusCode::OK && body["valid"] == json!(false));
                assert!(rejected, "{at}: must not verify, got {status} {body}");
                refused += 1;
            }
        }
    }

    assert_eq!(valid, 168, "the published count of valid signatures");
    assert_eq!(refused, 308, "…and of the ones that must be refused");
}

/// High `s` verifies, because `(r, s)` and `(r, n − s)` are one signature.
/// Low-`s` is Bitcoin's malleability policy, reported separately.
#[tokio::test]
async fn a_high_s_signature_verifies_and_says_so() {
    let document = vectors::wycheproof_ecdsa();
    let groups = document["testGroups"].as_array().expect("test groups");

    let mut seen_high_s = 0;
    for group in groups {
        let key = field(&group["publicKey"], "uncompressed", "a group");
        for test in group["tests"].as_array().expect("tests") {
            if test["result"] != "valid" {
                continue;
            }
            let at = format!("wycheproof[{}]", test["tcId"]);
            let message = hex::decode(field(test, "msg", &at)).expect("hex");
            let body = post_ok(
                VERIFY_URI,
                &json!({
                    "publicKey": key,
                    "messageHash": hex::encode(&sha256(&message)),
                    "signature": field(test, "sig", &at),
                }),
            )
            .await;

            assert_eq!(body["valid"], json!(true), "{at}");
            if body["signature"]["isLowS"] == json!(false) {
                seen_high_s += 1;
            }
        }
    }

    assert_eq!(
        seen_high_s, 72,
        "the published count of valid signatures with high s — every one \
         produced by a correct signer, and every one verifying here"
    );
}

/// A signature that does not verify is the answer, not a failure.
#[tokio::test]
async fn a_wrong_signature_is_a_two_hundred() {
    let signed = post_ok(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await;
    let mut other_hash = HASH.to_owned();
    other_hash.replace_range(0..2, "ff");

    let body = post_ok(
        VERIFY_URI,
        &json!({
            "publicKey": PUBKEY,
            "messageHash": other_hash,
            "signature": signed["signature"]["der"],
        }),
    )
    .await;
    assert_eq!(body["valid"], json!(false));
    assert!(
        body["signature"]["der"].is_string(),
        "…and the signature is still reported, since it parsed: {body}"
    );
}

#[tokio::test]
async fn each_field_reports_its_own_failure() {
    let body = assert_error(
        post_json(
            SIGN_URI,
            &json!({ "privateKey": KEY, "messageHash": &HASH[..62] }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-message-hash",
    );
    assert!(
        message(&body).contains("32") && message(&body).contains("got 31"),
        "{body}"
    );

    // A bad key reports the same slug it does at `/keys/public`.
    assert_error(
        post_json(
            SIGN_URI,
            &json!({ "privateKey": "00".repeat(32), "messageHash": HASH }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-private-key",
    );

    assert_error(
        post_json(
            VERIFY_URI,
            &json!({ "publicKey": "02ff", "messageHash": HASH, "signature": "3006020101020101" })
                .to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-public-key",
    );

    assert_error(
        post_json(
            VERIFY_URI,
            &json!({ "publicKey": PUBKEY, "messageHash": HASH, "signature": "3044ff" }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-signature",
    );
}

/// Neither response carries a secret, so neither forbids caching — the header
/// means something because it is not on everything.
#[tokio::test]
async fn neither_response_is_a_secret() {
    let signed =
        post_json_headers(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await;
    assert!(signed.get("cache-control").is_none());

    let verified = post_json_headers(
        VERIFY_URI,
        &json!({ "publicKey": PUBKEY, "messageHash": HASH, "signature": "3006020101020101" }),
    )
    .await;
    assert!(verified.get("cache-control").is_none());
}

/// The request carries a key; the response must not.
#[tokio::test]
async fn signing_does_not_echo_the_key() {
    let body = post_ok(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await;
    assert!(!body.to_string().contains(KEY), "{body}");
}

#[tokio::test]
async fn unusable_input_gets_the_shared_vocabulary() {
    assert_error(
        post_json(
            SIGN_URI,
            &json!({ "privateKey": KEY, "messageHash": "  " }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "empty-input",
    );
    assert_error(
        post_json(
            SIGN_URI,
            &json!({ "privateKey": "zz", "messageHash": HASH }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-hex",
    );
}

#[tokio::test]
async fn the_request_shapes_are_enforced() {
    assert_transport_contract(SIGN_URI, &json!({ "privateKey": KEY, "messageHash": HASH })).await;
    assert_transport_contract(
        VERIFY_URI,
        &json!({ "publicKey": PUBKEY, "messageHash": HASH, "signature": "3006020101020101" }),
    )
    .await;

    // Every field of `/crypto/verify` is required; none can be defaulted.
    for missing in ["publicKey", "messageHash", "signature"] {
        let mut request = json!({
            "publicKey": PUBKEY, "messageHash": HASH, "signature": "3006020101020101"
        });
        request.as_object_mut().expect("an object").remove(missing);
        assert_error(
            post_json(VERIFY_URI, &request.to_string()).await,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid-body",
        );
    }
}

/// The two ceilings, and which one answers.
///
/// A signature past the domain's 72 bytes is not a signature, and the caller
/// hears that — even at four kilobytes, which is where Wycheproof's
/// length-overflow cases live. Only a body past the *transport* budget gets
/// the transport's answer.
#[tokio::test]
async fn the_domain_answers_for_anything_it_can_have_an_opinion_about() {
    let body = assert_error(
        post_json(
            VERIFY_URI,
            &json!({
                "publicKey": PUBKEY,
                "messageHash": HASH,
                "signature": "00".repeat(4096),
            })
            .to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-signature",
    );
    assert!(message(&body).contains("DER"), "{body}");

    // Past the route's own cap nothing is buffered, so no service runs.
    let huge = json!({ "privateKey": "00".repeat(10_000), "messageHash": HASH });
    for uri in [SIGN_URI, VERIFY_URI] {
        assert_error(
            post_json(uri, &huge.to_string()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "unreadable-body",
        );
    }
}
