//! End-to-end tests for `POST /hd/mnemonic` and `POST /hd/derive`.
//!
//! Derivation is checked against the published BIP49, BIP84 and BIP86 account
//! vectors from the shared vectors crate — real addresses from the standards
//! themselves, not this workspace's output.
//!
//! Generation cannot be checked that way, since the whole point is that the
//! result is unpredictable. It is checked structurally, and by the seam: a
//! mnemonic's seed, fed straight to `/hd/derive`, must produce the master key
//! the mnemonic endpoint already reported.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_vectors::{accounts, field, number};
use common::{
    assert_error, assert_transport_contract, message, post_json, post_json_headers, post_ok,
};
use serde_json::{Value, json};

const MNEMONIC_URI: &str = "/hd/mnemonic";
const DERIVE_URI: &str = "/hd/derive";

/// The seed of the account vectors' mnemonic — "abandon …  about" with an
/// empty passphrase.
///
/// Computed independently with PBKDF2-HMAC-SHA512, 2048 rounds, salt
/// `"mnemonic"`, outside this workspace; the same script reproduces BIP39's
/// own published seed for those words under the `TREZOR` passphrase, which is
/// what says the method is right. The vectors carry addresses but no seed, so
/// this constant is the bridge between them.
const SEED: &str = concat!(
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1",
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
);

async fn derived(request: Value) -> Value {
    post_ok(DERIVE_URI, &request).await
}

/// A path split into the branch above it and the index beneath — which is
/// exactly the shape `/hd/derive` takes.
fn split_path(path: &str) -> (String, usize) {
    let (branch, index) = path.rsplit_once('/').expect("a path with a last step");
    (
        branch.to_owned(),
        index.parse().expect("a normal final index"),
    )
}

/// Every published account vector, driven through the endpoint.
///
/// Each address's path is split into a branch and an index; the branch is
/// requested with enough children to reach that index, and the address at it
/// has to equal the standard's own.
#[tokio::test]
async fn reproduces_the_published_account_vectors() {
    for group in accounts() {
        let bip = number(&group, "bip", "an account group");
        let network = field(&group, "network", "an account group");

        for address in group["addresses"].as_array().expect("addresses") {
            let path = field(address, "path", "an address");
            let expected = field(address, "address", "an address");
            let (branch, index) = split_path(path);

            let body = derived(json!({
                "seed": SEED,
                "path": branch,
                "count": index + 1,
                "network": network,
            }))
            .await;

            let key = &body["keys"][index];
            assert_eq!(key["path"], path, "bip{bip}");
            assert_eq!(
                key["address"], expected,
                "bip{bip} at {path}: the purpose's own address"
            );
            assert_eq!(
                body["purpose"],
                json!(format!("bip{bip}")),
                "the path's first step names the standard"
            );
        }
    }
}

/// BIP86's vector publishes the extended keys as well as the addresses, so the
/// branch this endpoint returns is checkable rather than merely plausible.
#[tokio::test]
async fn the_branch_is_the_account_key_the_vector_publishes() {
    let group = accounts()
        .into_iter()
        .find(|g| g["bip"].as_u64() == Some(86))
        .expect("the BIP86 group");

    let account = derived(json!({
        "seed": SEED,
        "path": field(&group, "accountPath", "bip86"),
        "count": 0,
    }))
    .await;
    assert_eq!(account["branch"]["xprv"], group["accountXprv"]);
    assert_eq!(account["branch"]["xpub"], group["accountXpub"]);
    assert!(
        account["keys"].as_array().expect("an array").is_empty(),
        "count 0 asks for no children"
    );

    // …and the master, which is the same vector's root.
    let master = derived(json!({ "seed": SEED, "path": "m", "count": 0 })).await;
    assert_eq!(master["branch"]["xprv"], group["rootXprv"]);
    assert_eq!(master["branch"]["xpub"], group["rootXpub"]);
    assert_eq!(master["branch"]["depth"], json!(0));
}

/// The seam between the two endpoints: a generated seed has to root the master
/// key the generating endpoint already reported.
#[tokio::test]
async fn a_generated_seed_derives_the_master_key_it_came_with() {
    let generated = post_ok(MNEMONIC_URI, &json!({})).await;
    let seed = generated["seed"].as_str().expect("a seed");

    let derived = derived(json!({ "seed": seed, "path": "m", "count": 1 })).await;
    assert_eq!(
        derived["branch"]["xprv"], generated["masterKey"]["xprv"],
        "the same seed roots the same wallet, whichever endpoint says so"
    );
    assert_eq!(
        derived["branch"]["fingerprint"],
        generated["masterKey"]["fingerprint"]
    );
}

#[tokio::test]
async fn generates_a_mnemonic_with_its_parts() {
    let body = post_ok(MNEMONIC_URI, &json!({})).await;

    assert_eq!(body["network"], "mainnet", "the documented default");
    assert_eq!(body["passphraseUsed"], json!(false));

    let m = &body["mnemonic"];
    assert_eq!(m["wordCount"], json!(12), "the documented default");
    assert_eq!(m["entropyBits"], json!(128));
    assert_eq!(m["checksumBits"], json!(4));

    let words = m["words"].as_array().expect("words");
    assert_eq!(words.len(), 12);
    assert_eq!(
        m["phrase"].as_str().expect("a phrase").split(' ').count(),
        12,
        "the phrase is the same words, space separated"
    );
    assert_eq!(
        m["indices"].as_array().expect("indices").len(),
        12,
        "one eleven-bit index per word"
    );
    for index in m["indices"].as_array().expect("indices") {
        let index = index.as_u64().expect("a number");
        assert!(index < 2048, "the list is 2048 words: {index}");
    }
    assert_eq!(
        m["entropy"].as_str().expect("entropy").len(),
        32,
        "128 bits, hex"
    );
    assert_eq!(
        body["seed"].as_str().expect("a seed").len(),
        128,
        "64 bytes"
    );
    assert!(
        body["masterKey"]["xprv"]
            .as_str()
            .expect("an xprv")
            .starts_with("xprv"),
        "{body}"
    );
}

#[tokio::test]
async fn every_bip39_length_is_offered() {
    for (words, entropy_bits, checksum_bits) in [
        (12, 128, 4),
        (15, 160, 5),
        (18, 192, 6),
        (21, 224, 7),
        (24, 256, 8),
    ] {
        let body = post_ok(MNEMONIC_URI, &json!({ "wordCount": words })).await;
        let m = &body["mnemonic"];
        assert_eq!(m["wordCount"], json!(words));
        assert_eq!(m["entropyBits"], json!(entropy_bits));
        assert_eq!(m["checksumBits"], json!(checksum_bits));
        assert_eq!(m["words"].as_array().expect("words").len(), words);
    }
}

/// The passphrase changes the seed and nothing else, and is never echoed.
#[tokio::test]
async fn the_passphrase_is_reported_but_not_returned() {
    let body = post_ok(MNEMONIC_URI, &json!({ "passphrase": "hunter2" })).await;

    assert_eq!(body["passphraseUsed"], json!(true));
    assert!(
        !body.to_string().contains("hunter2"),
        "the passphrase came back: {body}"
    );
}

#[tokio::test]
async fn two_calls_return_two_wallets() {
    let a = post_ok(MNEMONIC_URI, &json!({})).await;
    let b = post_ok(MNEMONIC_URI, &json!({})).await;
    assert_ne!(a["mnemonic"]["phrase"], b["mnemonic"]["phrase"]);
    assert_ne!(a["seed"], b["seed"]);
}

/// Both endpoints hand over a wallet, so both must forbid caching — and their
/// neighbour in `/keys` must not, which is what keeps the header meaningful.
#[tokio::test]
async fn the_secret_responses_forbid_caching() {
    for (uri, body) in [
        (MNEMONIC_URI, json!({})),
        (DERIVE_URI, json!({ "seed": SEED, "path": "m" })),
    ] {
        let headers = post_json_headers(uri, &body).await;
        assert_eq!(
            headers
                .get("cache-control")
                .map(|v| v.to_str().expect("ascii")),
            Some("no-store"),
            "{uri}"
        );
    }
}

/// A path that names no standard is not an error — `m/0/1` is a valid path
/// that simply says nothing about what to pay to.
#[tokio::test]
async fn a_path_without_a_purpose_still_derives() {
    let body = derived(json!({ "seed": SEED, "path": "m/0/1", "count": 2 })).await;

    assert_eq!(body["purpose"], Value::Null);
    assert_eq!(body["keys"][0]["address"], Value::Null, "nothing to pick");
    assert_eq!(body["keys"][0]["path"], "m/0/1/0");
    assert!(
        body["keys"][0]["addresses"]["p2pkh"]["address"].is_string(),
        "…but all four candidates are still there: {body}"
    );
}

/// Every derived key carries its private half, which is the difference between
/// this endpoint and a watch-only view.
#[tokio::test]
async fn each_key_carries_its_private_half_and_its_addresses() {
    let body = derived(json!({
        "seed": SEED, "path": "m/84'/0'/0'/0", "count": 1
    }))
    .await;
    let key = &body["keys"][0];

    assert_eq!(key["index"], json!(0));
    assert_eq!(
        key["privateKey"]["hex"].as_str().expect("hex").len(),
        64,
        "32 bytes"
    );
    let wif = key["privateKey"]["wif"].as_str().expect("a wif");
    assert!(
        wif.starts_with('K') || wif.starts_with('L'),
        "BIP32 keys are always compressed: {wif}"
    );
    assert_eq!(
        key["publicKey"].as_str().expect("a public key").len(),
        66,
        "compressed"
    );
    assert_eq!(
        key["addresses"]["p2wpkh"]["bech32"]["program"], key["pubkeyHash"],
        "the witness program is the key's own hash"
    );
    assert_eq!(
        key["address"], key["addresses"]["p2wpkh"]["address"],
        "a BIP84 path means the native segwit one"
    );
}

#[tokio::test]
async fn start_index_pages_through_an_account() {
    let paged = derived(json!({
        "seed": SEED, "path": "m/84'/0'/0'/0", "count": 2, "startIndex": 1
    }))
    .await;
    let straight = derived(json!({
        "seed": SEED, "path": "m/84'/0'/0'/0", "count": 3
    }))
    .await;

    assert_eq!(paged["keys"][0]["index"], json!(1));
    assert_eq!(paged["keys"][0]["address"], straight["keys"][1]["address"]);
    assert_eq!(paged["keys"][1]["address"], straight["keys"][2]["address"]);
}

#[tokio::test]
async fn each_input_reports_its_own_failure() {
    let body = assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": SEED, "path": "m/84'/nope/0'" }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-derivation-path",
    );
    assert!(message(&body).contains("step 2"), "{body}");

    // A seed below the floor, which is a security rule rather than an
    // encoding one.
    let body = assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": "00".repeat(15), "path": "m" }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-seed",
    );
    assert!(message(&body).contains("16"), "{body}");

    // …and above the ceiling it is the same slug, because it is the same rule.
    let body = assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": "00".repeat(65), "path": "m" }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-seed",
    );
    assert!(message(&body).contains("65"), "{body}");

    assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": SEED, "path": "m", "count": 101 }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "too-many-keys",
    );

    assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": SEED, "path": "m", "count": 2, "startIndex": 2_147_483_647u32 })
                .to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "index-out-of-range",
    );

    assert_error(
        post_json(MNEMONIC_URI, &json!({ "wordCount": 13 }).to_string()).await,
        StatusCode::BAD_REQUEST,
        "invalid-word-count",
    );
}

#[tokio::test]
async fn unusable_input_gets_the_shared_vocabulary() {
    assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": "  ", "path": "m" }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "empty-input",
    );
    assert_error(
        post_json(
            DERIVE_URI,
            &json!({ "seed": "zz", "path": "m" }).to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "invalid-hex",
    );
}

#[tokio::test]
async fn the_transport_cap_rejects_before_the_service_does() {
    let huge = json!({ "seed": "00".repeat(2000), "path": "m" });
    for uri in [MNEMONIC_URI, DERIVE_URI] {
        assert_error(
            post_json(uri, &huge.to_string()).await,
            StatusCode::PAYLOAD_TOO_LARGE,
            "unreadable-body",
        );
    }
}

#[tokio::test]
async fn the_request_shapes_are_enforced() {
    assert_transport_contract(MNEMONIC_URI, &json!({})).await;
    assert_transport_contract(DERIVE_URI, &json!({ "seed": SEED, "path": "m" })).await;

    // `/hd/derive` needs the two fields it cannot default.
    assert_error(
        post_json(DERIVE_URI, &json!({ "path": "m" }).to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
    assert_error(
        post_json(DERIVE_URI, &json!({ "seed": SEED }).to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}
