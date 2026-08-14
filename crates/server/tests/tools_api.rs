//! End-to-end tests for `POST /tools/reverse-bytes`, `POST /tools/number` and
//! `POST /tools/units` — § 1.
//!
//! These three endpoints have no vectors of their own, and inventing a file of
//! them would only restate arithmetic. What they do have is *relations to the
//! rest of the API*, which is stronger: 1.1 is the operation relating the two
//! byte orders `/blocks/hash` already reports, so the ten mainnet headers in
//! the shared vectors crate pin it without a single expectation being written
//! down twice.

mod common;

use axum::http::StatusCode;
use bitcoin_tools_core::general::{Denomination, Number};
use bitcoin_tools_vectors::{blocks, field};
use bitcoin_tools_web_server::services::tools::reverse::MAX_BYTES;
use common::{assert_error, assert_transport_contract, message, post_json, post_ok};
use serde_json::{Value, json};

const REVERSE_URI: &str = "/tools/reverse-bytes";
const NUMBER_URI: &str = "/tools/number";
const UNITS_URI: &str = "/tools/units";

fn hex_request(hex: &str) -> Value {
    json!({ "hex": hex })
}

fn number_request(value: &str, base: &str) -> Value {
    json!({ "value": value, "base": base })
}

fn units_request(amount: &str, denomination: &str) -> Value {
    json!({ "amount": amount, "denomination": denomination })
}

fn str_at<'a>(body: &'a Value, key: &str) -> &'a str {
    body[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is a string; body = {body}"))
}

/// The keys of a JSON object, so a response can be checked for completeness
/// rather than only for the fields a test remembered to look at.
fn keys(body: &Value) -> Vec<&str> {
    body.as_object()
        .unwrap_or_else(|| panic!("an object; body = {body}"))
        .keys()
        .map(String::as_str)
        .collect()
}

// ---------------------------------------------------------------- 1.1

/// The relation that makes 1.1 checkable against something other than itself:
/// a block hash as people write it is the header's own hash reversed, and
/// `/blocks/hash` reports both. Ten mainnet headers, and neither endpoint is
/// told the other's answer.
#[tokio::test]
async fn reversing_a_block_hash_gives_the_order_the_header_carries() {
    for vector in blocks() {
        let at = format!("block {}", vector["height"]);
        let header = field(&vector, "header", &at);

        let hashed = post_ok("/blocks/hash", &json!({ "header": header })).await;
        let displayed = str_at(&hashed, "blockHash").to_owned();
        let wire = str_at(&hashed, "blockHashWireOrder").to_owned();

        let flipped = post_ok(REVERSE_URI, &hex_request(&displayed)).await;
        assert_eq!(str_at(&flipped, "reversed"), wire, "{at}");
        assert_eq!(flipped["bytes"], 32, "{at}");

        let back = post_ok(REVERSE_URI, &hex_request(&wire)).await;
        assert_eq!(
            str_at(&back, "reversed"),
            displayed,
            "{at}: and the other way round"
        );
    }
}

/// Reversal is an involution, which is why one endpoint covers both
/// directions instead of taking a `direction` field.
///
/// The `assert_ne!` is the load-bearing half. A round trip alone is satisfied
/// by an endpoint that reverses *nothing* — identity is an involution too — so
/// without it this test would pass against the one bug it exists to catch.
/// Every case is asymmetric for the same reason: a palindrome asserts nothing
/// about ordering.
#[tokio::test]
async fn reversing_twice_returns_the_original() {
    for case in [
        "abcd",
        "dead",
        "0102030405",
        "ff00ff01",
        &("00".repeat(31) + "ff"),
    ] {
        let there = post_ok(REVERSE_URI, &hex_request(case)).await;
        assert_ne!(
            str_at(&there, "reversed"),
            case,
            "{case} reversed is a different string, or this proves nothing"
        );

        let back = post_ok(REVERSE_URI, &hex_request(str_at(&there, "reversed"))).await;
        assert_eq!(str_at(&back, "reversed"), case, "round trip for {case}");
    }
}

/// The echo is the value, not the spelling — the rule `/crypto/sign` settled
/// for `messageHash`, and the reason a response can be fed straight back in.
#[tokio::test]
async fn the_input_is_echoed_as_the_server_read_it() {
    let body = post_ok(REVERSE_URI, &hex_request("  0xDEADBEEF \n")).await;
    assert_eq!(str_at(&body, "input"), "deadbeef");
    assert_eq!(str_at(&body, "reversed"), "efbeadde");
    assert_eq!(body["bytes"], 4);
}

/// Reversing bytes, not characters. `"daed"` would be the text reversed, which
/// is a different value rather than the same value the other way round.
#[tokio::test]
async fn a_reversal_moves_bytes_rather_than_digits() {
    let body = post_ok(REVERSE_URI, &hex_request("dead")).await;
    assert_eq!(str_at(&body, "reversed"), "adde");
}

#[tokio::test]
async fn unusable_hex_keeps_the_vocabulary_every_endpoint_shares() {
    assert_error(
        post_json(REVERSE_URI, &hex_request(" 0x ").to_string()).await,
        StatusCode::BAD_REQUEST,
        "empty-input",
    );
    assert_error(
        post_json(REVERSE_URI, &hex_request("abc").to_string()).await,
        StatusCode::BAD_REQUEST,
        "invalid-hex",
    );
    assert_error(
        post_json(REVERSE_URI, &hex_request("zz").to_string()).await,
        StatusCode::BAD_REQUEST,
        "invalid-hex",
    );
}

/// The cap is the largest payload this API accepts anywhere, so the tool for
/// flipping byte order is never the endpoint that refuses what another one
/// would have read — a transaction `/transactions/splitter` would decode
/// reverses here.
///
/// The route's transport budget sits above the service's cap on purpose, so
/// the *service* is what answers and the message can name the size sent.
/// `unreadable-body` would be the transport talking, and it cannot.
#[tokio::test]
async fn a_payload_past_the_cap_is_refused_by_the_service() {
    let over = "00".repeat(MAX_BYTES + 1);
    let body = assert_error(
        post_json(REVERSE_URI, &hex_request(&over).to_string()).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "input-too-large",
    );
    assert!(
        message(&body).contains(&(MAX_BYTES + 1).to_string()),
        "the size actually sent: {}",
        message(&body)
    );
}

// ---------------------------------------------------------------- 1.2

/// The case 1.2 exists for. A 256-bit value has no JSON number that holds it,
/// which is why `value` is a string in both directions.
#[tokio::test]
async fn the_group_order_converts_without_losing_a_bit() {
    let body = post_ok(
        NUMBER_URI,
        &number_request(
            "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            "hexadecimal",
        ),
    )
    .await;

    assert_eq!(
        str_at(&body, "decimal"),
        "115792089237316195423570985008687907852837564279074904382605163141518161494337"
    );
    assert_eq!(
        str_at(&body, "hexadecimal"),
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        "lowercase, and no 0x — the prefix is read, never written"
    );
    assert_eq!(body["bits"], 256);
    assert_eq!(body["bytes"], 32);
    assert_eq!(str_at(&body, "binary").len(), 256);
}

/// Why `base` has no default: the same three characters are three numbers.
#[tokio::test]
async fn the_same_digits_in_three_bases_are_three_numbers() {
    for (base, decimal) in [("binary", "2"), ("decimal", "10"), ("hexadecimal", "16")] {
        let body = post_ok(NUMBER_URI, &number_request("10", base)).await;
        assert_eq!(str_at(&body, "decimal"), decimal, "10 read as {base}");
    }
}

/// Every base the endpoint reads is a base it reports, and the keys are the
/// same tokens the request takes.
#[tokio::test]
async fn a_number_response_answers_in_every_base_it_accepts() {
    let body = post_ok(NUMBER_URI, &number_request("255", "decimal")).await;

    for base in ["binary", "decimal", "hexadecimal"] {
        let round_trip = post_ok(NUMBER_URI, &number_request(str_at(&body, base), base)).await;
        assert_eq!(
            str_at(&round_trip, "decimal"),
            "255",
            "{base} reads back as what it rendered"
        );
    }
    assert_eq!(str_at(&body, "binary"), "11111111");
    assert_eq!(str_at(&body, "hexadecimal"), "ff");
    assert_eq!(body["bits"], 8);
}

/// Zero is a number, and every renderer has to agree about it.
#[tokio::test]
async fn zero_is_one_digit_one_bit_and_one_byte() {
    let body = post_ok(NUMBER_URI, &number_request("0", "decimal")).await;
    assert_eq!(str_at(&body, "binary"), "0");
    assert_eq!(str_at(&body, "decimal"), "0");
    assert_eq!(str_at(&body, "hexadecimal"), "0");
    assert_eq!(body["bits"], 1);
    assert_eq!(body["bytes"], 1);
}

/// Leading zeros are notation, not value — so they change neither the answer
/// nor the widths reported beside it.
#[tokio::test]
async fn leading_zeros_do_not_change_a_number() {
    let padded = post_ok(NUMBER_URI, &number_request("0x00ff", "hexadecimal")).await;
    let bare = post_ok(NUMBER_URI, &number_request("ff", "hexadecimal")).await;
    assert_eq!(padded, bare);
}

/// Only the base's own prefix is stripped, so a foreign one is judged as
/// digits rather than quietly answering a different number.
#[tokio::test]
async fn a_prefix_from_another_base_is_a_digit_error() {
    let body = assert_error(
        post_json(NUMBER_URI, &number_request("0x10", "decimal").to_string()).await,
        StatusCode::BAD_REQUEST,
        "invalid-number",
    );
    assert!(
        message(&body).contains("byte 1"),
        "the offset of the bad digit: {}",
        message(&body)
    );
}

#[tokio::test]
async fn an_empty_value_and_an_oversized_one_keep_the_shared_slugs() {
    assert_error(
        post_json(NUMBER_URI, &number_request("   ", "decimal").to_string()).await,
        StatusCode::BAD_REQUEST,
        "empty-input",
    );

    let too_many = "1".repeat(Number::MAX_DIGITS + 1);
    let body = assert_error(
        post_json(
            NUMBER_URI,
            &number_request(&too_many, "decimal").to_string(),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "input-too-large",
    );
    assert!(
        message(&body).contains(&Number::MAX_DIGITS.to_string()),
        "the limit is named, which is why this reaches the service at all: {}",
        message(&body)
    );
}

/// The endpoint refuses the shape that would silently change the value.
#[tokio::test]
async fn a_value_sent_as_a_json_number_is_refused() {
    assert_error(
        post_json(NUMBER_URI, r#"{"value":10,"base":"decimal"}"#).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}

#[tokio::test]
async fn a_missing_or_unknown_base_is_refused() {
    assert_error(
        post_json(NUMBER_URI, r#"{"value":"10"}"#).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
    let body = assert_error(
        post_json(NUMBER_URI, &number_request("10", "octal").to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
    assert!(
        message(&body).contains("hexadecimal"),
        "the message lists what is accepted: {}",
        message(&body)
    );
}

// ---------------------------------------------------------------- 1.3

/// One amount, read in each unit and rendered in all four — the same 15 000
/// satoshis every time.
#[tokio::test]
async fn one_amount_is_the_same_amount_in_every_unit() {
    let expected = json!({
        "satoshi": "15000",
        "microbitcoin": "150",
        "millibitcoin": "0.15",
        "bitcoin": "0.00015",
        "isMoneyRange": true,
    });

    for (amount, denomination) in [
        ("15000", "satoshi"),
        ("150", "microbitcoin"),
        ("0.15", "millibitcoin"),
        ("0.00015", "bitcoin"),
    ] {
        let body = post_ok(UNITS_URI, &units_request(amount, denomination)).await;
        assert_eq!(body, expected, "{amount} {denomination}");
    }
}

/// The response cannot render three units and quietly forget the fourth: the
/// expected keys are generated from the domain's own list, so a denomination
/// added there without a field here fails this test rather than shipping.
#[tokio::test]
async fn a_units_response_names_every_denomination_the_domain_has() {
    let body = post_ok(UNITS_URI, &units_request("1", "bitcoin")).await;
    let present = keys(&body);

    for denomination in Denomination::all() {
        let key = serde_json::to_value(denomination).expect("a denomination serializes");
        let key = key.as_str().expect("as a string").to_owned();
        assert!(
            present.contains(&key.as_str()),
            "no {key} in {present:?} — and it is a unit the request accepts"
        );
    }
    assert_eq!(
        present.len(),
        Denomination::all().len() + 1,
        "the four units and isMoneyRange, and nothing else: {present:?}"
    );
}

/// Trailing zeros come off, so the answer is a value rather than a
/// fixed-width field.
#[tokio::test]
async fn a_whole_bitcoin_is_written_as_one() {
    let body = post_ok(UNITS_URI, &units_request("1", "bitcoin")).await;
    assert_eq!(str_at(&body, "bitcoin"), "1", "not 1.00000000");
    assert_eq!(str_at(&body, "satoshi"), "100000000");
}

/// The 21-million cap is a question the response answers, not a rejection —
/// because a malformed transaction can declare any `u64` and a tool has to be
/// able to show it.
#[tokio::test]
async fn an_impossible_amount_is_reported_rather_than_refused() {
    let over = post_ok(UNITS_URI, &units_request("21000001", "bitcoin")).await;
    assert_eq!(over["isMoneyRange"], false);
    assert_eq!(str_at(&over, "satoshi"), "2100000100000000");

    let at = post_ok(UNITS_URI, &units_request("21000000", "bitcoin")).await;
    assert_eq!(at["isMoneyRange"], true, "the cap itself is in range");
}

/// A tenth of a satoshi is not a small amount; it is not an amount. Its own
/// slug, because the fix is to drop digits rather than to retype the field.
#[tokio::test]
async fn precision_past_the_unit_is_its_own_failure() {
    let body = assert_error(
        post_json(
            UNITS_URI,
            &units_request("0.000000001", "bitcoin").to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "amount-too-precise",
    );
    assert!(
        message(&body).contains("8 decimal places"),
        "the message says how much precision the unit has: {}",
        message(&body)
    );
}

/// A trailing zero is notation, not precision, so this one is accepted — the
/// distinction the domain draws and the endpoint inherits.
#[tokio::test]
async fn one_point_zero_satoshis_is_one_satoshi() {
    let body = post_ok(UNITS_URI, &units_request("1.0", "satoshi")).await;
    assert_eq!(str_at(&body, "satoshi"), "1");

    assert_error(
        post_json(UNITS_URI, &units_request("0.1", "satoshi").to_string()).await,
        StatusCode::BAD_REQUEST,
        "amount-too-precise",
    );
}

#[tokio::test]
async fn the_amounts_that_are_not_amounts() {
    for (amount, slug) in [
        ("", "empty-input"),
        ("   ", "empty-input"),
        ("-1", "invalid-amount"),
        ("1.2.3", "invalid-amount"),
        ("1 BTC", "invalid-amount"),
        ("99999999999999999999", "amount-out-of-range"),
    ] {
        assert_error(
            post_json(UNITS_URI, &units_request(amount, "satoshi").to_string()).await,
            StatusCode::BAD_REQUEST,
            slug,
        );
    }
}

/// The refusal that matters most here: a double is how a wallet loses a
/// satoshi, and this endpoint is a *converter*.
#[tokio::test]
async fn an_amount_sent_as_a_json_number_is_refused() {
    assert_error(
        post_json(UNITS_URI, r#"{"amount":0.1,"denomination":"bitcoin"}"#).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
}

#[tokio::test]
async fn a_missing_or_unknown_denomination_is_refused() {
    assert_error(
        post_json(UNITS_URI, r#"{"amount":"1"}"#).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
    let body = assert_error(
        post_json(UNITS_URI, &units_request("1", "btc").to_string()).await,
        StatusCode::UNPROCESSABLE_ENTITY,
        "invalid-body",
    );
    // Generated rather than spelled out: `contains("bitcoin")` would be
    // satisfied by `microbitcoin` alone, so the obvious version of this
    // assertion cannot fail for the reason it names.
    for denomination in Denomination::all() {
        let name = serde_json::to_value(denomination).expect("a denomination serializes");
        let name = name.as_str().expect("as a string").to_owned();
        assert!(
            message(&body).contains(&name),
            "{name} is a unit this endpoint takes, but is missing from: {}",
            message(&body)
        );
    }
}

/// Which of the two 413s a caller gets, and where the boundary between them
/// sits.
///
/// `/tools/units` has a transport cap and a domain error that can both refuse
/// an over-long amount, and `CLAUDE.md` promises clients the distinction is
/// real: `unreadable-body` is the route turning a request away before the
/// handler runs, `amount-out-of-range` is the parser answering about a value it
/// read. Without this the cap could be any size at all and the suite would not
/// notice, because every other body here is about fifty bytes.
#[tokio::test]
async fn both_size_limits_report_which_one_was_hit() {
    let inside = assert_error(
        post_json(
            UNITS_URI,
            &units_request("99999999999999999999", "satoshi").to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "amount-out-of-range",
    );
    assert!(
        message(&inside).contains("64 bits"),
        "the domain answered about the value: {}",
        message(&inside)
    );

    // 900 digits is nonsense as an amount and still the domain's to refuse:
    // it brackets the transport cap from below, so a typo turning 1024 into
    // 100 fails here rather than silently moving where the boundary is.
    assert_error(
        post_json(
            UNITS_URI,
            &units_request(&"9".repeat(900), "satoshi").to_string(),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "amount-out-of-range",
    );

    assert_error(
        post_json(
            UNITS_URI,
            &units_request(&"9".repeat(2048), "satoshi").to_string(),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "unreadable-body",
    );
}

// ---------------------------------------------------------------- transport

#[tokio::test]
async fn every_tools_endpoint_keeps_the_transport_contract() {
    assert_transport_contract(REVERSE_URI, &hex_request("dead")).await;
    assert_transport_contract(NUMBER_URI, &number_request("10", "decimal")).await;
    assert_transport_contract(UNITS_URI, &units_request("1", "bitcoin")).await;
}

/// The path is `/tools/reverse-bytes`, and the snake_case spelling somebody
/// might guess is not quietly an alias for it.
#[tokio::test]
async fn the_multi_word_path_is_kebab_case() {
    assert_error(
        post_json("/tools/reverse_bytes", &hex_request("dead").to_string()).await,
        StatusCode::NOT_FOUND,
        "not-found",
    );
}
