//! `blocks hash` and `blocks header`, through the binary.
//!
//! The domain assertions come from `bitcoin-tools-vectors`, which is the same
//! file core checks its decoder against and the server checks its responses
//! against — so a disagreement between the three shows up here rather than in
//! someone's wallet.

mod common;

use common::{assert_both_modes_agree, assert_usage_error, json_of, run_err, run_ok};

/// Every published block header, hashed and split.
///
/// Ten headers chosen for their `bits`, walking the compact encoding down from
/// `0x1d` to `0x17` — so the target expansion is exercised at every width
/// mainnet has used, rather than only at difficulty 1.
#[test]
fn every_published_header_reproduces_its_vector() {
    let blocks = bitcoin_tools_vectors::blocks();
    assert!(!blocks.is_empty(), "the vectors loaded");

    for block in &blocks {
        let raw = block["header"].as_str().expect("a header");

        // The vector calls it `hash`; the response calls it `blockHash`. The
        // names are each front end's own and the value is the vector's.
        let hashed = json_of(&["blocks", "hash", raw]);
        assert_eq!(hashed["blockHash"], block["hash"], "{raw}");

        let split = json_of(&["blocks", "header", raw]);
        for field in [
            "version",
            "prevBlock",
            "merkleRoot",
            "time",
            "nonce",
            "target",
            "difficulty",
        ] {
            assert_eq!(split[field], block[field], "{field} of {raw}");
        }
        assert_eq!(split["blockHash"], block["hash"], "{raw}");
        assert_eq!(split["meetsTarget"], true, "a real header meets its target");

        // The vector writes `bits` as the number the header carries; the
        // response writes the eight hex digits it is written as.
        let bits = split["bits"].as_str().expect("bits is hex");
        assert_eq!(
            u32::from_str_radix(bits, 16).expect("eight hex digits"),
            u32::try_from(block["bits"].as_u64().expect("a number")).expect("a u32"),
            "bits of {raw}"
        );
    }
}

/// The two orders are the same bytes, and the pair is the answer: one is what an
/// explorer shows and the other is what the next block's header contains.
#[test]
fn the_two_hash_orders_are_the_same_bytes_reversed() {
    let genesis = bitcoin_tools_vectors::blocks()[0]["header"]
        .as_str()
        .expect("a header")
        .to_owned();

    let json = json_of(&["blocks", "hash", &genesis]);
    let display = json["blockHash"].as_str().expect("a hash");
    let wire = json["blockHashWireOrder"].as_str().expect("a hash");

    let reversed = json_of(&["converter", "reverse-bytes", wire]);
    assert_eq!(reversed["reversed"], display, "one hash, two orders");
}

#[test]
fn both_modes_carry_the_same_values() {
    let genesis = bitcoin_tools_vectors::blocks()[0]["header"]
        .as_str()
        .expect("a header")
        .to_owned();

    assert_both_modes_agree(&["blocks", "hash", &genesis]);
    assert_both_modes_agree(&["blocks", "header", &genesis]);
}

/// Both commands read the same request shape, which is what stops the two from
/// drifting apart while looking deliberate.
#[test]
fn one_request_file_drives_both_commands() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let genesis = bitcoin_tools_vectors::blocks()[0]["header"]
        .as_str()
        .expect("a header")
        .to_owned();
    let request = common::file_arg(&dir, "header.json", &format!(r#"{{"header":"{genesis}"}}"#));

    assert_eq!(
        json_of(&["blocks", "hash", "--input", &request])["blockHash"],
        json_of(&["blocks", "hash", &genesis])["blockHash"],
    );
    assert_eq!(
        json_of(&["blocks", "header", "--input", &request])["merkleRoot"],
        json_of(&["blocks", "header", &genesis])["merkleRoot"],
    );
}

/// A header is one width, so both directions of getting it wrong are one
/// mistake with one answer — carrying the size actually sent, and never the
/// size-cap vocabulary a script or a transaction would get.
#[test]
fn a_header_of_the_wrong_length_is_one_mistake_either_way() {
    for (value, bytes) in [("00", "1"), (&"00".repeat(81), "81")] {
        for command in ["hash", "header"] {
            let stderr = run_err(&["blocks", command, value]);

            assert!(
                stderr.contains(bytes),
                "the size sent is missing:\n{stderr}"
            );
            assert!(
                !stderr.contains("maximum"),
                "a fixed width is not a size cap:\n{stderr}"
            );
        }
    }
}

#[test]
fn exactly_one_source_is_required() {
    assert_usage_error(&["blocks", "hash"]);
    assert_usage_error(&["blocks", "header", "00", "--input", "-"]);
}

/// The formatted output is not a JSON dump: a `null` field is absent rather than
/// printed as `None`, which is the one place the two modes are allowed to
/// differ.
#[test]
fn an_absent_field_is_absent_from_the_formatted_output() {
    let genesis = bitcoin_tools_vectors::blocks()[0]["header"]
        .as_str()
        .expect("a header")
        .to_owned();

    let human = run_ok(&["blocks", "header", &genesis]);

    assert!(!human.contains("None"), "{human}");
    assert!(!human.contains("targetError"), "there is no error: {human}");
}
