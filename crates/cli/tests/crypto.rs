//! `crypto sign` and `crypto verify`, through the binary.

mod common;

use common::{assert_both_modes_agree, assert_usage_error, file_arg, json_of, run_err, run_ok};

const KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";
const PUBLIC: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

/// A digest, not a message. Nothing here hashes anything.
fn digest(byte: &str) -> String {
    byte.repeat(32)
}

/// The two commands are each other's inverse, which is the only end-to-end
/// check either of them has: a signature this program produces is one it
/// accepts, under the key it reported.
#[test]
fn what_sign_produces_is_what_verify_accepts() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);
    let hash = digest("ab");

    let signed = json_of(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &hash,
    ]);
    let der = signed["signature"]["der"].as_str().expect("a signature");
    let public = signed["publicKey"].as_str().expect("a key");

    assert_eq!(public, PUBLIC);

    let checked = json_of(&[
        "crypto",
        "verify",
        "--public-key",
        public,
        "--message-hash",
        &hash,
        "--signature",
        der,
    ]);

    assert_eq!(checked["valid"], true);
    assert_eq!(checked["encoding"], "der");
}

/// RFC 6979: no RNG, so the same key over the same digest is the same signature
/// every time. That is the property that makes a repeated nonce — which hands an
/// attacker the private key outright — impossible unless the digest repeats.
#[test]
fn signing_is_deterministic() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);
    let args = [
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &digest("ab"),
    ];

    assert_eq!(json_of(&args), json_of(&args), "two runs, one signature");
}

/// The length decides the encoding, and both readings of one signature verify —
/// which is what makes reporting `encoding` back useful rather than decorative.
#[test]
fn the_length_decides_the_encoding_and_both_forms_verify() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);
    let hash = digest("ab");

    let signed = json_of(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &hash,
    ]);

    for (form, expected) in [("der", "der"), ("compact", "compact")] {
        let value = signed["signature"][form].as_str().expect("a signature");
        let checked = json_of(&[
            "crypto",
            "verify",
            "--public-key",
            PUBLIC,
            "--message-hash",
            &hash,
            "--signature",
            value,
        ]);

        assert_eq!(checked["valid"], true, "{form}");
        assert_eq!(checked["encoding"], expected);
        assert_eq!(
            checked["signature"], signed["signature"],
            "one signature read two ways is one signature"
        );
    }
}

/// A `false` answer is not a failure. If this ever exits non-zero, the command
/// loses the ability to say `no` — which is the question it exists to answer.
#[test]
fn a_signature_that_does_not_verify_exits_zero() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);

    let signed = json_of(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &digest("ab"),
    ]);
    let der = signed["signature"]["der"].as_str().expect("a signature");

    // The right signature, the wrong digest.
    let checked = json_of(&[
        "crypto",
        "verify",
        "--public-key",
        PUBLIC,
        "--message-hash",
        &digest("cd"),
        "--signature",
        der,
    ]);

    assert_eq!(checked["valid"], false);
    // …and everything else is still reported, so a caller can see what was
    // actually checked.
    assert_eq!(checked["publicKey"], PUBLIC);
    assert_eq!(checked["signature"]["der"], der);
}

/// Bytes that are not a signature at all *are* a failure, and the two cases are
/// distinguishable from the exit code alone.
#[test]
fn bytes_that_are_not_a_signature_are_a_failure() {
    let stderr = run_err(&[
        "crypto",
        "verify",
        "--public-key",
        PUBLIC,
        "--message-hash",
        &digest("ab"),
        "--signature",
        "deadbeef",
    ]);

    assert!(!stderr.is_empty(), "a failure says why");
}

/// Something far too long to be DER hears about DER, not about a size cap: 72
/// bytes is a fact about the encoding rather than a policy of this program, and
/// the message a user acts on is different in each case.
#[test]
fn an_oversized_signature_is_a_signature_error_not_a_size_error() {
    let stderr = run_err(&[
        "crypto",
        "verify",
        "--public-key",
        PUBLIC,
        "--message-hash",
        &digest("ab"),
        "--signature",
        &"00".repeat(4096),
    ]);

    assert!(!stderr.contains("maximum"), "{stderr}");
}

/// The digest is 32 bytes in both directions of wrong, and the message says so
/// in the digest's own vocabulary — including *why*, since sending a message
/// where a digest was wanted is the mistake this catches.
#[test]
fn a_message_hash_of_the_wrong_width_says_what_it_wanted() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);

    let stderr = run_err(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        "abab",
    ]);

    assert!(stderr.contains("32 bytes"), "{stderr}");
    assert!(stderr.contains("digest"), "…and why: {stderr}");
    assert!(!stderr.contains("maximum"), "not a size cap: {stderr}");
}

/// Signing takes a secret and hands back none: the answer is a signature and a
/// public key, both of which are things you publish.
#[test]
fn the_signature_carries_nothing_the_key_file_held() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);
    let args = [
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &digest("ab"),
    ];

    let json = json_of(&args).to_string();
    let human = run_ok(&args);

    for output in [&json, &human] {
        assert!(!output.contains(KEY), "the key is in the output:\n{output}");
        assert!(
            !output.contains("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
            "the WIF is in the output:\n{output}"
        );
    }
}

#[test]
fn both_modes_carry_the_same_values() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);
    let hash = digest("ab");

    assert_both_modes_agree(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &hash,
    ]);

    let signed = json_of(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--message-hash",
        &hash,
    ]);
    let der = signed["signature"]["der"].as_str().expect("a signature");

    assert_both_modes_agree(&[
        "crypto",
        "verify",
        "--public-key",
        PUBLIC,
        "--message-hash",
        &hash,
        "--signature",
        der,
    ]);
}

/// A partial set of flags is a usage error, and so is mixing them with a request
/// file.
#[test]
fn a_partial_request_is_a_usage_error() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", KEY);
    let request = file_arg(
        &dir,
        "req.json",
        &format!(
            r#"{{"privateKey":"{KEY}","messageHash":"{}"}}"#,
            digest("ab")
        ),
    );

    assert_usage_error(&["crypto", "sign", "--private-key-file", &key]);
    assert_usage_error(&["crypto", "sign", "--message-hash", &digest("ab")]);
    assert_usage_error(&[
        "crypto",
        "sign",
        "--private-key-file",
        &key,
        "--input",
        &request,
    ]);
    assert_usage_error(&["crypto", "verify", "--public-key", PUBLIC]);
}

/// A request file is the API's request body, so one file drives both front ends.
#[test]
fn a_request_file_is_the_api_request_body() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let hash = digest("ab");
    let request = file_arg(
        &dir,
        "req.json",
        &format!(r#"{{"privateKey": "{KEY}", "messageHash": "{hash}"}}"#),
    );

    let json = json_of(&["crypto", "sign", "--input", &request]);
    assert_eq!(json["publicKey"], PUBLIC);
    assert_eq!(json["messageHash"], hash);
}
