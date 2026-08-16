//! `keys generate` and `keys public`, through the binary.

mod common;

use common::{assert_both_modes_agree, assert_usage_error, bt, file_arg, json_of, run_err, run_ok};

/// The private key BIP32 and half the internet use as the smallest legal one.
const ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";

/// What that key produces on mainnet, compressed.
const PUBLIC: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const P2PKH: &str = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH";
const P2WPKH: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

/// **The** rule of this crate's secret handling, asserted against the argument
/// surface rather than against a comment.
///
/// If a flag taking the key itself is ever added, every user who types it puts a
/// private key into `ps` and into their shell history, and neither is something
/// they can take back. So this greps the *help* — which is generated from the
/// arguments — for a flag that would carry one.
#[test]
fn no_command_offers_a_flag_that_carries_a_secret() {
    let forbidden = [
        "--private-key ",
        "--private-key=",
        "--seed ",
        "--seed=",
        "--passphrase ",
        "--passphrase=",
        "--mnemonic ",
    ];

    for command in [
        vec!["keys", "public"],
        vec!["keys", "generate"],
        vec!["crypto", "sign"],
        vec!["hd", "derive"],
        vec!["hd", "mnemonic"],
    ] {
        let mut args = command.clone();
        args.push("--help");
        let help = run_ok(&args);

        for flag in forbidden {
            assert!(
                !help.contains(flag),
                "{command:?} offers {flag:?}, which puts a secret in argv:\n{help}"
            );
        }
    }
}

/// A key read from a file produces the answer that key is known to produce.
#[test]
fn a_key_from_a_file_produces_its_known_addresses() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", ONE);

    let json = json_of(&["keys", "public", "--private-key-file", &key]);

    assert_eq!(json["publicKey"]["hex"], PUBLIC);
    assert_eq!(json["addresses"]["p2pkh"]["address"], P2PKH);
    assert_eq!(json["addresses"]["p2wpkh"]["address"], P2WPKH);
    assert_eq!(json["network"], "mainnet", "the default");
    assert_eq!(json["compressed"], true, "the default");
}

/// `-` is stdin, which is the form a script uses so the key never touches disk.
#[test]
fn a_key_can_arrive_on_stdin() {
    let output = bt()
        .args(["keys", "public", "--private-key-file", "-", "--json"])
        .write_stdin(ONE)
        .assert()
        .success();

    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("one JSON value");

    assert_eq!(json["publicKey"]["hex"], PUBLIC);
}

/// The trailing newline `echo` leaves is not a different key.
#[test]
fn a_trailing_newline_in_the_key_file_is_ignored() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let plain = file_arg(&dir, "plain.hex", ONE);
    let with_newline = file_arg(&dir, "newline.hex", &format!("  0x{ONE}\n"));

    assert_eq!(
        json_of(&["keys", "public", "--private-key-file", &plain]),
        json_of(&["keys", "public", "--private-key-file", &with_newline]),
    );
}

/// This command takes a secret and hands back none. The header the API sets to
/// say so has no CLI equivalent, so the property is asserted directly.
#[test]
fn the_private_key_is_never_echoed_back() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", ONE);
    let args = ["keys", "public", "--private-key-file", &key];

    let json = json_of(&args).to_string();
    let human = run_ok(&args);

    for output in [&json, &human] {
        assert!(!output.contains(ONE), "the key is in the output:\n{output}");
        // The WIF of that key, which would be just as bad.
        assert!(
            !output.contains("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn"),
            "the WIF is in the output:\n{output}"
        );
    }
}

/// The two flags that change what the answer *is* both do.
#[test]
fn the_network_and_the_compression_flag_change_the_answer() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", ONE);

    let testnet = json_of(&[
        "keys",
        "public",
        "--private-key-file",
        &key,
        "--network",
        "testnet",
    ]);
    assert_eq!(testnet["network"], "testnet");
    assert_ne!(testnet["addresses"]["p2pkh"]["address"], P2PKH);

    let uncompressed = json_of(&[
        "keys",
        "public",
        "--private-key-file",
        &key,
        "--uncompressed",
    ]);
    assert_eq!(uncompressed["compressed"], false);
    assert!(
        uncompressed["addresses"]["p2wpkh"].is_null(),
        "BIP143 forbids an uncompressed key in a v0 program"
    );
    assert!(
        uncompressed["addresses"]["note"]
            .as_str()
            .is_some_and(|note| note.contains("BIP143")),
        "…and the reason is stated once: {uncompressed}"
    );
}

/// Every value the JSON carries reaches the formatted output too — including the
/// address parts, which are three levels down.
#[test]
fn both_modes_carry_the_same_values() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", ONE);

    assert_both_modes_agree(&["keys", "public", "--private-key-file", &key]);
}

/// `keys generate` cannot be checked by running it twice — that is two keys — so
/// its two modes are pinned against a stated field list instead.
///
/// Two lists, not one: a field added to the JSON and not to the formatted output
/// fails the second assertion, and the reverse fails the first. That is the same
/// property `both_modes_carry_the_same_values` has, bought the only way a
/// generator allows.
#[test]
fn a_generated_key_reaches_both_modes_in_full() {
    let json = json_of(&["keys", "generate"]);

    let mut top: Vec<&str> = json
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    top.sort_unstable();
    assert_eq!(top, ["compressed", "network", "privateKey"]);

    let mut inner: Vec<&str> = json["privateKey"]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    inner.sort_unstable();
    assert_eq!(inner, ["binary", "decimal", "hex", "wif"]);

    let human = run_ok(&["keys", "generate"]);
    for label in ["network", "compressed", "wif", "hex", "decimal", "binary"] {
        assert!(
            human.lines().any(|line| line.starts_with(label)),
            "no {label} row:\n{human}"
        );
    }
}

/// A generated key is a *new* key each time, and a usable one.
#[test]
fn a_generated_key_is_new_and_round_trips_to_its_own_addresses() {
    let first = json_of(&["keys", "generate"]);
    let second = json_of(&["keys", "generate"]);

    assert_ne!(
        first["privateKey"]["hex"], second["privateKey"]["hex"],
        "two runs produced one key"
    );

    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(
        &dir,
        "generated.hex",
        first["privateKey"]["hex"]
            .as_str()
            .expect("hex is a string"),
    );

    // The generated key is one `keys public` accepts, which is the only way to
    // know the two commands agree about what a key is.
    let derived = json_of(&["keys", "public", "--private-key-file", &key]);
    assert_eq!(derived["compressed"], first["compressed"]);
}

/// The two source flags are mutually exclusive, and one of them is required.
#[test]
fn exactly_one_source_is_a_usage_error_to_get_wrong() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let key = file_arg(&dir, "key.hex", ONE);
    let request = file_arg(&dir, "req.json", &format!(r#"{{"privateKey":"{ONE}"}}"#));

    assert_usage_error(&["keys", "public"]);
    // `--input` carries the network and the compression flag too, so giving
    // either beside it must be refused rather than silently dropped: a request
    // answered for mainnet when testnet was asked for exits 0, which is the
    // worst shape a failure takes.
    assert_usage_error(&[
        "keys",
        "public",
        "--input",
        &request,
        "--network",
        "testnet",
    ]);
    assert_usage_error(&["keys", "public", "--input", &request, "--uncompressed"]);
    assert_usage_error(&[
        "keys",
        "public",
        "--private-key-file",
        &key,
        "--input",
        &request,
    ]);
    assert_usage_error(&[
        "keys",
        "generate",
        "--input",
        &request,
        "--network",
        "testnet",
    ]);
}

/// A request file is the API's request body, so one file drives both front ends.
#[test]
fn a_request_file_is_the_api_request_body() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let request = file_arg(
        &dir,
        "req.json",
        &format!(r#"{{"privateKey": "{ONE}", "network": "testnet", "compressed": false}}"#),
    );

    let json = json_of(&["keys", "public", "--input", &request]);

    assert_eq!(json["network"], "testnet");
    assert_eq!(json["compressed"], false);
}

/// A key of the wrong width hears about the key, not about a size cap — and the
/// message says which way it was wrong.
#[test]
fn a_key_of_the_wrong_width_says_so_in_the_keys_own_vocabulary() {
    let dir = tempfile::tempdir().expect("a temp dir");

    for (contents, bytes) in [("01", "1"), (&"01".repeat(40), "40")] {
        let key = file_arg(&dir, "wrong.hex", contents);
        let stderr = run_err(&["keys", "public", "--private-key-file", &key]);

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

/// A rejected key is not echoed into stderr, which gets redirected into logs far
/// more often than `argv` gets read.
#[test]
fn a_rejected_key_is_not_printed_back() {
    let dir = tempfile::tempdir().expect("a temp dir");
    // 32 bytes, and not a scalar: the group order itself.
    let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    let key = file_arg(&dir, "order.hex", order);

    let stderr = run_err(&["keys", "public", "--private-key-file", &key]);

    assert!(
        !stderr.contains(order),
        "the value was echoed back:\n{stderr}"
    );
}
