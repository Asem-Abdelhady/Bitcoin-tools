//! `transactions script`, `splitter` and `builder`, through the binary.
//!
//! The splitter's assertions come from `bitcoin-tools-vectors` — real mainnet
//! transactions, the same ones core checks its decoder against.

mod common;

use common::{assert_both_modes_agree, assert_usage_error, file_arg, json_of, run_err, run_ok};

const P2PKH_SCRIPT: &str = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";
const TXID: &str = "aa52ef52f47e26a3e0bd0e8de4b7c0e3e2d2c1b0a9f8e7d6c5b4a39281706150";

/// Every real transaction the vectors carry, split and compared field by field.
///
/// Both families: a legacy transaction has no marker, flag, witness or wtxid,
/// and a segwit one has all four. A splitter that quietly produced the same
/// shape for both would pass a suite that only checked one.
#[test]
fn every_published_transaction_reproduces_its_vector() {
    let mut checked = 0;

    for (family, txs) in [
        ("legacy", bitcoin_tools_vectors::legacy()),
        ("segwit", bitcoin_tools_vectors::segwit()),
    ] {
        assert!(!txs.is_empty(), "{family} vectors loaded");

        for tx in &txs {
            let raw = tx["rawTx"].as_str().expect("a transaction");
            let split = json_of(&["transactions", "splitter", raw]);

            assert_eq!(split["txid"], tx["txid"], "{family}");
            assert_eq!(split["version"], tx["version"], "{family}");
            assert_eq!(split["locktime"], tx["locktime"], "{family}");
            assert_eq!(split["rawTx"], raw, "{family}");

            match family {
                "segwit" => {
                    assert!(split["witness"].is_array(), "{family} has a witness");
                    assert!(split["wtxid"].is_string(), "{family} has a wtxid");
                    assert_eq!(split["marker"], "00");
                    assert_eq!(split["flag"], "01");
                }
                _ => {
                    assert!(split["witness"].is_null(), "{family} has no witness");
                    assert!(split["wtxid"].is_null(), "{family} has no wtxid");
                    assert!(split["marker"].is_null());
                }
            }

            checked += 1;
        }
    }

    assert!(checked > 1, "more than one transaction was checked");
}

/// A standard template is recognised, its parts extracted, and every
/// instruction given its offset — the three things this command exists for.
#[test]
fn a_standard_script_is_recognised_and_taken_apart() {
    let json = json_of(&["transactions", "script", P2PKH_SCRIPT]);

    assert_eq!(json["kind"], "P2PKH");
    assert_eq!(json["sizeBytes"], 25);
    assert_eq!(
        json["fields"]["pubkeyHash"],
        "751e76e8199196d454941c45d1b3a323f1433bd6"
    );
    assert_eq!(json["instructions"][0]["opcode"], "OP_DUP");
    assert_eq!(json["instructions"][0]["offset"], 0);
    assert!(json["error"].is_null(), "nothing went wrong");
}

/// The judgement call this group makes, and the reason the two commands differ:
/// a broken **script** is an answer, because showing where it broke is the
/// point; a broken **transaction** is a failure, because once field boundaries
/// stop lining up there is no partial answer to give.
#[test]
fn a_broken_script_answers_where_a_broken_transaction_fails() {
    // `OP_PUSHBYTES_20` with nothing after it.
    let json = json_of(&["transactions", "script", "14"]);

    assert!(!json["error"].is_null(), "the problem is reported");
    assert_eq!(
        json["sizeBytes"], 1,
        "…alongside everything that did decode"
    );

    let stderr = run_err(&["transactions", "splitter", "0200"]);
    assert!(!stderr.is_empty(), "a truncated transaction says why");
}

/// Every value in the splitter's output is the **bytes as they appear**, not a
/// decoded number. Rendering the version as `2` would hide the thing the command
/// exists to show.
#[test]
fn the_splitter_shows_bytes_rather_than_numbers() {
    let raw = bitcoin_tools_vectors::legacy()[0]["rawTx"]
        .as_str()
        .expect("a transaction")
        .to_owned();

    let json = json_of(&["transactions", "splitter", &raw]);
    let version = json["version"].as_str().expect("a hex field");

    assert_eq!(
        version.len(),
        8,
        "four bytes of hex, not a number: {version}"
    );
    assert!(
        json["inputs"][0]["sequence"].as_str().expect("hex").len() == 8,
        "{json}"
    );
}

/// The flags build the same transaction the request file does — which is the
/// only reason offering both is worth the surface.
#[test]
fn the_flags_and_a_request_file_build_the_same_transaction() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let request = file_arg(
        &dir,
        "tx.json",
        &format!(
            r#"{{"type":"legacy",
                 "inputs":[{{"txid":"{TXID}","vout":0}}],
                 "outputs":[{{"amount":100000,"scriptPubkey":"{P2PKH_SCRIPT}"}}]}}"#
        ),
    );

    let from_flags = json_of(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        &format!("{TXID}:0"),
        "--pay",
        &format!("100000:{P2PKH_SCRIPT}"),
    ]);
    let from_file = json_of(&["transactions", "builder", "--input", &request]);

    assert_eq!(from_flags, from_file);
    assert!(
        from_flags["wtxid"].is_null(),
        "a legacy transaction has none"
    );
}

/// A built transaction is one this program can read back — the builder and the
/// splitter agreeing about the bytes is what makes either of them trustworthy.
#[test]
fn a_built_transaction_splits_back_into_what_built_it() {
    let built = json_of(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        &format!("{TXID}:1"),
        "--pay",
        &format!("250000:{P2PKH_SCRIPT}"),
    ]);
    let raw = built["rawTx"].as_str().expect("a transaction");

    let split = json_of(&["transactions", "splitter", raw]);

    assert_eq!(split["txid"], built["txid"]);
    assert_eq!(split["outputs"][0]["scriptPubkey"], P2PKH_SCRIPT);

    // The splitter reports the bytes *as they appear*, and a txid appears in a
    // transaction reversed — so the outpoint that went in as a display-order
    // txid comes back out in wire order. That is not a discrepancy, it is the
    // fact this whole program exists to make visible.
    let wire = split["inputs"][0]["txid"].as_str().expect("a txid");
    assert_eq!(
        json_of(&["converter", "reverse-bytes", wire])["reversed"],
        TXID
    );
    assert_eq!(split["inputs"][0]["vout"], "01000000");
}

/// `--version` on this command is the transaction's, not the program's. Both
/// still work, which is the whole point of disabling the inherited flag here.
#[test]
fn the_builders_version_flag_is_the_transactions() {
    let built = json_of(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--version",
        "1",
        "--spend",
        &format!("{TXID}:0"),
        "--pay",
        &format!("100000:{P2PKH_SCRIPT}"),
    ]);

    let split = json_of(&[
        "transactions",
        "splitter",
        built["rawTx"].as_str().expect("a transaction"),
    ]);
    assert_eq!(split["version"], "01000000");

    let program = run_ok(&["--version"]);
    assert!(program.contains("bitcoin-tools"), "{program}");
}

/// A malformed argument is a usage error before the domain sees it, and the
/// message names the shape that was wanted.
#[test]
fn a_malformed_outpoint_or_payment_is_a_usage_error() {
    assert_usage_error(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        TXID,
    ]);
    assert_usage_error(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        &format!("{TXID}:0"),
        "--pay",
        // Satoshis are whole. A fractional amount is not a small one.
        &format!("0.001:{P2PKH_SCRIPT}"),
    ]);
    assert_usage_error(&["transactions", "builder", "--spend", &format!("{TXID}:0")]);
}

/// The rules the domain owns, reaching the user as failures rather than as
/// transactions no node would accept.
#[test]
fn the_domains_build_rules_are_enforced() {
    let spend = format!("{TXID}:0");
    let pay = format!("100000:{P2PKH_SCRIPT}");

    // BIP144 both ways: the flags cannot carry witness data, so `segwit` from
    // flags alone is always refused rather than silently written as legacy.
    let stderr = run_err(&[
        "transactions",
        "builder",
        "--type",
        "segwit",
        "--spend",
        &spend,
        "--pay",
        &pay,
    ]);
    assert!(!stderr.is_empty(), "segwit without a witness is refused");

    // Nothing spent, and nothing paid.
    run_err(&["transactions", "builder", "--type", "legacy", "--pay", &pay]);
    run_err(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        &spend,
    ]);

    // The same outpoint twice.
    let duplicate = run_err(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        &spend,
        "--spend",
        &spend,
        "--pay",
        &pay,
    ]);
    assert!(!duplicate.is_empty(), "a duplicated outpoint is refused");
}

/// A field-level problem names which input or output it was in, so a request
/// with six of them does not have to be bisected by hand — and names the field
/// **once**.
///
/// The position and the noun come from two places: `Located` owns "which one"
/// and the error owns "which field". They stuttered — `output 0 scriptPubkey:
/// scriptPubkey: invalid hex` — once the input error started carrying its
/// subject, and a test asserting two substrings passed straight through it. This
/// asserts the whole prefix.
#[test]
fn a_broken_field_names_its_position_once() {
    let spend = format!("{TXID}:0");
    let pay = format!("100000:{P2PKH_SCRIPT}");

    let cases: [(&[&str], &str); 3] = [
        (
            &["--type", "legacy", "--spend", &spend, "--pay", "100000:zz"],
            "output 0: scriptPubkey: ",
        ),
        (
            &["--type", "legacy", "--spend", "zz:0", "--pay", &pay],
            "input 0: txid: ",
        ),
        (
            &[
                "--type",
                "legacy",
                "--spend",
                &spend,
                "--pay",
                "100000:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeffzz",
            ],
            "output 0: scriptPubkey: ",
        ),
    ];

    for (args, expected) in cases {
        let mut argv = vec!["transactions", "builder"];
        argv.extend_from_slice(args);

        let stderr = run_err(&argv);
        let message = stderr
            .lines()
            .next()
            .expect("a failure says why")
            .trim_start_matches("error: ");

        assert!(
            message.starts_with(expected),
            "expected {expected:?}:\n{stderr}"
        );
        // The field name appears once, not twice.
        let field = expected.rsplit(": ").nth(1).expect("a field name");
        assert_eq!(
            message.matches(field).count(),
            1,
            "{field} is printed twice:\n{stderr}"
        );
    }
}

/// A witness item is inside an input, so its position needs both numbers — and
/// this is the one case where the item index has to survive the change above.
#[test]
fn a_broken_witness_item_names_the_input_and_the_item() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let request = file_arg(
        &dir,
        "tx.json",
        &format!(
            r#"{{"type":"segwit",
                 "inputs":[{{"txid":"{TXID}","vout":0,"witness":["ab","zz"]}}],
                 "outputs":[{{"amount":100000,"scriptPubkey":"{P2PKH_SCRIPT}"}}]}}"#
        ),
    );

    let stderr = run_err(&["transactions", "builder", "--input", &request]);

    assert!(stderr.contains("input 0 item 1: witness: "), "{stderr}");
}

#[test]
fn both_modes_carry_the_same_values() {
    let raw = bitcoin_tools_vectors::segwit()[0]["rawTx"]
        .as_str()
        .expect("a transaction")
        .to_owned();

    assert_both_modes_agree(&["transactions", "script", P2PKH_SCRIPT]);
    assert_both_modes_agree(&["transactions", "splitter", &raw]);
    assert_both_modes_agree(&[
        "transactions",
        "builder",
        "--type",
        "legacy",
        "--spend",
        &format!("{TXID}:0"),
        "--pay",
        &format!("100000:{P2PKH_SCRIPT}"),
    ]);
}

#[test]
fn exactly_one_source_is_required() {
    assert_usage_error(&["transactions", "script"]);
    assert_usage_error(&["transactions", "splitter", "0200", "--input", "-"]);
}
