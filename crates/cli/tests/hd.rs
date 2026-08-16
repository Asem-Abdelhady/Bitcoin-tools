//! `hd mnemonic` and `hd derive`, through the binary.
//!
//! The derivation assertions come from `bitcoin-tools-vectors` — BIP32's own
//! seeded vectors and BIP49/84/86's account vectors, the same files core checks
//! its own implementation against.

mod common;

use common::{
    assert_both_modes_agree_about, assert_usage_error, bt, file_arg, json_of, run_err, run_ok,
};

/// BIP32's first test vector seed.
const SEED: &str = "000102030405060708090a0b0c0d0e0f";

/// Every chain of every BIP32 vector, derived and compared to the published
/// extended keys.
///
/// This is the check that matters for an HD wallet: a derivation that is off by
/// one hardening flag produces plausible-looking keys for a wallet nobody has.
#[test]
fn every_bip32_chain_reproduces_its_vector() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut checked = 0;

    for vector in bitcoin_tools_vectors::bip32() {
        let seed = vector["seed"].as_str().expect("a seed");
        let seed_file = file_arg(&dir, "seed.hex", seed);

        for chain in vector["chains"].as_array().expect("chains") {
            let path = chain["path"].as_str().expect("a path");

            // `count 0` derives the branch and no children, which is exactly
            // what a vector names: one path, one pair of extended keys.
            let json = json_of(&[
                "hd",
                "derive",
                "--seed-file",
                &seed_file,
                "--path",
                path,
                "--count",
                "0",
            ]);

            assert_eq!(json["branch"]["xprv"], chain["xprv"], "{path} of {seed}");
            assert_eq!(json["branch"]["xpub"], chain["xpub"], "{path} of {seed}");
            assert!(json["keys"].as_array().expect("keys").is_empty());

            checked += 1;
        }
    }

    assert!(checked > 5, "{checked} chains is not the published set");
}

/// BIP49, BIP84 and BIP86's account vectors: one mnemonic, three layouts, and
/// the addresses each derives. The purpose is inferred from the path and decides
/// which of the four addresses is *the* address — getting that wrong sends money
/// to a real address in the wrong format.
///
/// # This test does something no user of this program can
///
/// The vectors start from a **mnemonic**, and nothing in the CLI takes one — so
/// the sentence is turned into a seed here, by calling core directly, before the
/// binary is run at all. That is the gap the `hd` module documents: a user who
/// kept the words and the passphrase cannot get back to their wallet with this
/// tool. When `hd seed` exists, these two lines become a command.
#[test]
fn every_account_vector_derives_its_published_addresses() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let mut checked = 0;

    for account in bitcoin_tools_vectors::accounts() {
        let phrase = account["mnemonic"].as_str().expect("a sentence");
        let passphrase = account["passphrase"].as_str().unwrap_or("");
        let network = account["network"].as_str().expect("a network");

        let mnemonic =
            bitcoin_tools_core::hd::Mnemonic::parse(phrase).expect("a published sentence");
        let seed = bitcoin_tools_core::hex::encode(&mnemonic.to_seed(passphrase));
        let seed_file = file_arg(&dir, "seed.hex", &seed);

        for entry in account["addresses"].as_array().expect("addresses") {
            let path = entry["path"].as_str().expect("a path");
            let address = entry["address"].as_str().expect("an address");

            // The vector names a leaf; derive its parent and take that child.
            let (branch, index) = path.rsplit_once('/').expect("a leaf path");
            let index: u32 = index.parse().expect("a normal index");

            let json = json_of(&[
                "hd",
                "derive",
                "--seed-file",
                &seed_file,
                "--path",
                branch,
                "--start-index",
                &index.to_string(),
                "--count",
                "1",
                "--network",
                network,
            ]);

            assert_eq!(json["keys"][0]["path"], path);
            assert_eq!(json["keys"][0]["address"], address, "{path}");

            // The private key too, where the vector carries one — an address
            // that matches under a key that does not would be worse than both
            // being wrong.
            if let Some(wif) = entry["wif"].as_str() {
                assert_eq!(json["keys"][0]["privateKey"]["wif"], wif, "{path}");
            }

            checked += 1;
        }
    }

    assert!(checked > 2, "{checked} addresses is not the published set");
}

/// `--start-index` pages through one branch rather than restarting it: the sixth
/// key of a straight run is the first key of a run starting at five.
#[test]
fn start_index_pages_through_an_account() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    let straight = json_of(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m/84h/0h/0h/0",
        "--count",
        "6",
    ]);
    let paged = json_of(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m/84h/0h/0h/0",
        "--count",
        "1",
        "--start-index",
        "5",
    ]);

    assert_eq!(straight["keys"][5], paged["keys"][0]);
    assert_eq!(paged["keys"][0]["index"], 5);
}

/// An apostrophe and an `h` mark the same thing, and `h` is the one that does
/// not need quoting in a shell — which is why the help uses it.
#[test]
fn h_and_an_apostrophe_are_one_path() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    assert_eq!(
        json_of(&[
            "hd",
            "derive",
            "--seed-file",
            &seed,
            "--path",
            "m/84h/0h/0h/0"
        ]),
        json_of(&[
            "hd",
            "derive",
            "--seed-file",
            &seed,
            "--path",
            "m/84'/0'/0'/0"
        ]),
    );
}

/// The purpose comes from the path's first step, and `address` is present only
/// when there is one.
#[test]
fn the_purpose_comes_from_the_path() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    for (path, purpose) in [
        ("m/44h/0h/0h/0", Some("bip44")),
        ("m/49h/0h/0h/0", Some("bip49")),
        ("m/84h/0h/0h/0", Some("bip84")),
        ("m/86h/0h/0h/0", Some("bip86")),
        ("m/0/1", None),
    ] {
        let json = json_of(&["hd", "derive", "--seed-file", &seed, "--path", path]);

        assert_eq!(json["purpose"].as_str(), purpose, "{path}");
        assert_eq!(
            json["keys"][0]["address"].is_null(),
            purpose.is_none(),
            "a path with no purpose names no single address: {path}"
        );
        // Every address still exists, whatever the path says.
        assert!(!json["keys"][0]["addresses"]["p2pkh"]["address"].is_null());
    }
}

/// The seed can arrive on stdin, which is how a script keeps it off disk.
#[test]
fn a_seed_can_arrive_on_stdin() {
    let output = bt()
        .args([
            "hd",
            "derive",
            "--seed-file",
            "-",
            "--path",
            "m/0",
            "--json",
        ])
        .write_stdin(SEED)
        .assert()
        .success();

    let json: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("one JSON value");

    assert_eq!(json["branch"]["path"], "m/0");
}

/// A generated sentence is a new one each time, and the seed it derives opens a
/// wallet this program can walk.
#[test]
fn a_generated_mnemonic_is_new_and_leads_to_a_derivable_wallet() {
    let first = json_of(&["hd", "mnemonic"]);
    let second = json_of(&["hd", "mnemonic"]);

    assert_ne!(first["mnemonic"]["phrase"], second["mnemonic"]["phrase"]);
    assert_eq!(first["mnemonic"]["wordCount"], 12, "the default");
    assert_eq!(first["passphraseUsed"], false, "the default");

    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", first["seed"].as_str().expect("a seed"));

    // The master key `hd mnemonic` reported is the one `hd derive` reaches from
    // the seed beside it — which is the only check that the two agree.
    let derived = json_of(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m",
        "--count",
        "0",
    ]);
    assert_eq!(derived["branch"]["xprv"], first["masterKey"]["xprv"]);
}

/// Every word count BIP39 defines, and the entropy each implies.
#[test]
fn every_word_count_carries_its_own_entropy() {
    for (words, bits) in [(12, 128), (15, 160), (18, 192), (21, 224), (24, 256)] {
        let json = json_of(&["hd", "mnemonic", "--words", &words.to_string()]);

        assert_eq!(json["mnemonic"]["wordCount"], words);
        assert_eq!(json["mnemonic"]["entropyBits"], bits);
        assert_eq!(
            json["mnemonic"]["words"].as_array().expect("words").len(),
            words
        );
    }

    // A wrong *argument* exits 2, like `--network foo` does: a scripter
    // branching on the exit code has to be able to tell "you typed a bad flag"
    // from "your data was bad".
    assert_usage_error(&["hd", "mnemonic", "--words", "13"]);
    assert_usage_error(&["hd", "mnemonic", "--words", "x"]);
}

/// A passphrase changes the seed completely, is read from a file, and is never
/// printed back — only *whether* one was used.
#[test]
fn a_passphrase_is_used_and_never_echoed() {
    let dir = tempfile::tempdir().expect("a temp dir");
    // Hyphenated on purpose. The sentence is generated, so a passphrase made of
    // wordlist words can appear in it by chance -- `horse` is a BIP39 word, and
    // asserting on it failed about one run in 170 for a leak that never
    // happened. No BIP39 sentence, hex seed or base58 key can contain `-`.
    let passphrase = "correct-horse-battery-staple-42";
    let file = file_arg(&dir, "pass.txt", passphrase);

    let args = ["hd", "mnemonic", "--passphrase-file", &file];
    let json = json_of(&args);
    let human = run_ok(&args);

    assert_eq!(json["passphraseUsed"], true);
    for output in [&json.to_string(), &human] {
        assert!(
            !output.contains(passphrase) && !output.contains("correct-horse"),
            "the passphrase was printed:\n{output}"
        );
    }
}

/// A passphrase is an arbitrary byte string and is **not** trimmed: a leading or
/// trailing space is part of the wallet.
///
/// The seed is checked against one computed here from the exact bytes, because
/// the sentence is different every run and there is nothing else to compare to.
/// Trimming made `--passphrase-file` and the equivalent `--input` field derive
/// two different seeds from one passphrase — and since the `--input` one is what
/// the HTTP API answers, a wallet generated from a file could not be restored
/// anywhere else.
#[test]
fn a_passphrase_is_used_byte_for_byte_whichever_source_it_came_through() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let passphrase = "  hunter2  ";

    let seed_of = |json: &serde_json::Value| {
        let phrase = json["mnemonic"]["phrase"].as_str().expect("a sentence");
        let mnemonic = bitcoin_tools_core::hd::Mnemonic::parse(phrase).expect("its own sentence");

        (
            json["seed"].as_str().expect("a seed").to_owned(),
            bitcoin_tools_core::hex::encode(&mnemonic.to_seed(passphrase)),
        )
    };

    let file = file_arg(&dir, "pass.txt", passphrase);
    let (reported, expected) = seed_of(&json_of(&["hd", "mnemonic", "--passphrase-file", &file]));
    assert_eq!(reported, expected, "the spaces were trimmed away");

    // `echo` appends a newline, and that one character is removed — otherwise
    // every passphrase written with `echo` would be a different wallet.
    let with_newline = file_arg(&dir, "echoed.txt", &format!("{passphrase}\n"));
    let (reported, expected) = seed_of(&json_of(&[
        "hd",
        "mnemonic",
        "--passphrase-file",
        &with_newline,
    ]));
    assert_eq!(reported, expected, "the trailing newline was kept");

    // And a passphrase that is nothing but spaces is still a passphrase.
    let spaces = file_arg(&dir, "spaces.txt", "   ");
    assert_eq!(
        json_of(&["hd", "mnemonic", "--passphrase-file", &spaces])["passphraseUsed"],
        true
    );
}

/// The seed is a fixed range, and a value past it hears about the *seed* rather
/// than about a size cap this program chose.
#[test]
fn a_seed_of_the_wrong_size_says_so_in_the_seeds_own_vocabulary() {
    let dir = tempfile::tempdir().expect("a temp dir");

    for contents in ["00", &"00".repeat(65)] {
        let seed = file_arg(&dir, "wrong.hex", contents);
        let stderr = run_err(&["hd", "derive", "--seed-file", &seed, "--path", "m"]);

        assert!(!stderr.contains("maximum"), "{stderr}");
        assert!(stderr.to_lowercase().contains("seed"), "{stderr}");
    }
}

/// A rejected seed is not echoed into stderr — it is the whole wallet, and
/// stderr is redirected into logs far more often than `argv` is read.
#[test]
fn a_rejected_seed_is_not_printed_back() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let bad = "zz".repeat(32);
    let seed = file_arg(&dir, "bad.hex", &bad);

    let stderr = run_err(&["hd", "derive", "--seed-file", &seed, "--path", "m"]);

    assert!(
        !stderr.contains(&bad),
        "the value was echoed back:\n{stderr}"
    );
}

/// A path that is not a path says which step failed, rather than "invalid".
#[test]
fn a_broken_path_names_the_step() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    let stderr = run_err(&["hd", "derive", "--seed-file", &seed, "--path", "m/84h/zz"]);

    assert!(stderr.contains("zz"), "the step is named: {stderr}");
}

/// The count cap is this program's policy, and it says so rather than deriving a
/// hundred thousand private keys onto someone's terminal.
#[test]
fn the_count_is_capped() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    let stderr = run_err(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m",
        "--count",
        "101",
    ]);
    assert!(stderr.contains("100"), "{stderr}");

    // A hundred is fine.
    let json = json_of(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m",
        "--count",
        "100",
    ]);
    assert_eq!(json["keys"].as_array().expect("keys").len(), 100);
}

/// The same two limits, reached through a request file instead of an argument.
///
/// A file is *data*, not argv, so these exit 1 where the flags exit 2 — and both
/// checks have to exist, because clap never sees a request file.
#[test]
fn the_limits_hold_for_a_request_file_too() {
    let dir = tempfile::tempdir().expect("a temp dir");

    let too_many = file_arg(
        &dir,
        "count.json",
        &format!(r#"{{"seed":"{SEED}","path":"m","count":101}}"#),
    );
    let stderr = run_err(&["hd", "derive", "--input", &too_many]);
    assert!(stderr.contains("100"), "{stderr}");

    let bad_words = file_arg(&dir, "words.json", r#"{"wordCount":13}"#);
    let stderr = run_err(&["hd", "mnemonic", "--input", &bad_words]);
    assert!(stderr.contains("12, 15, 18, 21 or 24"), "{stderr}");
}

/// The walk stops at the end of the normal range rather than wrapping into the
/// hardened one, and says so before printing part of the answer.
#[test]
fn the_walk_stops_at_the_end_of_the_normal_range() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);
    let last = (2u32.pow(31) - 1).to_string();

    let stderr = run_err(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m",
        "--start-index",
        &last,
        "--count",
        "2",
    ]);
    assert!(stderr.contains(&last), "{stderr}");

    // Exactly the last one is fine.
    let json = json_of(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m",
        "--start-index",
        &last,
        "--count",
        "1",
    ]);
    assert_eq!(
        json["keys"][0]["index"].as_u64(),
        Some(u64::from(u32::MAX / 2))
    );
}

#[test]
fn both_modes_carry_the_same_values() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    // `addresses` is pruned: `hd derive` prints each key's addresses as
    // addresses rather than broken into version bytes and checksums, because
    // that breakdown times a hundred keys is not something anyone reads. That
    // the addresses themselves reach both modes is asserted just below.
    assert_both_modes_agree_about(
        &[
            "hd",
            "derive",
            "--seed-file",
            &seed,
            "--path",
            "m/84h/0h/0h/0",
            "--count",
            "2",
        ],
        |key| key != "addresses",
    );
}

/// The abbreviation `hd derive` makes is *only* an abbreviation: every address
/// still reaches the formatted output, and only their parts are left out.
#[test]
fn the_formatted_output_abbreviates_addresses_without_dropping_any() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);
    let args = [
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m/84h/0h/0h/0",
        "--count",
        "2",
    ];

    let human = run_ok(&args);
    let json = json_of(&args);

    for key in json["keys"].as_array().expect("keys") {
        for kind in ["p2pkh", "p2shP2wpkh", "p2wpkh", "p2tr"] {
            let address = key["addresses"][kind]["address"]
                .as_str()
                .expect("every address exists for a compressed key");
            assert!(human.contains(address), "{kind} is missing:\n{human}");
        }

        // …and the parts are deliberately not there.
        let checksum = key["addresses"]["p2pkh"]["base58"]["checksum"]
            .as_str()
            .expect("a checksum");
        assert!(
            !human.contains(checksum),
            "the breakdown belongs to `keys public`:\n{human}"
        );
    }
}

/// A request file is the API's request body, so one file drives both front ends.
#[test]
fn a_request_file_is_the_api_request_body() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let request = file_arg(
        &dir,
        "req.json",
        &format!(
            r#"{{"seed":"{SEED}","path":"m/84h/0h/0h/0","count":2,"startIndex":3,
                 "network":"testnet"}}"#
        ),
    );

    let json = json_of(&["hd", "derive", "--input", &request]);

    assert_eq!(json["network"], "testnet");
    assert_eq!(json["keys"][0]["index"], 3);
    assert_eq!(json["keys"].as_array().expect("keys").len(), 2);
}

#[test]
fn a_partial_request_is_a_usage_error() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let seed = file_arg(&dir, "seed.hex", SEED);

    assert_usage_error(&["hd", "derive"]);
    assert_usage_error(&["hd", "derive", "--seed-file", &seed]);
    assert_usage_error(&["hd", "derive", "--path", "m"]);
    assert_usage_error(&[
        "hd",
        "derive",
        "--seed-file",
        &seed,
        "--path",
        "m",
        "--input",
        "-",
    ]);
    assert_usage_error(&["hd", "mnemonic", "--words", "12", "--input", "-"]);
}
