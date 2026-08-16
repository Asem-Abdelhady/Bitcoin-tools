//! End-to-end tests for the `converter` commands.
//!
//! These run the **binary**, not inner functions. A CLI's contract is its
//! argument surface, its two output modes, its streams and its exit codes, and
//! none of those are exercised by calling `run` directly.

mod common;

use common::{bt, json_of, run_ok};
use predicates::prelude::*;
use serde_json::json;

use bitcoin_tools_core::general::Denomination;
use bitcoin_tools_vectors::{blocks, field, tools};

// ---------------------------------------------------------------- the contract

/// The load-bearing test of this crate.
///
/// `--json` and the formatted output are two views of one value, so every value
/// in the JSON has to be somewhere in the text. A `--json` mode that quietly
/// dropped a field, or a formatted output that grew one the JSON never got,
/// fails here — and nowhere else, because each mode passes its own assertions
/// perfectly well on its own.
#[test]
fn both_modes_carry_the_same_values() {
    let cases: [&[&str]; 3] = [
        &["converter", "reverse-bytes", "deadbeef"],
        &["converter", "base", "--decimal", "255"],
        &["converter", "unit", "--btc", "1.5"],
    ];

    for args in cases {
        let text = run_ok(args);
        let value = json_of(args);

        let object = value.as_object().expect("every command answers an object");
        assert!(!object.is_empty(), "{args:?} answered nothing");

        for (key, value) in object {
            let rendered = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => {
                    // The one value the two modes deliberately spell
                    // differently; `yes`/`no` reads as English and
                    // `true`/`false` reads as JSON.
                    if *b { "yes" } else { "no" }.to_owned()
                }
                other => other.to_string(),
            };

            // Matched per line and anchored at the end, not as a substring of
            // the whole output: `Fields` puts the value last, and a bare
            // `contains` is satisfied by the wrong row — "1500" is inside
            // "150000000", so a millibitcoin row printing the satoshi count
            // would pass.
            assert!(
                text.lines()
                    .any(|line| line.trim_end().ends_with(&rendered)),
                "`{key}` is `{rendered}` in --json but no line of the text output \
                 ends with it:\n{text}"
            );
        }
    }
}

/// In `--json` mode stdout is JSON and nothing else — no banner, no progress,
/// no trailing "Done." One stray line makes the mode useless to `jq`.
#[test]
fn json_mode_puts_nothing_but_json_on_stdout() {
    let output = bt()
        .args(["converter", "unit", "--btc", "1.5", "--json"])
        .assert()
        .success();

    let stdout = String::from_utf8(output.get_output().stdout.clone()).unwrap();
    serde_json::from_str::<serde_json::Value>(&stdout)
        .unwrap_or_else(|e| panic!("stdout is not one JSON value ({e}):\n{stdout}"));
}

/// Diagnostics go to stderr, so a failing command in `--json` mode still leaves
/// stdout parseable — or, as here, empty rather than half-written.
#[test]
fn a_failure_writes_nothing_to_stdout_and_exits_nonzero() {
    bt().args(["converter", "unit", "--sat", "0.1", "--json"])
        .assert()
        .failure()
        .code(1)
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::contains("decimal places"));
}

/// clap owns exit code 2, and the arguments it refuses never reach a command.
#[test]
fn a_usage_mistake_exits_two() {
    // A bare value: this command has no positional, because the notation is
    // the flag and the value rides with it.
    bt().args(["converter", "base", "255"]).assert().code(2);

    // The two input sources are mutually exclusive, and clap enforces it rather
    // than the command discovering it later.
    bt().args(["converter", "base", "--dec", "255", "--input", "x.json"])
        .assert()
        .code(2);

    bt().args(["converter", "nope"]).assert().code(2);
}

/// The two front ends answer identically, and a shared file says what the
/// answer is.
///
/// The file holds each operation three ways: this crate's argv, the HTTP
/// request body, and the one response both must produce. Neither front-end
/// crate can depend on the other, so that file is where the agreement can live.
///
/// **This suite asserts against it; the server's does not yet** — wiring
/// `tools_api.rs` to the same file belongs to that crate's review. Until then,
/// a change to the *server's* output makes the file stale and fails this test,
/// which looks like a CLI bug and is not.
#[test]
fn the_json_is_what_both_front_ends_promise() {
    for vector in tools() {
        let name = vector["name"].as_str().unwrap_or("unnamed");

        let command: Vec<&str> = vector["command"]
            .as_array()
            .unwrap_or_else(|| panic!("{name} has no command"))
            .iter()
            .map(|arg| {
                arg.as_str()
                    .unwrap_or_else(|| panic!("{name}: argv is strings"))
            })
            .collect();

        assert_eq!(json_of(&command), vector["response"], "{name}");
    }
}

// ---------------------------------------------------------------- reverse-bytes

/// The relation that makes this checkable against something other than itself:
/// a block hash as people write it is the header's own hash reversed. The
/// vectors carry both, and the command is told neither.
#[test]
fn reversing_a_block_hash_gives_the_order_the_header_carries() {
    for vector in blocks() {
        let at = format!("block {}", vector["height"]);
        let displayed = field(&vector, "hash", &at);

        let flipped = json_of(&["converter", "reverse-bytes", displayed]);
        assert_eq!(flipped["bytes"], 32, "{at}");

        let wire = flipped["reversed"].as_str().expect("reversed is a string");
        let back = json_of(&["converter", "reverse-bytes", wire]);

        assert_eq!(back["reversed"], displayed, "{at}: and the other way round");
        assert_ne!(wire, displayed, "{at}: a palindrome asserts nothing");
    }
}

/// `0x` and whitespace are accepted, and `input` echoes what was actually
/// decoded rather than what was typed.
#[test]
fn the_noise_people_paste_is_accepted_and_the_bytes_are_the_value() {
    let value = json_of(&["converter", "reverse-bytes", "  0xDEADBEEF  "]);

    assert_eq!(value["input"], "deadbeef");
    assert_eq!(value["reversed"], "efbeadde");
    assert_eq!(value["bytes"], 4);
}

#[test]
fn a_lone_nibble_is_not_bytes_to_reverse() {
    bt().args(["converter", "reverse-bytes", "abc"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("odd"));
}

// ---------------------------------------------------------------- base

/// The case this command exists for: a 256-bit value has no JSON number that
/// holds it, which is why the value is a string in both directions.
#[test]
fn the_group_order_converts_without_losing_a_bit() {
    let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    let value = json_of(&["converter", "base", "--hex", order]);

    assert_eq!(value["hexadecimal"], order);
    assert_eq!(value["bits"], 256);
    assert_eq!(value["bytes"], 32);
    assert_eq!(
        value["decimal"],
        "115792089237316195423570985008687907852837564279074904382605163141518161494337"
    );
}

/// Each notation has a long flag and its short aliases, and they name the same
/// base. The long form is also the key that base is answered under.
#[test]
fn every_base_flag_and_alias_names_its_own_base() {
    for flag in ["--hexadecimal", "--hex"] {
        let value = json_of(&["converter", "base", flag, "ff"]);
        assert_eq!(value["decimal"], "255", "{flag}");
    }
    for flag in ["--binary", "--bin"] {
        let value = json_of(&["converter", "base", flag, "11111111"]);
        assert_eq!(value["decimal"], "255", "{flag}");
    }
    for flag in ["--decimal", "--dec"] {
        let value = json_of(&["converter", "base", flag, "255"]);
        assert_eq!(value["hexadecimal"], "ff", "{flag}");
    }
}

/// The notation cannot be omitted, because there is no argument that carries a
/// value without one — and it cannot be given twice.
#[test]
fn a_value_cannot_arrive_without_its_notation_or_with_two() {
    bt().args(["converter", "base", "255"]).assert().code(2);
    bt().args(["converter", "base", "--hex", "ff", "--decimal", "255"])
        .assert()
        .code(2);
    bt().args(["converter", "unit", "1.5"]).assert().code(2);
    bt().args(["converter", "unit", "--btc", "1.5", "--sat", "1"])
        .assert()
        .code(2);
}

/// A base the tool does not have is not a flag it has, so clap says so and
/// suggests the nearest one.
#[test]
fn an_unknown_base_is_not_a_flag() {
    bt().args(["converter", "base", "--octal", "10"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("unexpected argument"));
}

/// A request *file* still names its base as a value, and there core's parser
/// says what it expected.
#[test]
fn an_unknown_base_in_a_request_file_names_what_it_expected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("octal.json");
    std::fs::write(&path, r#"{"value":"10","base":"octal"}"#).unwrap();

    bt().args(["converter", "base", "--input", path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("binary, decimal, or hexadecimal"));
}

// ---------------------------------------------------------------- unit

/// One amount, given under each unit's flag, is the same amount.
///
/// The flag names are written out rather than derived from `Denomination`:
/// `as_str` gives the canonical short spelling (`sat`, `µBTC`), and the flags
/// are the spelled-out names — which are also the keys the answer comes back
/// under. Pairing them here is what pins that correspondence.
#[test]
fn an_amount_reads_the_same_under_every_unit_flag() {
    let written = [
        (Denomination::Satoshi, "--satoshi", "150000000"),
        (Denomination::MicroBitcoin, "--microbitcoin", "1500000"),
        (Denomination::MilliBitcoin, "--millibitcoin", "1500"),
        (Denomination::Bitcoin, "--bitcoin", "1.5"),
    ];

    // Anchored to the domain's own set, so a fifth unit fails here rather than
    // shipping with an output key and no flag to ask for it. `Base` gets no
    // such anchor — it is `#[non_exhaustive]` with no `all()`, which is a
    // deliberate one-directional guarantee rather than an oversight, so
    // `base`'s equivalent test lists its three and cannot do better.
    for unit in Denomination::all() {
        assert!(
            written.iter().any(|(d, ..)| *d == unit),
            "no --{unit} flag; the domain has a unit this command cannot be given"
        );
    }

    for (_, flag, amount) in written {
        let value = json_of(&["converter", "unit", flag, amount]);

        assert_eq!(value["satoshi"], "150000000", "{flag} {amount}");
        assert_eq!(value["bitcoin"], "1.5", "{flag} {amount}");
        assert_eq!(value["isMoneyRange"], true, "{flag} {amount}");

        // The flag's own key answers with the value it was given.
        let key = flag.trim_start_matches('-');
        assert_eq!(
            value[key], amount,
            "{flag} did not answer under its own key"
        );
    }
}

/// The short aliases name the same units as the long forms.
#[test]
fn every_unit_alias_names_its_own_unit() {
    for (alias, long) in [
        ("--sat", "satoshi"),
        ("--sats", "satoshi"),
        ("--ubtc", "microbitcoin"),
        ("--bits", "microbitcoin"),
        ("--mbtc", "millibitcoin"),
        ("--btc", "bitcoin"),
    ] {
        let value = json_of(&["converter", "unit", alias, "1"]);
        assert_eq!(value[long], "1", "{alias} is not {long}");
    }
}

/// Every unit is answered, under a key that can be handed straight back as a
/// `--input` denomination, and is the long form of the flag that produces it.
/// Pinned against `Denomination::all` rather than
/// restated, so a fifth unit fails here instead of being silently missing.
#[test]
fn every_denomination_is_answered_under_a_key_that_reads_back_as_itself() {
    let value = json_of(&["converter", "unit", "--sat", "1"]);
    let object = value.as_object().expect("units answers an object");

    for denomination in Denomination::all() {
        assert!(
            object
                .keys()
                .any(|key| key.parse::<Denomination>() == Ok(denomination)),
            "no key reads back as {denomination}: {value}"
        );
    }
}

/// Past 21 million is reported, not refused: a malformed transaction can
/// declare any `u64`, and a tool has to be able to show it.
#[test]
fn an_amount_past_21_million_is_answered_rather_than_refused() {
    let value = json_of(&["converter", "unit", "--btc", "21000001"]);

    assert_eq!(value["isMoneyRange"], false);
    assert_eq!(value["satoshi"], "2100000100000000");
}

/// More satoshis than exist is a different failure from a payload that is too
/// big, and the string here is a perfectly ordinary size.
#[test]
fn more_satoshis_than_fit_is_a_failure_not_an_answer() {
    bt().args(["converter", "unit", "--btc", "184467440737.09551616"])
        .assert()
        .failure()
        .code(1);
}

// ---------------------------------------------------------------- input sources

/// A request read from a JSON file, which is the same shape the HTTP API takes.
#[test]
fn a_request_can_come_from_a_json_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("request.json");
    std::fs::write(&path, json!({"value": "ff", "base": "hex"}).to_string()).unwrap();

    let value = json_of(&["converter", "base", "--input", path.to_str().unwrap()]);
    assert_eq!(value["decimal"], "255");
}

/// `-` is stdin, which is the spelling every other tool uses.
#[test]
fn a_request_can_come_from_stdin() {
    let output = bt()
        .args(["converter", "unit", "--input", "-", "--json"])
        .write_stdin(json!({"amount": "1", "denomination": "BTC"}).to_string())
        .assert()
        .success();

    let value: serde_json::Value =
        serde_json::from_slice(&output.get_output().stdout).expect("stdout is JSON");
    assert_eq!(value["satoshi"], "100000000");
}

/// A typo in a request file is an error rather than a silently ignored key.
#[test]
fn an_unknown_field_in_a_request_file_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.json");
    std::fs::write(&path, r#"{"value":"ff","bass":"hex"}"#).unwrap();

    bt().args(["converter", "base", "--input", path.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unknown field"));
}

/// The message names the file, because "expected a string" is useless when
/// three of them were involved.
#[test]
fn a_missing_request_file_names_itself() {
    bt().args(["converter", "base", "--input", "/nonexistent/request.json"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("/nonexistent/request.json"));
}

// ---------------------------------------------------------------- streams

/// A closed pipe is not a failure. `… | head` is an ordinary thing to do, and a
/// program that reported it would make every pipeline using it look broken.
///
/// Both modes, because they take different paths out: `--json` writes through
/// `serde_json` and human output writes directly, and only one of them was
/// right the first time.
#[test]
fn a_closed_pipe_is_not_a_failure() {
    use std::process::{Command, Stdio};

    // Large enough that the write cannot finish into the pipe buffer before the
    // reader goes away.
    let big = serde_json::json!({ "hex": "de".repeat(200_000) }).to_string();

    for mode in [&["--json"][..], &[][..]] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.json");
        std::fs::write(&path, &big).unwrap();

        let mut child = Command::new(env!("CARGO_BIN_EXE_bitcoin-tools"))
            .args(["converter", "reverse-bytes", "--input"])
            .arg(&path)
            .args(mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();

        // Drop the read end while the child is still writing.
        drop(child.stdout.take());

        let output = child.wait_with_output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "mode {mode:?} exited {:?} on a closed pipe; stderr: {stderr}",
            output.status.code()
        );
        assert!(stderr.is_empty(), "mode {mode:?} complained: {stderr}");
    }
}

/// Colour is a terminal's business. `assert_cmd` gives the child a pipe, so
/// this is also the default path — but NO_COLOR and `--color never` are the two
/// a user reaches for, and neither has any excuse to emit an escape.
#[test]
fn nothing_emits_escape_codes_when_colour_is_refused() {
    let plain = run_ok(&["converter", "unit", "--btc", "1.5"]);
    assert!(!plain.contains('\x1b'), "piped output is styled: {plain:?}");

    let never = bt()
        .args(["converter", "unit", "--btc", "1.5", "--color", "never"])
        .assert()
        .success();
    let never = String::from_utf8(never.get_output().stdout.clone()).unwrap();
    assert!(
        !never.contains('\x1b'),
        "--color never is styled: {never:?}"
    );

    let no_color = bt()
        .args(["converter", "unit", "--btc", "1.5"])
        .env("NO_COLOR", "1")
        .assert()
        .success();
    let no_color = String::from_utf8(no_color.get_output().stdout.clone()).unwrap();
    assert!(
        !no_color.contains('\x1b'),
        "NO_COLOR is styled: {no_color:?}"
    );
}

/// A rejected value is not echoed back in full. `converter base` is the command
/// whose own help says it exists so a private key can be read in decimal, and
/// stderr is redirected into logs far more often than argv is read.
#[test]
fn a_rejected_value_is_not_echoed_back_in_full() {
    // Not hex, so it is rejected — 3000 nines would have been a perfectly
    // valid hexadecimal number and the command would have succeeded.
    let secret = "z".repeat(3000);

    let assert = bt()
        .args(["converter", "base", "--hex", &secret])
        .assert()
        .failure();

    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(
        !stderr.contains(&secret),
        "the whole value reached stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("3000 characters"),
        "the length is the useful part, and it is missing:\n{stderr}"
    );
}

/// The commands printed in `--help` are run, not just read.
///
/// `Examples:` and `Note:` are the one part of the help nothing executes, and
/// two things in them have now been wrong in a way only a human noticed. The
/// second was worse than a typo: the `Note` on `converter base` exists to steer
/// a private key out of `argv`, and it named a form that fails — so a user who
/// tried the safe way, watched it error, and reached for `--hex $KEY` was walked
/// into the exposure the note is there to prevent.
///
/// Only the piped forms are run. A `bitcoin-tools …` line with no pipe is
/// illustrative and its placeholder values are not meant to parse.
#[test]
fn every_piped_command_in_the_help_actually_runs() {
    let mut checked = 0;

    for command in [
        vec!["converter", "base"],
        vec!["converter", "unit"],
        vec!["converter", "reverse-bytes"],
    ] {
        let mut args = command.clone();
        args.push("--help");
        let help = run_ok(&args);

        // A line ending in `|` continues on the next one — which is true of the
        // help text and of `sh`, so the two agree without any unwrapping. Only
        // the piped forms are run: a `bitcoin-tools …` line with no pipe is
        // illustrative and its placeholder values are not meant to parse.
        let mut lines = help.lines().map(str::trim).peekable();
        let mut commands = Vec::new();

        while let Some(line) = lines.next() {
            if !line.starts_with("echo ") && !line.starts_with("printf ") {
                continue;
            }

            let mut whole = line.to_owned();
            while whole.ends_with('|') {
                match lines.next() {
                    Some(next) => {
                        whole.push(' ');
                        whole.push_str(next);
                    }
                    None => break,
                }
            }

            if whole.contains("bitcoin-tools") {
                commands.push(whole);
            }
        }

        for line in commands {
            // `$KEY` stands for whatever the user is holding; give it a value
            // the command can actually answer for.
            let script = format!(
                "KEY=00000000000000000000000000000000000000000000000000000000000000ff\n{}",
                line.replacen("bitcoin-tools", env!("CARGO_BIN_EXE_bitcoin-tools"), 1)
            );

            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(&script)
                .output()
                .expect("sh runs");

            assert!(
                output.status.success(),
                "{command:?} --help prints a command that fails:\n  {line}\n{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                !output.stdout.is_empty(),
                "{command:?} --help prints a command that answers nothing:\n  {line}"
            );

            checked += 1;
        }
    }

    // A floor, not a count: without it a scan that silently matched nothing
    // would pass, which is how a test like this stops testing anything.
    assert!(
        checked >= 3,
        "only {checked} piped examples were found and run"
    );
}
