//! Properties of the program itself, asserted across every group.
//!
//! Not "does this command answer correctly" — each group's suite does that —
//! but the things a *CLI* owes its caller regardless of which command ran: the
//! streams, the exit codes, the colour, and the fact that both output modes
//! exist everywhere.

mod common;

use common::{bt, file_arg, run_ok};

/// One representative of every group, chosen to need no secret and no fixture.
///
/// Derived from the group list rather than restated per test, so a group added
/// without being wired into these properties fails here.
fn one_of_each_group() -> Vec<Vec<String>> {
    let genesis = bitcoin_tools_vectors::blocks()[0]["header"]
        .as_str()
        .expect("a header")
        .to_owned();
    let tx = bitcoin_tools_vectors::segwit()[0]["rawTx"]
        .as_str()
        .expect("a transaction")
        .to_owned();

    [
        vec!["converter", "unit", "--bitcoin", "1.5"],
        vec!["blocks", "header", &genesis],
        vec!["keys", "generate"],
        vec!["hd", "mnemonic"],
        vec!["transactions", "splitter", &tx],
        vec![
            "transactions",
            "script",
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
        ],
    ]
    .into_iter()
    .map(|args| args.into_iter().map(str::to_owned).collect())
    .collect()
}

/// Every group is reachable, listed in the top-level help, and has a `--json`.
///
/// The help is generated from the argument definition, so this is a check that
/// the groups are *wired in* — a module written and never mounted would pass
/// its own unit tests and be unreachable.
#[test]
fn every_group_is_mounted_and_answers_in_both_modes() {
    let help = run_ok(&["--help"]);

    for group in [
        "blocks",
        "converter",
        "crypto",
        "hd",
        "keys",
        "transactions",
    ] {
        assert!(help.contains(group), "{group} is not in the help:\n{help}");

        let subcommands = run_ok(&[group, "--help"]);
        assert!(
            subcommands.contains("Commands:"),
            "{group} has no subcommands:\n{subcommands}"
        );
    }
}

/// In `--json` mode, **stdout carries nothing but JSON**. A stray `println!`
/// anywhere in a command would break every pipeline that parses it.
#[test]
fn json_mode_puts_nothing_but_json_on_stdout() {
    for args in one_of_each_group() {
        let mut with_json: Vec<&str> = args.iter().map(String::as_str).collect();
        with_json.push("--json");

        let stdout = run_ok(&with_json);
        serde_json::from_str::<serde_json::Value>(&stdout)
            .unwrap_or_else(|e| panic!("{args:?} --json is not one JSON value ({e}):\n{stdout}"));
    }
}

/// A closed pipe is not a failure, in either mode.
///
/// `bt … | head` closes stdout as soon as it has its line. Rust
/// suppresses `SIGPIPE`, so that arrives as an ordinary write error — and a
/// program that reported it would make every correct pipeline print a spurious
/// failure and exit non-zero.
#[test]
fn a_closed_pipe_is_not_a_failure() {
    use std::process::{Command, Stdio};

    for args in one_of_each_group() {
        for json in [false, true] {
            let mut argv: Vec<&str> = args.iter().map(String::as_str).collect();
            if json {
                argv.push("--json");
            }

            // `std::process::Command`, not `assert_cmd`'s: this needs the child
            // handle so the read end can be dropped mid-write, which the
            // assertion wrapper does not expose.
            let mut child = Command::new(env!("CARGO_BIN_EXE_bt"))
                .args(&argv)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("the binary runs");

            // Drop the read end while the child is still writing, which is what
            // `| head -1` does.
            drop(child.stdout.take());

            let output = child.wait_with_output().expect("the child finishes");
            let stderr = String::from_utf8_lossy(&output.stderr);

            assert!(
                output.status.success(),
                "{argv:?} exited {:?} on a closed pipe: {stderr}",
                output.status.code()
            );
            assert!(stderr.is_empty(), "{argv:?} complained: {stderr}");
        }
    }
}

/// Nothing emits an escape code when colour is refused, by either route.
///
/// `assert_cmd` gives the child no terminal, so the automatic rule already
/// applies; `NO_COLOR` and `--color never` are the two explicit ones, and all
/// three have to hold or a redirected file ends up with `\x1b[2m` in it.
#[test]
fn nothing_emits_escape_codes_when_colour_is_refused() {
    for args in one_of_each_group() {
        let argv: Vec<&str> = args.iter().map(String::as_str).collect();

        let piped = run_ok(&argv);

        let with_flag = {
            let mut argv = argv.clone();
            argv.push("--color");
            argv.push("never");
            run_ok(&argv)
        };

        let no_color = String::from_utf8(
            bt().args(&argv)
                .env("NO_COLOR", "1")
                .assert()
                .success()
                .get_output()
                .stdout
                .clone(),
        )
        .expect("stdout is UTF-8");

        for (how, output) in [
            ("piped", &piped),
            ("--color never", &with_flag),
            ("NO_COLOR", &no_color),
        ] {
            assert!(
                !output.contains('\x1b'),
                "{argv:?} emitted an escape code under {how}:\n{output:?}"
            );
        }
    }
}

/// A failure writes to stderr, leaves stdout empty, and exits 1 — in `--json`
/// mode too, where a half-written object would be worse than nothing.
#[test]
fn a_failure_leaves_stdout_empty_and_parseable() {
    let failures: [&[&str]; 4] = [
        &["blocks", "header", "00"],
        &["converter", "unit", "--satoshi", "0.1"],
        &["transactions", "splitter", "0200"],
        &["converter", "base", "--decimal", "zz"],
    ];

    for args in failures {
        for json in [false, true] {
            let mut argv = args.to_vec();
            if json {
                argv.push("--json");
            }

            let output = bt().args(&argv).output().expect("the binary runs");

            assert_eq!(output.status.code(), Some(1), "{argv:?}");
            assert!(output.stdout.is_empty(), "{argv:?} wrote to stdout");
            assert!(!output.stderr.is_empty(), "{argv:?} said nothing");
        }
    }
}

/// Every `--input` accepts `-` for stdin, which is the spelling every other
/// tool uses and the one a user tries first.
#[test]
fn every_request_file_flag_reads_stdin_as_a_dash() {
    let genesis = bitcoin_tools_vectors::blocks()[0]["header"]
        .as_str()
        .expect("a header")
        .to_owned();

    let requests: [(&[&str], String); 4] = [
        (&["blocks", "hash"], format!(r#"{{"header":"{genesis}"}}"#)),
        (
            &["converter", "unit"],
            r#"{"amount":"1.5","denomination":"bitcoin"}"#.to_owned(),
        ),
        (
            &["transactions", "script"],
            r#"{"script":"76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"}"#.to_owned(),
        ),
        (&["keys", "generate"], r#"{"network":"testnet"}"#.to_owned()),
    ];

    for (command, body) in requests {
        let mut argv = command.to_vec();
        argv.extend(["--input", "-", "--json"]);

        let output = bt()
            .args(&argv)
            .write_stdin(body.clone())
            .assert()
            .success();

        serde_json::from_slice::<serde_json::Value>(&output.get_output().stdout)
            .unwrap_or_else(|e| panic!("{command:?} --input - is not JSON ({e})"));
    }
}

/// A request file that is not the shape a command expects says which file and
/// what was wrong, rather than "expected a string".
#[test]
fn an_unusable_request_file_names_the_file() {
    let dir = tempfile::tempdir().expect("a temp dir");
    let broken = file_arg(&dir, "broken.json", "{not json");

    let output = bt()
        .args(["blocks", "hash", "--input", &broken])
        .output()
        .expect("the binary runs");

    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");

    assert_eq!(output.status.code(), Some(1));
    assert!(stderr.contains("broken.json"), "{stderr}");
    assert!(
        stderr.contains("caused by"),
        "the chain is printed: {stderr}"
    );
}
