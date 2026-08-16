//! Shared test harness.
//!
//! Every test drives the built binary through `assert_cmd`, so what is under
//! test is the thing a user runs: argument parsing, both output modes, the
//! streams and the exit code.

// Each test binary includes this module and uses only part of it.
#![allow(dead_code)]

use assert_cmd::Command;
use serde_json::Value;

/// The binary under test.
///
/// `cargo_bin` resolves the build this test run belongs to, so there is no path
/// to keep in step and no chance of testing a stale binary.
pub fn bt() -> Command {
    Command::cargo_bin("bitcoin-tools").expect("the binary is built for its own tests")
}

/// Run a command that must succeed, and return its stdout.
pub fn run_ok(args: &[&str]) -> String {
    let output = bt().args(args).assert().success();
    String::from_utf8(output.get_output().stdout.clone()).expect("stdout is UTF-8")
}

/// Run a command with `--json` and parse what it printed.
///
/// The parse is the assertion: a mode that emitted anything besides one JSON
/// value fails here rather than in whatever consumed it.
pub fn json_of(args: &[&str]) -> Value {
    let mut with_json = args.to_vec();
    with_json.push("--json");

    let stdout = run_ok(&with_json);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("{args:?} --json is not one JSON value ({e}):\n{stdout}"))
}

/// Write a file into a directory and hand back its path.
///
/// The directory is the caller's `TempDir`, so it lives exactly as long as the
/// test and cleans itself up on the way out — including when the test panics.
pub fn file(dir: &tempfile::TempDir, name: &str, contents: &str) -> std::path::PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, contents).expect("writing a test fixture");
    path
}

/// The path of a file holding a secret, as a string for an argument list.
pub fn file_arg(dir: &tempfile::TempDir, name: &str, contents: &str) -> String {
    file(dir, name, contents)
        .to_str()
        .expect("a temp path is UTF-8")
        .to_owned()
}

/// Run a command that must fail, and return its stderr.
///
/// Asserts the two halves of a failure a user notices: the exit code, and that
/// **stdout stayed empty** — a command that printed half an answer and then
/// failed would leave a pipeline parsing garbage.
pub fn run_err(args: &[&str]) -> String {
    let output = bt().args(args).output().expect("the binary runs");

    assert!(
        !output.status.success(),
        "{args:?} was supposed to fail:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stdout.is_empty(),
        "{args:?} failed but wrote to stdout:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    String::from_utf8(output.stderr).expect("stderr is UTF-8")
}

/// Run a command whose arguments are wrong, and assert clap owned the failure.
///
/// Exit code 2 is the convention's, and clap is the only thing in this program
/// that produces it: a usage mistake reaching the domain and coming back as a
/// 1 would be a command that forgot to state its own rule.
pub fn assert_usage_error(args: &[&str]) {
    let output = bt().args(args).output().expect("the binary runs");

    assert_eq!(
        output.status.code(),
        Some(2),
        "{args:?} should be a usage error:\n{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
}

/// Assert that every value in a command's `--json` also reaches its formatted
/// output.
///
/// The one property the two modes owe each other. Nested objects are walked, so
/// an address buried three levels down counts; keys are not compared, because
/// the formatted output is allowed to label a value differently — what it is not
/// allowed to do is drop it.
///
/// Booleans and nulls are skipped: `yes`/`no` and "absent" are the deliberate
/// spelling differences, and both are asserted where they matter instead.
///
/// # Only for a command that answers the same thing twice
///
/// This runs the command once per mode, so it cannot be used on `keys generate`
/// or `hd mnemonic` — two runs of those are two different keys, and every value
/// would look missing. Those two pin their modes against a stated field list
/// instead, which is the best a generator allows.
pub fn assert_both_modes_agree(args: &[&str]) {
    assert_both_modes_agree_about(args, |_| true);
}

/// The same, for a command whose formatted output abbreviates on purpose.
///
/// `keep` is asked about each JSON key on the way down; a key it refuses is not
/// descended into. `hd derive` is the only caller: it prints each key's
/// addresses as addresses rather than broken into their parts, because four
/// addresses fully taken apart times a hundred keys is not something anyone
/// reads — `keys public` is where one key gets taken apart.
///
/// This is a *narrower* assertion, not a waived one: everything outside the
/// pruned subtree is still required to reach both modes.
pub fn assert_both_modes_agree_about(args: &[&str], keep: fn(&str) -> bool) {
    let human = run_ok(args);
    let json = prune(json_of(args), keep);

    let mut missing = Vec::new();
    walk(&json, &human, &mut missing);

    assert!(
        missing.is_empty(),
        "{args:?}: in --json but not in the formatted output: {missing:?}\n{human}"
    );
}

/// Drop every subtree whose key `keep` refuses.
fn prune(value: Value, keep: fn(&str) -> bool) -> Value {
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .into_iter()
                .filter(|(key, _)| keep(key))
                .map(|(key, value)| (key, prune(value, keep)))
                .collect(),
        ),
        Value::Array(items) => {
            Value::Array(items.into_iter().map(|item| prune(item, keep)).collect())
        }
        other => other,
    }
}

fn walk(value: &Value, human: &str, missing: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if !s.is_empty() && !human.contains(s.as_str()) {
                missing.push(s.clone());
            }
        }
        Value::Number(n) => {
            if !human.contains(&n.to_string()) {
                missing.push(n.to_string());
            }
        }
        Value::Array(items) => items.iter().for_each(|item| walk(item, human, missing)),
        Value::Object(fields) => fields.values().for_each(|v| walk(v, human, missing)),
        // `true`/`false` render as `yes`/`no` and `null` renders as nothing at
        // all. Both are deliberate, and both are asserted where they matter.
        Value::Bool(_) | Value::Null => {}
    }
}
