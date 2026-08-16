//! A command-line interface over `bitcoin-tools-core`.
//!
//! A sibling of the axum server, not a layer under or over it: both are front
//! ends, the core is shaped by neither, and where they answer the same question
//! they answer it the same way.
//!
//! # What this file owns
//!
//! Only the process boundary — parse, run, turn an error into a message on
//! stderr and a non-zero exit. Everything else is in [`cli`], [`commands`],
//! [`input`] and [`output`].
//!
//! # Exit codes
//!
//! Two, which is what the convention gives and no more than the program has
//! anything to say with:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | The command answered. |
//! | 1 | It could not: bad input, an unreadable file, an unwritable stdout. |
//! | 2 | The arguments were wrong. clap owns this one and writes its own message. |
//!
//! A closed pipe is **not** a failure. `… | head` closes stdout early, and a
//! program that reported that as an error would make every pipeline that uses
//! it look broken.

#![warn(missing_docs)]
// This is a binary with a person on the other end: a panic prints a backtrace
// and an issue-tracker request where a sentence was wanted. Everything
// reachable from `main` returns an error instead.
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cli;
mod commands;
mod input;
mod output;

use std::io::{self, Write};
use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;

fn main() -> ExitCode {
    // `parse` exits with clap's own message and code 2 if the arguments are
    // wrong, so nothing below has to consider that case.
    let cli = Cli::parse();

    match cli.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) if is_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(error) => {
            report(&error);
            ExitCode::FAILURE
        }
    }
}

/// Whether this failure is just a reader that stopped listening.
///
/// `bt … | head -1` closes the pipe as soon as it has its line. Rust
/// suppresses `SIGPIPE`, so that surfaces here as an ordinary write error
/// rather than killing the process — and reporting it would make a correct
/// pipeline print a spurious failure and exit non-zero.
///
/// The whole chain is searched, not just the outermost error, because the write
/// is several `context` layers below where it is caught.
fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<io::Error>()
            .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
    })
}

/// Print a failure to **stderr**, so `--json` mode's stdout stays parseable
/// even when the command fails.
///
/// The chain is printed as indented `caused by` lines rather than as one
/// sentence: the outermost context says which file was being read, and the
/// innermost says what was actually wrong with it, and a user needs both.
fn report(error: &anyhow::Error) {
    let bold = anstyle::Style::new().bold();
    let red = anstyle::AnsiColor::Red.on_default() | anstyle::Effects::BOLD;

    let mut stderr = anstream::stderr().lock();

    // Failing to report a failure leaves nothing useful to do, and the exit
    // code still carries the answer.
    let _ = writeln!(
        stderr,
        "{}error:{} {}{error}{}",
        red.render(),
        red.render_reset(),
        bold.render(),
        bold.render_reset()
    );

    for cause in error.chain().skip(1) {
        let _ = writeln!(stderr, "  caused by: {cause}");
    }
}
