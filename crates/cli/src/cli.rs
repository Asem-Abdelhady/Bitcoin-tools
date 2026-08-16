//! The argument surface.
//!
//! Everything a user can type is declared here or in a `commands` module, and
//! nothing else parses arguments.
//!
//! The groups follow the server's, with one deliberate exception. `keys`, `hd`,
//! `transactions`, `blocks` and `crypto` will be named as the server names
//! them, so someone who knows one front end can guess the other. The
//! conversions are `converter` here and `/tools` there, because the argument
//! surface underneath them genuinely differs — see
//! [`commands::converter`](crate::commands::converter). Where they differ in
//! *spelling*, they still agree on every *answer*.

use anyhow::Result;
use clap::{Args, ColorChoice, Parser, Subcommand};

use crate::commands::{blocks, converter, crypto, hd, keys, transactions};
use crate::output::{Context, Format};

/// Decode and inspect Bitcoin's data formats.
#[derive(Debug, Parser)]
#[command(
    name = "bitcoin-tools",
    version,
    about,
    long_about = "Decode and inspect Bitcoin's data formats: transactions, scripts, keys, \
                  addresses, HD wallets, and blocks.\n\n\
                  Every command prints formatted text for a terminal, or the same values as \
                  JSON with --json. Commands that take a request can read it from arguments \
                  or from a JSON file with --input.",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global: GlobalArgs,
}

/// The flags that mean the same thing everywhere.
///
/// `global = true`, so they are accepted after the subcommand — which is where
/// a user will type them — and are declared once rather than on each command.
#[derive(Debug, Args)]
#[command(next_help_heading = "Global options")]
pub struct GlobalArgs {
    /// Print JSON instead of formatted text.
    ///
    /// The JSON carries exactly the values the formatted output does, and
    /// matches the shape the HTTP API returns for the same request. Nothing but
    /// JSON is written to stdout in this mode; diagnostics go to stderr.
    #[arg(long, global = true)]
    json: bool,

    /// When to colour the output.
    ///
    /// Colour is off automatically when stdout is not a terminal, and when
    /// NO_COLOR is set. This overrides both.
    #[arg(long, global = true, value_name = "WHEN", default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

/// The top-level groups.
#[derive(Debug, Subcommand)]
enum Command {
    /// Representation conversions: number bases, units, and byte order.
    Converter {
        #[command(subcommand)]
        command: converter::Command,
    },

    /// Block headers: their hash, and their fields.
    Blocks {
        #[command(subcommand)]
        command: blocks::Command,
    },

    /// ECDSA signing and verification.
    Crypto {
        #[command(subcommand)]
        command: crypto::Command,
    },

    /// Hierarchical deterministic wallets: mnemonics, seeds and derivation.
    Hd {
        #[command(subcommand)]
        command: hd::Command,
    },

    /// Private keys, public keys and addresses.
    Keys {
        #[command(subcommand)]
        command: keys::Command,
    },

    /// Scripts, raw transactions, and building one.
    Transactions {
        #[command(subcommand)]
        command: transactions::Command,
    },
}

impl Cli {
    /// Apply the global flags, then run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self) -> Result<()> {
        // Set before anything writes: `anstream` consults this global choice,
        // so no writer in the crate has to be told about colour or check for a
        // terminal itself.
        //
        // clap's own help and error output is not covered by this — it decides
        // before `--color` has been parsed. It follows the same auto rules
        // (terminal detection and NO_COLOR), so the two agree except when this
        // flag is used to override them.
        color_choice(self.global.color).write_global();

        let ctx = Context::new(if self.global.json {
            Format::Json
        } else {
            Format::Human
        });

        match self.command {
            Command::Converter { command } => command.run(ctx),
            Command::Blocks { command } => command.run(ctx),
            Command::Crypto { command } => command.run(ctx),
            Command::Hd { command } => command.run(ctx),
            Command::Keys { command } => command.run(ctx),
            Command::Transactions { command } => command.run(ctx),
        }
    }
}

/// clap and anstream each have their own three-valued colour enum.
const fn color_choice(choice: ColorChoice) -> anstream::ColorChoice {
    match choice {
        ColorChoice::Auto => anstream::ColorChoice::Auto,
        ColorChoice::Always => anstream::ColorChoice::Always,
        ColorChoice::Never => anstream::ColorChoice::Never,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// clap validates the argument definition at runtime, not at compile time —
    /// a duplicated short flag or a `required_unless_present` naming an argument
    /// that does not exist panics on first use. This turns that into a test
    /// failure instead of a user's first run.
    #[test]
    fn the_argument_definition_is_well_formed() {
        Cli::command().debug_assert();
    }
}
