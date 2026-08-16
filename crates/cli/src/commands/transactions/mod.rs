//! Whole transactions — the `transactions` group.
//!
//! Three commands: read a script, take a transaction apart, or put one
//! together. Named as the server names them, and answering the same shapes.
//!
//! # None of these sign anything
//!
//! A signature commits to a *sighash*, and a sighash needs the value and script
//! of every output being spent — data a raw transaction does not carry. So
//! `builder` validates and serializes, and a transaction that needs a signature
//! gets one somewhere that knows what it is spending.
//!
//! # Malformed data is not the same as a malformed request
//!
//! `script` answers 200-equivalent — exit 0, with an `error` field — for a
//! broken script, because showing how far it decoded and where it stopped is the
//! entire point of the command. `splitter` fails outright on a broken
//! transaction, because once field boundaries stop lining up there is no partial
//! answer to give. The API draws the line in the same place.

pub mod builder;
pub mod script;
pub mod splitter;

use anyhow::Result;
use clap::Subcommand;

use crate::output::Context;

/// The commands under `transactions`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Decode a script: its template, its disassembly, and every instruction.
    ///
    /// A script that does not decode cleanly is still an answer — everything up
    /// to the problem is printed, with the problem beside it — because showing
    /// where it broke is what the command is for.
    #[command(after_long_help = "Examples:
  bt transactions script 76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
  bt transactions script --input script.json --json")]
    Script(script::Args),

    /// Split a raw transaction into the bytes each wire field occupies.
    ///
    /// Every field is printed as the hex it actually is, in the order it
    /// appears, so the output reads as the transaction does — plus the txid, and
    /// the wtxid when there is a witness.
    #[command(after_long_help = "Examples:
  bt transactions splitter 0200000001...
  bt transactions splitter --input tx.json --json")]
    Splitter(splitter::Args),

    /// Build a transaction from inputs and outputs.
    ///
    /// Validates and serializes; it does not sign. What it refuses is the set of
    /// transactions that serialize cleanly and are still rejected by every node.
    ///
    /// The flags build an unsigned skeleton. Anything carrying a scriptSig or a
    /// witness comes from --input, because a nested list has no flag spelling
    /// that beats writing the JSON.
    #[command(after_long_help = "Examples:
  bt transactions builder --type legacy \\
      --spend aa52ef52...:0 --pay 100000:76a914751e76e8...88ac
  bt transactions builder --input tx.json --json")]
    Builder(builder::Args),
}

impl Command {
    /// Run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self, ctx: Context) -> Result<()> {
        match self {
            Command::Script(args) => script::run(args, ctx),
            Command::Splitter(args) => splitter::run(args, ctx),
            Command::Builder(args) => builder::run(args, ctx),
        }
    }
}
