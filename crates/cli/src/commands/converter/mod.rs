//! Representation conversions — the `converter` group.
//!
//! Three commands over one value each: which base it is written in, which unit
//! it is counted in, and which byte order it is in. None of them touch the
//! network or a key, and none of them can fail on anything but their input.
//!
//! # The notation is the flag
//!
//! `converter base --hex 0xab12` and `converter unit --bitcoin 1.5`, rather
//! than a value plus a `--base`/`--denomination` naming it. The notation and
//! the value arrive as one argument, which is how a person says it, and it
//! makes the rule structural instead of enforced: there is no way to give a
//! value without saying what it is written in. `10` is two, ten or sixteen; `1`
//! is a satoshi or a hundred million of them. A tool that guessed would return
//! a confident wrong answer, which is worse than an error.
//!
//! `reverse-bytes` has no such flag because it has no such choice — hex in, hex
//! out — so its value is positional.
//!
//! # This is where the two front ends' surfaces differ
//!
//! The HTTP API spells these `/tools/number` and `/tools/units`, and takes the
//! notation as a required *field*: `{"value": "…", "base": "hexadecimal"}`. A
//! JSON body has no better option — a field is the only thing it has — while a
//! command line does, and `--hex` is it.
//!
//! What is deliberately **not** allowed to differ is the answer. Both front
//! ends emit the same keys, values and shapes, and `bitcoin_tools_vectors`'
//! `tools` set carries the argv, the request body and the one response both
//! must produce.

pub mod base;
pub mod reverse;
pub mod unit;

use anyhow::Result;
use clap::Subcommand;

use crate::output::Context;

/// The commands under `converter`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Convert a value between binary, decimal and hexadecimal.
    ///
    /// The flag names the base the value is written in, and every base is
    /// printed.
    ///
    /// A request file names its base as a value where the flags name it as a
    /// flag; both read the same spellings.
    // `after_long_help` rather than the doc comment: clap re-wraps a doc
    // comment to the terminal width, which turns an example block into one
    // paragraph. This is printed verbatim.
    // The note belongs to the command rather than to one flag: a key given as
    // hex or binary is as visible in `ps` as one given in decimal. This is the
    // one place in the crate where a value that may be a secret is *meant* to
    // arrive as an argument, so it is the one place that has to say what that
    // costs.
    #[command(after_long_help = "Examples:
  bitcoin-tools converter base --hex 0xab12
  bitcoin-tools converter base --decimal 43794
  echo '{\"value\": \"0xab12\", \"base\": \"hexadecimal\"}' | bitcoin-tools converter base --input -

Note:
  This command exists partly so a 256-bit private key can be read in decimal.
  A value given as an argument is visible in `ps` to every user on the machine
  and lands in shell history. If it is a key, pipe it in instead:

  printf '{\"value\":\"%s\",\"base\":\"hexadecimal\"}' \"$KEY\" |
      bitcoin-tools converter base --input -")]
    Base(base::Args),

    /// Convert an amount between satoshi, µBTC, mBTC and BTC.
    ///
    /// The flag names the unit the amount is counted in, and every unit is
    /// printed.
    ///
    /// A request file names its unit as a value where the flags name it as a
    /// flag; both read the same spellings.
    #[command(after_long_help = "Examples:
  bitcoin-tools converter unit --bitcoin 1.5
  bitcoin-tools converter unit --sat 150000000 --json
  echo '{\"amount\": \"1.5\", \"denomination\": \"bitcoin\"}' | bitcoin-tools converter unit --input -")]
    Unit(unit::Args),

    /// Flip byte order between the wire's and the display's.
    ///
    /// Bitcoin writes hashes into blocks and transactions in one order and
    /// shows them to people in the other. This is the operation relating the
    /// two — a txid copied from an explorer never appears verbatim in the raw
    /// transaction that produced it.
    ///
    /// One command covers both directions, because reversal is an involution:
    /// a direction flag would decorate the request without changing what is
    /// computed.
    #[command(after_long_help = "Examples:
  bitcoin-tools converter reverse-bytes 0xdeadbeef
  bitcoin-tools converter reverse-bytes --input request.json --json")]
    ReverseBytes(reverse::Args),
}

impl Command {
    /// Run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self, ctx: Context) -> Result<()> {
        match self {
            Command::Base(args) => base::run(args, ctx),
            Command::Unit(args) => unit::run(args, ctx),
            Command::ReverseBytes(args) => reverse::run(args, ctx),
        }
    }
}
