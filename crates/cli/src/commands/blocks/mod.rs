//! Block headers — the `blocks` group.
//!
//! Two commands over the same eighty bytes: the hash they produce, and the
//! fields they are made of. Both take the header positionally, because a header
//! is one payload with nothing to name and no notation to choose.
//!
//! The request shape is shared, exactly as the API shares `BlockHeaderRequest`
//! between `/blocks/hash` and `/blocks/header`. Two structs with identical
//! fields would let the two drift apart while looking deliberate.

pub mod hash;
pub mod header;

use anyhow::Result;
use clap::Subcommand;
use serde::Deserialize;

use bitcoin_tools_core::blocks::{BlockHeader, HeaderDecodeError};

use crate::input;
use crate::output::Context;

/// The noun both commands' errors use.
const SUBJECT: &str = "block header";

/// The resolved request, and the shape `--input` reads for both commands.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    /// The eighty bytes, hex.
    pub header: String,
}

/// Decode the eighty bytes, or say which way the length was wrong.
///
/// A header has no "too large": it is one width, so a byte over and a byte under
/// are one mistake with one answer, carrying the size actually supplied. That is
/// what [`hex_bytes_exact`](crate::input::hex_bytes_exact) is for, and it is why
/// this does not borrow the size-cap error a script or a transaction would get.
///
/// # Errors
///
/// If the value is not hex, or is not exactly [`BlockHeader::SIZE`] bytes, or is
/// eighty bytes the decoder refuses.
pub fn decode(request: &Request) -> Result<BlockHeader> {
    let bytes: [u8; BlockHeader::SIZE] = input::hex_bytes_exact(&request.header, SUBJECT, |got| {
        HeaderDecodeError::WrongLength {
            got,
            expected: BlockHeader::SIZE,
        }
    })?;

    Ok(BlockHeader::decode(&bytes)?)
}

/// The commands under `blocks`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Hash a block header.
    ///
    /// Printed in both orders: the one an explorer shows, and the one the bytes
    /// are actually in. A block hash is a double SHA-256 of the header, read
    /// backwards for display — which is why it appears to start with zeros.
    #[command(after_long_help = "Examples:
  bitcoin-tools blocks hash 0100000000000000...1dac2b7c
  bitcoin-tools blocks hash --input header.json --json")]
    Hash(hash::Args),

    /// Split a block header into its fields.
    ///
    /// Version, previous block, merkle root, time, bits and nonce — plus the
    /// target those bits expand to, the difficulty they imply, and whether this
    /// header's own hash actually meets it.
    #[command(after_long_help = "Examples:
  bitcoin-tools blocks header 0100000000000000...1dac2b7c
  bitcoin-tools blocks header --input header.json --json")]
    Header(header::Args),
}

impl Command {
    /// Run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self, ctx: Context) -> Result<()> {
        match self {
            Command::Hash(args) => hash::run(args, ctx),
            Command::Header(args) => header::run(args, ctx),
        }
    }
}

/// The positional-or-`--input` argument pair both commands take.
///
/// A macro rather than a shared `Args` struct, because clap's derive builds the
/// help text, the usage line and the group from the struct it is written on —
/// a shared struct would give both commands one usage line naming neither.
macro_rules! header_args {
    ($command:literal) => {
        /// What this command accepts.
        ///
        /// The header and `--input` are one required, non-multiple `ArgGroup`,
        /// which is how every command in the crate says "exactly one source".
        #[derive(Debug, clap::Args)]
        #[command(override_usage = concat!(
                                    "bitcoin-tools blocks ", $command, " <HEX>\n",
                                    "\x20      bitcoin-tools blocks ", $command, " --input <FILE>"
                                ))]
        #[command(group = clap::ArgGroup::new("source")
                                    .args(["header", "input"])
                                    .required(true))]
        pub struct Args {
            /// The eighty bytes of the header, as hex.
            ///
            /// A leading `0x` and surrounding whitespace are accepted and
            /// ignored.
            #[arg(value_name = "HEX")]
            header: Option<String>,

            /// Read the request from a JSON file, or `-` for stdin.
            ///
            /// The file holds a `header` field of hex — the same shape the HTTP API
            /// takes, and the same shape the other `blocks` command reads.
            #[arg(long, value_name = "FILE")]
            input: Option<std::path::PathBuf>,
        }

        impl Args {
            /// The request, resolved from whichever source was given.
            fn request(mut self) -> anyhow::Result<super::Request> {
                let source = self.input.take();
                crate::input::resolve(source.as_deref(), || {
                    self.header.map(|header| super::Request { header })
                })
            }
        }
    };
}

pub(crate) use header_args;
