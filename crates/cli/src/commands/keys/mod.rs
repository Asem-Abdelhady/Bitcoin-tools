//! Private keys, public keys and addresses — the `keys` group.
//!
//! Two commands: mint a key, or take one and show everything public it
//! produces. Named as the server names them, and answering the same shapes.
//!
//! # The private key never arrives as an argument
//!
//! `keys public --private-key-file key.hex`, never `--private-key <HEX>`.
//! Arguments are visible in `ps` to every user on the machine and land verbatim
//! in shell history; a file, or stdin under `-`, is neither. See
//! [`input::secret_from`](crate::input::secret_from), which is the one place
//! that reads one.
//!
//! # Two flags that change what the answer *is*
//!
//! `--network` decides the WIF prefix and every address version byte, and
//! `--uncompressed` changes the public key's serialization and therefore the
//! addresses. A key rendered under the wrong one of either is a key for a wallet
//! the user does not have, which is why both are stated rather than guessed at
//! from the value.
//!
//! They still have defaults — mainnet and compressed, matching the API — because
//! they are what every modern wallet uses and a tool that made you say so every
//! time would be answering a question nobody asked. The domain deliberately
//! gives `Network` no `Default`: picking one is a front end's decision.

pub mod generate;
pub mod public;

use anyhow::Result;
use clap::Subcommand;

use bitcoin_tools_core::network::Network;

use crate::output::Context;

/// The default network, stated once for both commands.
///
/// Shared with [`hd`](crate::commands::hd) through a `use`, so the two groups
/// cannot drift the way the API's `services::default_network` stops its own
/// two from drifting.
pub const fn default_network() -> Network {
    Network::Mainnet
}

/// Whether the public key is used in compressed form, by default.
pub const fn default_compressed() -> bool {
    true
}

/// The commands under `keys`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a new private key from the operating system's randomness.
    ///
    /// The key is printed as hex, decimal, binary and WIF. It is drawn on this
    /// machine and never leaves it, but it is still written to stdout — so
    /// redirect it into a file rather than into a scrollback buffer, and do not
    /// use a key generated here to hold value unless this machine is the one
    /// that will keep it.
    #[command(after_long_help = "Examples:
  bt keys generate
  bt keys generate --network testnet --uncompressed
  bt keys generate --json > key.json")]
    Generate(generate::Args),

    /// Show the public key and every address a private key produces.
    ///
    /// Only public data comes back: the private key is read and never echoed.
    ///
    /// The key is read from a file, or from stdin with `-`, and never from an
    /// argument — arguments are visible to every process on the machine.
    #[command(after_long_help = "Examples:
  bt keys public --private-key-file key.hex
  printf %s \"$KEY\" | bt keys public --private-key-file -
  bt keys public --input request.json --json")]
    Public(public::Args),
}

impl Command {
    /// Run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self, ctx: Context) -> Result<()> {
        match self {
            Command::Generate(args) => generate::run(args, ctx),
            Command::Public(args) => public::run(args, ctx),
        }
    }
}
