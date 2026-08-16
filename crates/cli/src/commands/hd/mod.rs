//! BIP32/39/44 hierarchical deterministic wallets — the `hd` group.
//!
//! Two commands: mint a sentence and the wallet under it, or walk a path from a
//! seed you already have.
//!
//! # Both of these hand you a secret
//!
//! That is their purpose, unlike `keys public`, which takes one and returns only
//! public data. So both write a key to stdout, and stdout is a place that gets
//! redirected into scrollback, into `less`, and into files nobody deletes.
//! Redirect the output somewhere you meant to.
//!
//! # The passphrase and the seed never arrive as arguments
//!
//! `--passphrase-file` and `--seed-file`, for the reason
//! [`keys`](crate::commands::keys) gives — with `-` for stdin, which is the
//! scripting form. A passphrase is the one input here that a person is most
//! likely to type inline, and it is exactly the one that must not be.
//!
//! # What is missing, and it is deliberate for now
//!
//! Nothing takes a *mnemonic*. A user who kept the sentence and the passphrase —
//! which is what BIP39 trains people to keep — cannot get back to their wallet
//! here; they need the seed. The HTTP API has the same gap. Keep the seed.

pub mod derive;
pub mod mnemonic;

use std::fmt;
use std::io::{self, Write};

use anyhow::Result;
use clap::Subcommand;
use serde::Serialize;

use bitcoin_tools_core::hd::Xpriv;

use crate::output::{Context, Fields};

/// An extended key, with the fields BIP32 serializes it from.
///
/// # This type hand-writes its `Debug`
///
/// `xprv` is the whole wallet. Everything else here is public and keeps
/// printing, because a redaction that blanked the struct would lose the only
/// reason `Debug` is on it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedKeyView {
    /// Where in the tree this key sits.
    pub path: String,
    /// How many derivation steps from the master key.
    pub depth: u8,
    /// The first four bytes of this key's identifier.
    pub fingerprint: String,
    /// The parent's fingerprint, or four zero bytes at the master.
    pub parent_fingerprint: String,
    /// The 32 bytes of entropy that make a child index deterministic.
    ///
    /// Not a secret on its own, but an xpub plus a chain code plus any one
    /// child *private* key exposes every sibling — which is the reason an xpub
    /// is safe to publish only if no derived private key ever is.
    pub chain_code: String,
    /// The extended private key, Base58Check.
    pub xprv: String,
    /// The extended public key, Base58Check. Safe to publish.
    pub xpub: String,
}

impl fmt::Debug for ExtendedKeyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedKeyView")
            .field("path", &self.path)
            .field("depth", &self.depth)
            .field("fingerprint", &self.fingerprint)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("chain_code", &self.chain_code)
            .field("xprv", &"<redacted>")
            .field("xpub", &self.xpub)
            .finish()
    }
}

impl ExtendedKeyView {
    /// Render a key at a path.
    pub fn of(key: &Xpriv, path: String) -> Self {
        ExtendedKeyView {
            path,
            depth: key.depth(),
            fingerprint: key.fingerprint().to_string(),
            parent_fingerprint: key.parent_fingerprint().to_string(),
            chain_code: key.chain_code().to_string(),
            xprv: key.to_base58(),
            xpub: key.to_xpub().to_base58(),
        }
    }

    /// Write the key's fields into a block, `depth` levels in.
    pub fn render(&self, fields: &mut Fields, depth: usize) {
        fields
            .nested(depth, "path", &self.path)
            .nested(depth, "depth", self.depth)
            .nested(depth, "fingerprint", &self.fingerprint)
            .nested(depth, "parentFingerprint", &self.parent_fingerprint)
            .nested(depth, "chainCode", &self.chain_code)
            .nested(depth, "xprv", &self.xprv)
            .nested(depth, "xpub", &self.xpub);
    }
}

/// Write an extended key as its own headed block.
///
/// # Errors
///
/// Whatever `w` produced.
pub fn write_extended_key(
    w: &mut dyn Write,
    fields: &mut Fields,
    heading: &str,
    key: &ExtendedKeyView,
) -> io::Result<()> {
    fields.blank().heading(0, heading);
    key.render(fields, 1);
    fields.write(w)
}

/// The commands under `hd`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a BIP39 sentence and the wallet it opens.
    ///
    /// Prints the words with their entropy, indices and checksum, the seed they
    /// derive, and the BIP32 master key — everything needed to reconstruct the
    /// wallet, which is to say: the whole wallet.
    ///
    /// A passphrase is read from a file, or from stdin with `-`, and never from
    /// an argument.
    #[command(after_long_help = "Examples:
  bitcoin-tools hd mnemonic
  bitcoin-tools hd mnemonic --words 24 --network testnet
  bitcoin-tools hd mnemonic --passphrase-file secret.txt --json > wallet.json")]
    Mnemonic(mnemonic::Args),

    /// Derive a branch and its children from a seed.
    ///
    /// Prints the branch's extended keys, then each child with its private key,
    /// WIF and full address set. The purpose — BIP44, 49, 84 or 86 — is inferred
    /// from the path's first step, and decides which of the addresses is *the*
    /// address for that layout.
    ///
    /// The seed is read from a file, or from stdin with `-`, and never from an
    /// argument.
    #[command(after_long_help = "Examples:
  bitcoin-tools hd derive --seed-file seed.hex --path \"m/84h/0h/0h/0\" --count 5
  bitcoin-tools hd derive --seed-file - --path m/0 --json
  bitcoin-tools hd derive --input request.json")]
    Derive(derive::Args),
}

impl Command {
    /// Run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self, ctx: Context) -> Result<()> {
        match self {
            Command::Mnemonic(args) => mnemonic::run(args, ctx),
            Command::Derive(args) => derive::run(args, ctx),
        }
    }
}
