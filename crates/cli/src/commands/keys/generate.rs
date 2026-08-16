//! `keys generate` — a new private key.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::PrivateKey;
use bitcoin_tools_core::network::Network;

use crate::commands::keys::{default_compressed, default_network};
use crate::input;
use crate::output::{Context, Fields, Output, yes_no};

/// What `keys generate` accepts.
///
/// Nothing is required — `keys generate` on its own produces a compressed
/// mainnet key — so unlike every other command here there is no required group.
/// `--input` is still accepted, for a script holding one request file it feeds
/// to both front ends, and it conflicts with the two flags rather than joining
/// them in a group: `--network` and `--uncompressed` are used *together*, so a
/// mutually-exclusive group over all three would forbid the ordinary case.
#[derive(Debug, clap::Args)]
#[command(
    override_usage = "bitcoin-tools keys generate [--network <NETWORK>] [--uncompressed]\n\
                          \x20      bitcoin-tools keys generate --input <FILE>"
)]
pub struct Args {
    /// Which network the key is for: mainnet, testnet, signet or regtest.
    ///
    /// Decides the WIF prefix and every address version byte.
    #[arg(long, value_name = "NETWORK", default_value_t = default_network())]
    network: Network,

    /// Produce a key whose public form is the 65-byte uncompressed encoding.
    ///
    /// Almost never what you want: it changes the WIF, changes every address,
    /// and cannot appear in a version 0 witness program at all.
    #[arg(long)]
    uncompressed: bool,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds {"network"?, "compressed"?} — the HTTP API's request
    /// body, in which both fields are optional, so `{}` is valid.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["network", "uncompressed"])]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
///
/// Both fields carry the API's defaults, so a partial request file means what it
/// means there.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    #[serde(default = "default_network")]
    network: Network,
    #[serde(default = "default_compressed")]
    compressed: bool,
}

/// A private key in every form it is written in.
///
/// # This type hand-writes its `Debug`
///
/// Every field is the secret. Deriving `Debug` here would undo the redaction
/// core already writes for `PrivateKey`, and the first `tracing` layer or
/// `dbg!` anyone adds is what would find that out.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyView {
    /// The 32 bytes, hex.
    hex: String,
    /// The same number in base 10 — a scalar, and readable as one.
    decimal: String,
    /// The same number in base 2.
    binary: String,
    /// Wallet Import Format: the key, the network, the compression flag and a
    /// checksum, in one Base58Check string. This is the form a wallet imports.
    wif: String,
}

impl fmt::Debug for PrivateKeyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyView(<redacted>)")
    }
}

impl From<&PrivateKey> for PrivateKeyView {
    fn from(key: &PrivateKey) -> Self {
        let number = key.to_number();
        PrivateKeyView {
            hex: hex::encode(&key.to_be_bytes()),
            decimal: number.to_decimal(),
            binary: number.to_binary(),
            wif: key.to_wif(),
        }
    }
}

/// A generated key, with the two facts that decide what it means.
///
/// Derives `Debug`: the secret is behind [`PrivateKeyView`], whose own impl
/// redacts it, and a derived `Debug` calls that. Only the leaf needs writing.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyResponse {
    network: Network,
    compressed: bool,
    private_key: PrivateKeyView,
}

impl Output for GenerateKeyResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("network", self.network)
            .row("compressed", yes_no(self.compressed))
            .blank()
            .row("wif", &self.private_key.wif)
            .row("hex", &self.private_key.hex)
            .row("decimal", &self.private_key.decimal)
            .row("binary", &self.private_key.binary)
            .write(w)
    }
}

/// Draw a key and print it.
///
/// Infallible in the domain — core retries the vanishingly rare out-of-range
/// draw rather than handing back an error nobody could act on — so the only way
/// this fails is an unreadable request file or an unwritable stdout.
///
/// # Errors
///
/// If the request cannot be read, or stdout cannot be written.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let request: Request = input::resolve(source.as_deref(), || {
        Some(Request {
            network: args.network,
            compressed: !args.uncompressed,
        })
    })?;

    let key = PrivateKey::generate(request.network, request.compressed);

    ctx.emit(&GenerateKeyResponse {
        network: key.network,
        compressed: key.compressed,
        private_key: (&key).into(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redaction is the point of the hand-written impl, and so is the half
    /// that still prints — a `Debug` that blanked everything would pass the
    /// first assertion and lose the only reason `Debug` is there.
    #[test]
    fn no_part_of_the_key_appears_in_debug_output() {
        let key = PrivateKey::generate(Network::Mainnet, true);
        let response = GenerateKeyResponse {
            network: key.network,
            compressed: key.compressed,
            private_key: (&key).into(),
        };
        let rendered = format!("{response:?}");

        for secret in [key.to_wif(), hex::encode(&key.to_be_bytes())] {
            assert!(!rendered.contains(&secret), "{secret} leaked: {rendered}");
        }
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("Mainnet"),
            "…and the rest still prints: {rendered}"
        );
    }

    /// A request file uses the API's field names and its defaults, so `{}` is a
    /// compressed mainnet key on both front ends.
    #[test]
    fn an_empty_request_file_is_a_compressed_mainnet_key() {
        let request: Request = serde_json::from_str("{}").unwrap();
        assert_eq!(request.network, Network::Mainnet);
        assert!(request.compressed);
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"netwrok":"testnet"}"#).is_err());
    }
}
