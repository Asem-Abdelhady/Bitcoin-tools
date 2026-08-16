//! `keys public` — everything public a private key produces.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::ArgGroup;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::crypto::secp::SCALAR_SIZE;
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{PrivateKey, PrivateKeyError, PublicKey};
use bitcoin_tools_core::network::Network;

use crate::commands::address::{AddressesView, write_addresses};
use crate::commands::keys::{default_compressed, default_network};
use crate::input;
use crate::output::{Context, Fields, Output, yes_no};

/// What `keys public` accepts.
///
/// The private key names a **file**, not a value: see [the group note](super).
/// That file and `--input` are one required, non-multiple [`ArgGroup`], which is
/// how every command in the crate says "exactly one source" — so giving both, or
/// neither, is a usage error clap reports without a check here.
#[derive(Debug, clap::Args)]
#[command(
    override_usage = "bitcoin-tools keys public --private-key-file <FILE> \
                            [--network <NETWORK>] [--uncompressed]\n\
                          \x20      bitcoin-tools keys public --input <FILE>"
)]
#[command(group = ArgGroup::new("source")
    .args(["private_key_file", "input"])
    .required(true))]
pub struct Args {
    /// A file holding the private key as 64 hex digits, or `-` for stdin.
    ///
    /// A leading `0x` and surrounding whitespace are accepted and ignored.
    /// There is deliberately no flag that takes the key itself — an argument is
    /// visible in `ps` and in shell history.
    #[arg(long, value_name = "FILE")]
    private_key_file: Option<PathBuf>,

    /// Which network the addresses are for: mainnet, testnet, signet or regtest.
    #[arg(long, value_name = "NETWORK", default_value_t = default_network())]
    network: Network,

    /// Treat the public key as the 65-byte uncompressed encoding.
    ///
    /// Changes every address, and removes the two version 0 witness ones
    /// entirely — BIP143 forbids an uncompressed key in a v0 program.
    #[arg(long)]
    uncompressed: bool,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file carries a `privateKey` and optionally a `network` and a
    /// `compressed` flag — the HTTP API's request body. This is the one place
    /// the key itself may be written down, because a file is not `argv`.
    ///
    /// It carries the network and the compression flag too, so giving either of
    /// those beside it is a usage error rather than a silently ignored
    /// argument: a request answered for mainnet when testnet was asked for is
    /// the worst shape a failure takes, because it exits 0.
    #[arg(long, value_name = "FILE", conflicts_with_all = ["network", "uncompressed"])]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
///
/// Hand-writes `Debug`: it holds the key.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    private_key: String,
    #[serde(default = "default_network")]
    network: Network,
    #[serde(default = "default_compressed")]
    compressed: bool,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("private_key", &"<redacted>")
            .field("network", &self.network)
            .field("compressed", &self.compressed)
            .finish()
    }
}

/// A public key, in each encoding and with the coordinates behind them.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyView {
    /// The key as this program writes it — compressed or not, per the flag.
    hex: String,
    /// The 33-byte SEC1 encoding: a parity byte and the x coordinate.
    compressed: String,
    /// The 65-byte SEC1 encoding: `04`, then both coordinates.
    uncompressed: String,
    /// The 32-byte x-only encoding taproot uses.
    x_only: String,
    /// The x coordinate.
    x: String,
    /// The y coordinate. Not carried by the compressed form — a parity bit and
    /// the curve equation are enough to recover it.
    y: String,
    /// HASH160 of the key as encoded, which is what a P2PKH or P2WPKH output
    /// commits to.
    pubkey_hash: String,
}

impl From<&PublicKey> for PublicKeyView {
    fn from(key: &PublicKey) -> Self {
        let (x, y) = key.coordinates();
        PublicKeyView {
            hex: key.to_string(),
            compressed: hex::encode(&key.to_compressed()),
            uncompressed: hex::encode(&key.to_uncompressed()),
            x_only: hex::encode(&key.to_x_only()),
            x: hex::encode(&x),
            y: hex::encode(&y),
            pubkey_hash: key.pubkey_hash().to_string(),
        }
    }
}

/// Everything public that follows from one private key.
///
/// Derives `Debug` and holds no secret: this command takes a private key and
/// returns only public data, which is the rule that keeps `Cache-Control:
/// no-store` meaningful on the API and keeps this command safe to pipe.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    network: Network,
    compressed: bool,
    public_key: PublicKeyView,
    addresses: AddressesView,
    /// The witness program a P2SH-P2WPKH output hashes. `null` for an
    /// uncompressed key, for the reason the address set gives.
    p2wpkh_redeem_script: Option<String>,
}

impl Output for PublicKeyResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields
            .row("network", self.network)
            .row("compressed", yes_no(self.compressed))
            .blank()
            .row("publicKey", &self.public_key.hex)
            .row("compressedKey", &self.public_key.compressed)
            .row("uncompressedKey", &self.public_key.uncompressed)
            .row("xOnly", &self.public_key.x_only)
            .row("x", &self.public_key.x)
            .row("y", &self.public_key.y)
            .row("pubkeyHash", &self.public_key.pubkey_hash)
            .maybe(0, "p2wpkhRedeemScript", self.p2wpkh_redeem_script.as_ref());

        write_addresses(w, &mut fields, &self.addresses)
    }
}

/// The noun this command's width errors use.
const SUBJECT: &str = "private key";

/// Read the key, derive everything public, emit.
///
/// # Errors
///
/// If the request cannot be read, or the value is not 32 bytes of hex, or is 32
/// bytes that are not a scalar — zero, or at or above the group order.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let key_file = args.private_key_file.take();

    let request: Request = input::resolve_reading(source.as_deref(), || {
        key_file
            .as_deref()
            .map(|path| {
                Ok(Request {
                    private_key: input::secret_from(path)?,
                    network: args.network,
                    compressed: !args.uncompressed,
                })
            })
            .transpose()
    })?;

    // No excerpt and no context line naming the value: the value *is* the
    // secret. The width and the reason are what a user needs, and both are in
    // the error itself.
    let bytes: [u8; SCALAR_SIZE] = input::hex_bytes_exact(&request.private_key, SUBJECT, |got| {
        PrivateKeyError::WrongLength { got }
    })?;

    let private = PrivateKey::from_be_bytes(&bytes, request.network, request.compressed)
        .context("reading the private key")?;
    let key = private.public_key();

    ctx.emit(&PublicKeyResponse {
        network: request.network,
        compressed: private.compressed,
        public_key: (&key).into(),
        addresses: AddressesView::of(&key, request.network),
        p2wpkh_redeem_script: key.p2wpkh_redeem_script().ok().map(|s| hex::encode(&s)),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            private_key: "01".repeat(SCALAR_SIZE),
            network: Network::Mainnet,
            compressed: true,
        }
    }

    /// The request holds a key, so its `Debug` redacts it — and keeps printing
    /// the two fields that make the answer mean what it means.
    #[test]
    fn the_request_does_not_print_the_key() {
        let rendered = format!("{:?}", request());

        assert!(!rendered.contains("0101"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("Mainnet"), "{rendered}");
        assert!(rendered.contains("compressed: true"), "{rendered}");
    }

    /// The answer is public data only. A command that handed the key back
    /// because one was given is the thing this asserts against.
    #[test]
    fn the_answer_carries_nothing_the_request_gave_it() {
        let request = request();
        let bytes: [u8; SCALAR_SIZE] =
            input::hex_bytes_exact(&request.private_key, SUBJECT, |got| {
                PrivateKeyError::WrongLength { got }
            })
            .unwrap();
        let private =
            PrivateKey::from_be_bytes(&bytes, request.network, request.compressed).unwrap();
        let key = private.public_key();

        let response = PublicKeyResponse {
            network: request.network,
            compressed: private.compressed,
            public_key: (&key).into(),
            addresses: AddressesView::of(&key, request.network),
            p2wpkh_redeem_script: key.p2wpkh_redeem_script().ok().map(|s| hex::encode(&s)),
        };
        let json = serde_json::to_string(&response).unwrap();

        assert!(!json.contains(&request.private_key), "the key is in {json}");
        assert!(!json.contains(&private.to_wif()), "the WIF is in {json}");
        assert!(json.contains(&key.to_string()));
    }

    /// The wire shape is the HTTP API's, so a file written for one front end
    /// works with the other.
    #[test]
    fn the_request_file_is_the_api_request() {
        let json = format!(r#"{{"privateKey":"{}"}}"#, "01".repeat(SCALAR_SIZE));
        let request: Request = serde_json::from_str(&json).unwrap();

        assert_eq!(request.network, Network::Mainnet, "the API's default");
        assert!(request.compressed, "the API's default");
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"privatekey":"01"}"#).is_err());
    }
}
