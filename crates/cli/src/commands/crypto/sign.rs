//! `crypto sign` — a deterministic ECDSA signature over one digest.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::crypto::ecdsa::MESSAGE_SIZE;
use bitcoin_tools_core::crypto::secp::SCALAR_SIZE;
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{PrivateKey, PrivateKeyError};

use crate::commands::crypto::{SignatureView, message_hash, write_signature};
use crate::commands::keys::{default_compressed, default_network};
use crate::input;
use crate::output::{Context, Fields, Output};

/// What `crypto sign` accepts.
///
/// The key names a file and the digest does not, because one is a secret and the
/// other is not. `--input` carries both and therefore conflicts with all three
/// flags; the two required ones say `required_unless_present` rather than
/// joining an `ArgGroup`, because the rule here is "these together, or that" and
/// a mutually-exclusive group cannot say that.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bt crypto sign --private-key-file <FILE> \
                            --message-hash <HEX> [--uncompressed]\n\
                          \x20      bt crypto sign --input <FILE>")]
pub struct Args {
    /// A file holding the private key as 64 hex digits, or `-` for stdin.
    ///
    /// There is deliberately no flag that takes the key itself.
    #[arg(long, value_name = "FILE", required_unless_present = "input")]
    private_key_file: Option<PathBuf>,

    /// The 32-byte digest to sign, as hex.
    ///
    /// A digest, not a message: nothing here hashes for you, because what a
    /// Bitcoin signature commits to is a sighash and that needs data a raw
    /// transaction does not carry.
    #[arg(long, value_name = "HEX", required_unless_present = "input")]
    message_hash: Option<String>,

    /// Report the public key in its 65-byte uncompressed form.
    ///
    /// Changes nothing about the signature — it is the same scalar either way —
    /// only how the key beside it is printed.
    #[arg(long)]
    uncompressed: bool,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds {"privateKey", "messageHash", "compressed"?} — the HTTP
    /// API's request body.
    #[arg(long, value_name = "FILE",
          conflicts_with_all = ["private_key_file", "message_hash", "uncompressed"])]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
///
/// Hand-writes `Debug`: it holds the key.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    private_key: String,
    message_hash: String,
    #[serde(default = "default_compressed")]
    compressed: bool,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("private_key", &"<redacted>")
            .field("message_hash", &self.message_hash)
            .field("compressed", &self.compressed)
            .finish()
    }
}

/// Why the request could not be signed.
///
/// Two named cases rather than one, because they are two different mistakes:
/// a key that is not a scalar, and bytes that are not a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// The private key is not 32 bytes, or is 32 bytes that are not a scalar.
    Key(PrivateKeyError),
    /// The message hash is not the width ECDSA signs.
    MessageHash {
        /// What was supplied, in bytes.
        got: usize,
    },
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignError::Key(e) => write!(f, "{e}"),
            SignError::MessageHash { got } => write!(
                f,
                "a message hash is {MESSAGE_SIZE} bytes, got {got}; ECDSA signs a \
                 digest, not a message"
            ),
        }
    }
}

impl std::error::Error for SignError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignError::Key(e) => Some(e),
            SignError::MessageHash { .. } => None,
        }
    }
}

/// A signature, and the two public things it can be checked against.
///
/// Holds no secret: the key that made it is not here, only the public key it
/// verifies under — so the answer is safe to pipe even though the input was not.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignResponse {
    signature: SignatureView,
    public_key: String,
    message_hash: String,
}

impl Output for SignResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields
            .row("publicKey", &self.public_key)
            .row("messageHash", &self.message_hash);

        write_signature(w, &mut fields, &self.signature)
    }
}

/// Read the key and the digest, sign, emit.
///
/// # Errors
///
/// If the request cannot be read, the key is not a scalar, or the digest is not
/// 32 bytes.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let key_file = args.private_key_file.take();
    let hash = args.message_hash.take();

    let request: Request = input::resolve_reading(source.as_deref(), || {
        // Both are `required_unless_present = "input"`, so clap has already
        // refused the case where one is missing and the other is not.
        match (key_file.as_deref(), hash) {
            (Some(path), Some(message_hash)) => Ok(Some(Request {
                private_key: input::secret_from(path)?,
                message_hash,
                compressed: !args.uncompressed,
            })),
            _ => Ok(None),
        }
    })?;

    // The value is the secret, so no excerpt and no context line naming it.
    let bytes: [u8; SCALAR_SIZE] =
        input::hex_bytes_exact(&request.private_key, "private key", |got| {
            SignError::Key(PrivateKeyError::WrongLength { got })
        })?;

    let key = PrivateKey::from_be_bytes(&bytes, default_network(), request.compressed)
        .map_err(SignError::Key)
        .context("reading the private key")?;

    let hash = message_hash(&request.message_hash, |got| SignError::MessageHash { got })
        .with_context(|| format!("reading {}", input::excerpt(&request.message_hash)))?;

    let signature = key.sign(&hash);

    ctx.emit(&SignResponse {
        signature: (&signature).into(),
        public_key: key.public_key().to_string(),
        message_hash: hex::encode(&hash),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            private_key: "01".repeat(SCALAR_SIZE),
            message_hash: "ab".repeat(MESSAGE_SIZE),
            compressed: true,
        }
    }

    /// The request holds a key, so its `Debug` redacts it — and keeps the
    /// digest, which is public and is what you need to reproduce the run.
    #[test]
    fn the_request_does_not_print_the_key() {
        let rendered = format!("{:?}", request());

        assert!(!rendered.contains("0101"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("abab"),
            "the digest still prints: {rendered}"
        );
    }

    /// The answer carries nothing the request gave it. A signing command that
    /// echoed the key back is what this rules out.
    #[test]
    fn the_answer_does_not_carry_the_key() {
        let request = request();
        let bytes: [u8; SCALAR_SIZE] = input::hex_bytes_exact(&request.private_key, "k", |got| {
            SignError::Key(PrivateKeyError::WrongLength { got })
        })
        .unwrap();
        let key = PrivateKey::from_be_bytes(&bytes, default_network(), true).unwrap();
        let hash =
            message_hash(&request.message_hash, |got| SignError::MessageHash { got }).unwrap();

        let response = SignResponse {
            signature: (&key.sign(&hash)).into(),
            public_key: key.public_key().to_string(),
            message_hash: hex::encode(&hash),
        };
        let json = serde_json::to_string(&response).unwrap();

        assert!(!json.contains(&request.private_key), "the key is in {json}");
        assert!(!json.contains(&key.to_wif()), "the WIF is in {json}");
    }

    /// RFC 6979: the same key and the same digest produce the same signature,
    /// which is what makes a repeated nonce impossible.
    #[test]
    fn signing_is_deterministic() {
        let key = PrivateKey::from_hex(&"01".repeat(SCALAR_SIZE), default_network(), true).unwrap();
        let hash = [0xab; MESSAGE_SIZE];

        assert_eq!(key.sign(&hash).to_compact(), key.sign(&hash).to_compact());
    }

    /// The digest's width failure names what it was reading, rather than
    /// borrowing the size-cap vocabulary a script or a transaction gets.
    #[test]
    fn a_short_message_hash_says_what_it_was_reading() {
        let error = message_hash("abab", |got| SignError::MessageHash { got }).unwrap_err();
        let message = error.to_string();

        assert!(message.contains("32 bytes"), "{message}");
        assert!(message.contains("got 2"), "{message}");
        assert!(!message.contains("maximum"), "not a size cap: {message}");
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(
            serde_json::from_str::<Request>(r#"{"privateKey":"01","messageHsh":"ab"}"#).is_err()
        );
    }
}
