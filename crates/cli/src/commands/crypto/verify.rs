//! `crypto verify` — does this signature check out.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::crypto::ecdsa::verify as verify_ecdsa;
use bitcoin_tools_core::keys::PublicKey;

use crate::commands::crypto::{SignatureEncoding, SignatureView, message_hash, signature};
use crate::input;
use crate::output::{Context, Fields, Output, yes_no};

/// What `crypto verify` accepts.
///
/// Nothing here is a secret — a public key, a digest and a signature are all
/// public — so all three are ordinary flags. They are given together or replaced
/// wholesale by `--input`.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bitcoin-tools crypto verify --public-key <HEX> \
                            --message-hash <HEX> --signature <HEX>\n\
                          \x20      bitcoin-tools crypto verify --input <FILE>")]
pub struct Args {
    /// The public key, as 33 or 65 bytes of SEC1 hex.
    #[arg(long, value_name = "HEX", required_unless_present = "input")]
    public_key: Option<String>,

    /// The 32-byte digest the signature is over, as hex.
    #[arg(long, value_name = "HEX", required_unless_present = "input")]
    message_hash: Option<String>,

    /// The signature, as hex.
    ///
    /// Read as compact if it is exactly 64 bytes and as DER otherwise. The
    /// answer reports which, because that is this program's inference and not
    /// something you stated.
    #[arg(long, value_name = "HEX", required_unless_present = "input")]
    signature: Option<String>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds {"publicKey", "messageHash", "signature"} — the HTTP
    /// API's request body.
    #[arg(long, value_name = "FILE",
          conflicts_with_all = ["public_key", "message_hash", "signature"])]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
///
/// Derives `Debug`: every field is public.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    public_key: String,
    message_hash: String,
    signature: String,
}

/// Why the request could not be checked.
///
/// Distinct from "the signature does not verify", which is not an error at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongMessageHash {
    /// What was supplied, in bytes.
    got: usize,
}

impl std::fmt::Display for WrongMessageHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a message hash is {} bytes, got {}",
            bitcoin_tools_core::crypto::ecdsa::MESSAGE_SIZE,
            self.got
        )
    }
}

impl std::error::Error for WrongMessageHash {}

/// The verdict, and everything it was reached from.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    /// Whether the signature checks out.
    ///
    /// `false` is an answer, not a failure — this command exits 0 either way,
    /// because "does it verify" is the question it exists to answer and there is
    /// no sub-reason a caller could act on.
    valid: bool,
    /// Which encoding the signature was read in, inferred from its length.
    encoding: SignatureEncoding,
    signature: SignatureView,
    /// The key as this program read it back, so a mis-typed one is visible.
    public_key: String,
}

impl Output for VerifyResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields
            .row("valid", yes_no(self.valid))
            .row("encoding", self.encoding)
            .row("publicKey", &self.public_key);

        crate::commands::crypto::write_signature(w, &mut fields, &self.signature)
    }
}

/// Read the three values, check the signature, emit.
///
/// # Errors
///
/// If the request cannot be read, the key is not a point on the curve, the
/// digest is not 32 bytes, or the signature is not a signature in either
/// encoding. Not if it simply fails to verify.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();

    let request: Request = input::resolve(source.as_deref(), || {
        // All three are `required_unless_present = "input"`, so clap has already
        // refused any partial set.
        Some(Request {
            public_key: args.public_key?,
            message_hash: args.message_hash?,
            signature: args.signature?,
        })
    })?;

    let hash = message_hash(&request.message_hash, |got| WrongMessageHash { got })
        .with_context(|| format!("reading {}", input::excerpt(&request.message_hash)))?;

    let key = PublicKey::from_hex(&request.public_key)
        .with_context(|| format!("reading {}", input::excerpt(&request.public_key)))?;

    let (signature, encoding) = signature(&request.signature)
        .with_context(|| format!("reading {}", input::excerpt(&request.signature)))?;

    ctx.emit(&VerifyResponse {
        valid: verify_ecdsa(&hash, &signature, &key.point()),
        encoding,
        signature: (&signature).into(),
        public_key: key.to_string(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_tools_core::crypto::ecdsa::{COMPACT_SIZE, MESSAGE_SIZE};
    use bitcoin_tools_core::keys::PrivateKey;
    use bitcoin_tools_core::network::Network;

    fn signed() -> (PublicKey, [u8; MESSAGE_SIZE], String) {
        let key = PrivateKey::from_hex(&"01".repeat(32), Network::Mainnet, true).unwrap();
        let hash = [0xab; MESSAGE_SIZE];
        let sig = key.sign(&hash);

        (
            key.public_key(),
            hash,
            bitcoin_tools_core::hex::encode(&sig.to_der()),
        )
    }

    /// The length decides the encoding, and both readings of one signature are
    /// the same signature — which is what makes reporting `encoding` back
    /// useful rather than decorative.
    #[test]
    fn the_length_decides_the_encoding() {
        let (_, _, der) = signed();
        let (parsed, encoding) = signature(&der).unwrap();
        assert_eq!(encoding, SignatureEncoding::Der);

        let compact = bitcoin_tools_core::hex::encode(&parsed.to_compact());
        assert_eq!(compact.len(), COMPACT_SIZE * 2);

        let (again, encoding) = signature(&compact).unwrap();
        assert_eq!(encoding, SignatureEncoding::Compact);
        assert_eq!(
            again.to_der(),
            parsed.to_der(),
            "one signature, two spellings"
        );
    }

    /// A signature that does not verify is an answer. If this ever becomes an
    /// error, the command stops being able to say `no`.
    #[test]
    fn a_signature_that_does_not_verify_is_still_read() {
        let (key, _, der) = signed();
        let (signature, _) = signature(&der).unwrap();

        assert!(!verify_ecdsa(
            &[0x01; MESSAGE_SIZE],
            &signature,
            &key.point()
        ));
    }

    /// Something far too long to be DER hears about DER, not about a size cap:
    /// 72 bytes is a fact about the encoding rather than a policy of this
    /// program.
    #[test]
    fn an_oversized_signature_is_a_signature_error_not_a_size_error() {
        let message = signature(&"00".repeat(4096)).unwrap_err().to_string();

        assert!(!message.contains("maximum"), "{message}");
        assert!(message.to_lowercase().contains("der"), "{message}");
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        let json = r#"{"publicKey":"02","messageHash":"ab","signatur":"30"}"#;
        assert!(serde_json::from_str::<Request>(json).is_err());
    }
}
