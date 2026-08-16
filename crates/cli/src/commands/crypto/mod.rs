//! ECDSA over secp256k1 — the `crypto` group.
//!
//! Sign a 32-byte digest, or check a signature against one. Neither command
//! hashes anything: ECDSA signs a digest, and what a Bitcoin signature commits
//! to is a *sighash* — computed from the value and script of every output being
//! spent, which a raw transaction does not carry. Handing this a message and
//! quietly hashing it would produce a signature over the wrong thing and look
//! like it worked.
//!
//! # The private key never arrives as an argument
//!
//! `crypto sign --private-key-file key.hex`, for the reason
//! [`keys`](crate::commands::keys) gives. The message hash is not a secret and
//! is an ordinary flag.
//!
//! # A signature is read in whichever encoding its length says
//!
//! Exactly 64 bytes is compact; anything else is DER. `crypto verify` reports
//! `encoding` back, because that rule is this program's own inference rather
//! than something the user stated — and a caller who meant the other one should
//! be able to see that it was read the way they meant.

pub mod sign;
pub mod verify;

use std::fmt;
use std::io::{self, Write};

use anyhow::Result;
use clap::Subcommand;
use serde::Serialize;

use bitcoin_tools_core::crypto::ecdsa::{
    COMPACT_SIZE, MAX_DER_SIZE, MESSAGE_SIZE, Signature, SignatureError,
};
use bitcoin_tools_core::hex;

use crate::input::{self, InputError};
use crate::output::{Context, Fields, yes_no};

/// Which of the two encodings a signature was read in.
///
/// The spellings are the HTTP API's, which are what a client branches on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureEncoding {
    /// BIP66 strict DER: a variable-length ASN.1 structure.
    Der,
    /// 64 bytes: `r` then `s`, each a fixed 32.
    Compact,
}

impl fmt::Display for SignatureEncoding {
    /// The same two words the serde spellings are.
    ///
    /// Written beside the derive rather than as a `match` in the renderer: two
    /// spellings of one value in two output modes is precisely what
    /// `both_modes_carry_the_same_values` exists to catch, and the way to not
    /// have that bug is to not have a second spelling.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            SignatureEncoding::Der => "der",
            SignatureEncoding::Compact => "compact",
        })
    }
}

/// Read the 32 bytes ECDSA signs.
///
/// One width, so both directions of it are the caller's own error — see
/// [`hex_bytes_exact`](crate::input::hex_bytes_exact).
///
/// # Errors
///
/// `wrong_width(got)` if the value is not [`MESSAGE_SIZE`] bytes, or the input
/// error if it is not hex.
pub fn message_hash<E>(
    hex: &str,
    wrong_width: impl FnOnce(usize) -> E,
) -> Result<[u8; MESSAGE_SIZE]>
where
    E: std::error::Error + Send + Sync + 'static,
{
    input::hex_bytes_exact(hex, "message hash", wrong_width)
}

/// Read a signature, inferring its encoding from its length.
///
/// A value past [`MAX_DER_SIZE`] is a DER problem rather than a size-cap one:
/// 72 bytes is a fact about the encoding, not a policy of this program, so the
/// user hears `invalid signature` and not `too large`.
///
/// # Errors
///
/// If the value is not hex, or is not a signature in either encoding.
pub fn signature(value: &str) -> Result<(Signature, SignatureEncoding)> {
    let bytes = input::hex_bytes(value, "signature", MAX_DER_SIZE).map_err(|e| match e {
        InputError::TooLarge { .. } => anyhow::Error::from(SignatureError::Der),
        other => other.into(),
    })?;

    let read = if bytes.len() == COMPACT_SIZE {
        Signature::from_compact_slice(&bytes).map(|s| (s, SignatureEncoding::Compact))
    } else {
        Signature::from_der(&bytes).map(|s| (s, SignatureEncoding::Der))
    };

    Ok(read?)
}

/// A signature in both encodings, with the two scalars behind them.
///
/// The field names and their JSON spellings match the HTTP API's response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureView {
    /// Strict DER, as a Bitcoin script carries it.
    der: String,
    /// The 64-byte form: `r` then `s`.
    compact: String,
    /// The `r` scalar.
    r: String,
    /// The `s` scalar.
    s: String,
    /// Whether `s` is in the lower half of the order.
    ///
    /// Both `s` and `order - s` verify, so a signature can be mutated into a
    /// different valid one — which changes the txid. Consensus does not care;
    /// relay policy does, and everything this program produces is low-`s`.
    is_low_s: bool,
}

impl From<&Signature> for SignatureView {
    fn from(signature: &Signature) -> Self {
        let (r, s) = signature.parts();
        SignatureView {
            der: hex::encode(&signature.to_der()),
            compact: hex::encode(&signature.to_compact()),
            r: hex::encode(&r),
            s: hex::encode(&s),
            is_low_s: signature.is_low_s(),
        }
    }
}

impl SignatureView {
    /// Write the signature's parts into a block, `depth` levels in.
    ///
    /// Shared so the two commands render one signature identically.
    pub fn render(&self, fields: &mut Fields, depth: usize) {
        fields
            .nested(depth, "der", &self.der)
            .nested(depth, "compact", &self.compact)
            .nested(depth, "r", &self.r)
            .nested(depth, "s", &self.s)
            .nested(depth, "lowS", yes_no(self.is_low_s));
    }
}

/// Write a signature block on its own, headed.
///
/// # Errors
///
/// Whatever `w` produced.
pub fn write_signature(
    w: &mut dyn Write,
    fields: &mut Fields,
    signature: &SignatureView,
) -> io::Result<()> {
    fields.blank().heading(0, "signature");
    signature.render(fields, 1);
    fields.write(w)
}

/// The commands under `crypto`.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign a 32-byte message hash.
    ///
    /// Deterministic, per RFC 6979: no RNG is involved, and signing the same
    /// digest with the same key twice produces the same signature. That is the
    /// property that makes a repeated nonce — which hands an attacker the
    /// private key outright — impossible unless the digest repeats.
    ///
    /// The output is always low-s.
    #[command(after_long_help = "Examples:
  bt crypto sign --private-key-file key.hex --message-hash 0000...0001
  bt crypto sign --input request.json --json")]
    Sign(sign::Args),

    /// Check a signature against a message hash and a public key.
    ///
    /// A signature that does not verify is not an error: it exits 0 and says
    /// `valid  no`, because that is the question the command exists to answer.
    /// Only bytes that are not a signature at all are a failure.
    #[command(after_long_help = "Examples:
  bt crypto verify --public-key 0279be66... --message-hash 0000...0001 \\
      --signature 3044...
  bt crypto verify --input request.json --json")]
    Verify(verify::Args),
}

impl Command {
    /// Run the chosen command.
    ///
    /// # Errors
    ///
    /// Whatever the command produced.
    pub fn run(self, ctx: Context) -> Result<()> {
        match self {
            Command::Sign(args) => sign::run(args, ctx),
            Command::Verify(args) => verify::run(args, ctx),
        }
    }
}
