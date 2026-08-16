//! `converter reverse-bytes` — wire order ⇄ display order.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::ArgGroup;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::hex;
use bitcoin_tools_core::transactions::tx::Tx;

use crate::input::{self, hex_bytes};
use crate::output::{Context, Fields, Output};

/// The noun this command's error messages use.
///
/// Not "transaction" or "hash": the whole point is that it does not care what
/// the bytes are.
const SUBJECT: &str = "input";

/// The largest payload this command will flip.
///
/// Reversal is linear and could take anything, so the cap is a policy rather
/// than a limit of the operation — and the policy is that the byte-order tool
/// must not be the stingiest door in the program. [`Tx::MAX_SIZE`] is the
/// largest input anything here accepts, so a value some other command would
/// read cannot be one this command refuses.
const MAX_BYTES: usize = Tx::MAX_SIZE;

/// What `converter reverse-bytes` accepts.
///
/// One positional value, because this command has no notation to name — hex in,
/// hex out. Its siblings put theirs in the flag; see [the module note](super).
///
/// The value and `--input` are one required, non-multiple [`ArgGroup`], which
/// is how every command in the crate says "exactly one source". clap takes a
/// positional in a group as readily as a flag, so the shape the next four
/// groups copy is the same whether or not their arguments look like these.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bt converter reverse-bytes <HEX>\n\
                          \x20      bt converter reverse-bytes --input <FILE>")]
#[command(group = ArgGroup::new("source").args(["hex", "input"]).required(true))]
pub struct Args {
    /// The bytes to flip, as hex.
    ///
    /// A leading `0x` and surrounding whitespace are accepted and ignored.
    #[arg(value_name = "HEX")]
    hex: Option<String>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds a `hex` field — the same shape the HTTP API takes.
    /// This is also the way to flip a payload too long for a shell argument:
    /// the cap here is four megabytes, and a command line runs out long before
    /// that.
    #[arg(long, value_name = "FILE")]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    hex: String,
}

/// The same bytes, both ways round.
///
/// The field names and their JSON spellings match the HTTP API's response for
/// this operation, so a script can move between the two front ends without
/// learning a second vocabulary.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReverseOutput {
    /// The input as this program read it: `0x` and whitespace gone, lowercase.
    ///
    /// Echoed because without it a caller cannot tell what was actually
    /// decoded — and because feeding `reversed` back in returns exactly this.
    input: String,
    /// The same bytes, last first.
    reversed: String,
    /// How many bytes were flipped.
    bytes: usize,
}

impl Output for ReverseOutput {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("input", &self.input)
            .row("reversed", &self.reversed)
            .row("bytes", self.bytes)
            .write(w)
    }
}

/// Read the bytes, flip them, emit.
///
/// The flip itself is `hex::encode_rev`, and that is the layering rather than
/// an omission: reversing is *rendering* — one encoding of the bytes and one
/// encoding of them backwards — so it belongs with the view.
///
/// # Errors
///
/// If the request cannot be read, or the value is empty, is not whole bytes of
/// hex, or is past [`MAX_BYTES`].
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    // Taken out rather than cloned: the rest of `args` is consumed below.
    let source = args.input.take();
    let request: Request =
        input::resolve(source.as_deref(), || args.hex.map(|hex| Request { hex }))?;

    let bytes = hex_bytes(&request.hex, SUBJECT, MAX_BYTES)?;

    ctx.emit(&ReverseOutput {
        input: hex::encode(&bytes),
        reversed: hex::encode_rev(&bytes),
        bytes: bytes.len(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cap_is_the_largest_input_this_program_takes() {
        assert_eq!(MAX_BYTES, Tx::MAX_SIZE);

        // The help text beside this argument quotes the figure in megabytes,
        // and prose cannot be derived from a constant. If this changes, that
        // sentence and the README are what to fix.
        assert_eq!(MAX_BYTES, 4_000_000, "the help says four megabytes");
    }

    /// The request shape is the HTTP API's, so a file written for one front end
    /// works with the other.
    #[test]
    fn the_request_is_the_api_request() {
        let request: Request = serde_json::from_str(r#"{"hex":"deadbeef"}"#).unwrap();
        assert_eq!(request.hex, "deadbeef");
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(
            serde_json::from_str::<Request>(r#"{"hexx":"deadbeef"}"#).is_err(),
            "deny_unknown_fields is what turns a typo into a message"
        );
    }
}
