//! `converter base` — one value in base 2, 10 and 16.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use clap::ArgGroup;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::general::{Base, Number};

use crate::input;
use crate::output::{Context, Fields, Output};

/// What `converter base` accepts.
///
/// # The base is the flag, not a value it takes
///
/// `--hex 0xab12`, not `0xab12 --base hex`. The notation and the value arrive
/// together as one thing, which is how a person says it out loud, and it makes
/// the rule that matters here structural rather than enforced: a value cannot
/// be given without saying what it is written in, because there is no argument
/// that carries one without the other. `10` is two, ten or sixteen, and a tool
/// that guessed would return a confident wrong answer.
///
/// # One group states the whole rule
///
/// The three notations and `--input` are one required, non-multiple
/// [`ArgGroup`], so "exactly one of these four" is declared once. Two
/// notations, a notation with `--input`, and nothing at all are all the same
/// kind of mistake and clap reports each of them as a usage error without this
/// module containing a check.
#[derive(Debug, clap::Args)]
#[command(
    override_usage = "bitcoin-tools converter base --binary|--decimal|--hexadecimal <VALUE>\n\
                          \x20      bitcoin-tools converter base --input <FILE>"
)]
#[command(group = ArgGroup::new("source")
    .args(["binary", "decimal", "hexadecimal", "input"])
    .required(true))]
pub struct Args {
    /// A value written in base 2.
    #[arg(long, value_name = "VALUE", visible_alias = "bin")]
    binary: Option<String>,

    /// A value written in base 10.
    #[arg(long, value_name = "VALUE", visible_alias = "dec")]
    decimal: Option<String>,

    /// A value written in base 16. A leading `0x` is accepted and ignored.
    #[arg(long, value_name = "VALUE", visible_alias = "hex")]
    hexadecimal: Option<String>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds a `value` and a `base`. This is a
    /// superset of the HTTP API's request body: any body the API accepts works
    /// here, and `base` additionally takes the short spellings `bin`, `dec`,
    /// `hex`, the single letters `b`, `d`, `h`, and the radix itself — `2`,
    /// `10`, `16` — which the API refuses.
    #[arg(long, value_name = "FILE")]
    input: Option<PathBuf>,
}

impl Args {
    /// The request the flags describe, if a notation flag was the source.
    ///
    /// Each value is written beside the base it is in, so no ordering
    /// assumption can read a value in the wrong one. `find_map` because clap
    /// has already guaranteed at most one is `Some`.
    fn given(self) -> Option<Request> {
        let (value, base) = [
            (self.binary, Base::Binary),
            (self.decimal, Base::Decimal),
            (self.hexadecimal, Base::Hexadecimal),
        ]
        .into_iter()
        .find_map(|(value, base)| value.map(|value| (value, base)))?;

        Some(Request { value, base })
    }
}

/// The resolved request, and the shape `--input` reads.
///
/// The wire shape keeps `value` and `base` as the HTTP API spells them even
/// though the argument surface no longer does. A request file is a thing
/// scripts write and move between the two front ends; the flags are a thing
/// people type.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    value: String,
    #[serde(deserialize_with = "input::from_str")]
    base: Base,
}

/// One value, in every base.
///
/// The three keys are [`Base`]'s own canonical spellings, which are also the
/// long forms of the three flags — so a key of this output names the flag that
/// would produce it. The field names and JSON spellings match the HTTP API's
/// response for this operation.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseOutput {
    /// Base 2, no `0b` prefix.
    binary: String,
    /// Base 10.
    decimal: String,
    /// Base 16, lowercase, no `0x` prefix.
    hexadecimal: String,
    /// Significant bits — the width of the value, not of the field it came in.
    bits: usize,
    /// Significant bytes.
    bytes: usize,
}

impl Output for BaseOutput {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("binary", &self.binary)
            .row("decimal", &self.decimal)
            .row("hexadecimal", &self.hexadecimal)
            .row("bits", self.bits)
            .row("bytes", self.bytes)
            .write(w)
    }
}

/// Parse the value in the base its flag named, render it in all three.
///
/// # Errors
///
/// If the request cannot be read, or the value is not a number in that base.
/// Core's parser owns the trimming, the prefix, the empty check and the
/// digit-count cap, so this command adds no input policy of its own.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    // Taken out rather than cloned: `given` consumes the rest.
    let source = args.input.take();
    let request: Request = input::resolve(source.as_deref(), || args.given())?;

    let number = Number::parse(&request.value, request.base).with_context(|| {
        // An excerpt, not the value: this is the command whose own help says it
        // exists so a private key can be read in decimal.
        format!(
            "reading {} as {}",
            input::excerpt(&request.value),
            request.base
        )
    })?;

    ctx.emit(&BaseOutput {
        binary: number.to_binary(),
        decimal: number.to_decimal(),
        hexadecimal: number.to_hex(),
        bits: number.bits(),
        bytes: number.as_be_bytes().len(),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each flag names the base its value is read in — the one thing this
    /// module can get wrong on its own, since a mismatched pair would answer
    /// confidently and be wrong.
    #[test]
    fn each_flag_reads_its_value_in_its_own_base() {
        let cases = [
            (Base::Binary, "11111111"),
            (Base::Decimal, "255"),
            (Base::Hexadecimal, "ff"),
        ];

        for (base, value) in cases {
            let args = Args {
                binary: (base == Base::Binary).then(|| value.to_owned()),
                decimal: (base == Base::Decimal).then(|| value.to_owned()),
                hexadecimal: (base == Base::Hexadecimal).then(|| value.to_owned()),
                input: None,
            };

            let request = args.given().expect("a notation flag was given");

            assert_eq!(request.base, base);
            assert_eq!(request.value, value);
            assert_eq!(
                Number::parse(&request.value, request.base)
                    .expect("parses")
                    .to_decimal(),
                "255",
                "{base} read the wrong value"
            );
        }
    }

    /// The file path is unchanged by the new argument surface: it still names
    /// the base as a string, and still through core's `FromStr`.
    #[test]
    fn a_request_file_still_names_its_base() {
        for spelling in ["hexadecimal", "hex", "HEX", "16"] {
            let json = format!(r#"{{"value":"ff","base":"{spelling}"}}"#);
            let request: Request = serde_json::from_str(&json).unwrap();
            assert_eq!(request.base, Base::Hexadecimal);
        }
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"value":"1","bass":"decimal"}"#).is_err());
    }

    /// The request has no default for `base`, in either input path.
    #[test]
    fn the_base_is_required_in_a_request_file_too() {
        assert!(serde_json::from_str::<Request>(r#"{"value":"10"}"#).is_err());
    }
}
