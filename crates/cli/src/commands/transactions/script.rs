//! `transactions script` — what a script says.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::ArgGroup;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::hex;
use bitcoin_tools_core::transactions::script::{
    Category, DecodeError, Script, ScriptAnalysis, ScriptFields,
};

use crate::input::{self, hex_bytes};
use crate::output::{Context, Fields, Output, Table, yes_no};

/// The noun this command's errors use.
const SUBJECT: &str = "script";

/// What `transactions script` accepts.
///
/// One positional value, because a script has no notation to name — hex in.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bitcoin-tools transactions script <HEX>\n\
                          \x20      bitcoin-tools transactions script --input <FILE>")]
#[command(group = ArgGroup::new("source")
    .args(["script", "input"])
    .required(true))]
pub struct Args {
    /// The script, as hex. A leading `0x` and whitespace are ignored.
    #[arg(value_name = "HEX")]
    script: Option<String>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds a `script` field of hex — the same shape the HTTP API takes,
    /// and the way to pass a script too long for a shell argument.
    #[arg(long, value_name = "FILE")]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    script: String,
}

/// One instruction, rendered.
///
/// A view rather than core's `AnalyzedInstruction` straight through: that type
/// carries an `Opcode` and a `Vec<u8>`, which have to become a name and hex. The
/// value enums beside it — [`Category`], [`ScriptFields`], [`DecodeError`] —
/// *are* serialized directly, because their serde spellings are the published
/// contract both front ends emit.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstructionView {
    /// Where in the script this instruction starts.
    offset: usize,
    /// The opcode byte.
    hex: String,
    /// Its name.
    opcode: String,
    /// What kind of thing it does.
    category: Category,
    /// What it does, when there is something worth saying.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<&'static str>,
    /// The bytes pushed, for a push.
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    /// How many bytes those are.
    #[serde(skip_serializing_if = "Option::is_none")]
    data_size: Option<usize>,
}

/// Everything a script turned out to be.
///
/// The field names and their JSON spellings match the HTTP API's response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalyzeScriptResponse {
    /// The script as this program read it: `0x` and whitespace gone, lowercase.
    hex: String,
    /// Its length in bytes.
    size_bytes: usize,
    /// Which standard template it matches, if any.
    kind: String,
    /// The disassembly, as one line.
    asm: String,
    /// The template's named parts, or nothing when it matches none.
    fields: ScriptFields,
    /// Whether an opcode removed from the language appears as an *opcode* —
    /// bytes inside a data push do not count.
    has_disabled_opcode: bool,
    /// Every instruction that decoded, with its offset.
    instructions: Vec<InstructionView>,
    /// Set when the script is malformed; the instructions above are then
    /// everything that decoded before the problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<DecodeError>,
}

impl From<ScriptAnalysis> for AnalyzeScriptResponse {
    fn from(a: ScriptAnalysis) -> Self {
        AnalyzeScriptResponse {
            hex: a.hex,
            size_bytes: a.size_bytes,
            kind: a.kind.to_string(),
            asm: a.asm,
            fields: a.fields,
            has_disabled_opcode: a.has_disabled_opcode,
            instructions: a
                .instructions
                .into_iter()
                .map(|i| InstructionView {
                    offset: i.offset,
                    hex: format!("{:02x}", i.opcode.to_u8()),
                    opcode: i.opcode.to_string(),
                    category: i.opcode.category(),
                    description: i.opcode.describe(),
                    data_size: i.data.as_ref().map(Vec::len),
                    data: i.data.as_deref().map(hex::encode),
                })
                .collect(),
            error: a.error,
        }
    }
}

impl Output for AnalyzeScriptResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields
            .row("kind", &self.kind)
            .row("hex", &self.hex)
            .row("sizeBytes", self.size_bytes)
            .row("asm", &self.asm)
            .row("disabledOpcode", yes_no(self.has_disabled_opcode));

        // The named parts of whatever template it matched. Serialized rather
        // than matched on: `ScriptFields` is one variant per template and this
        // renders whichever it is, so a template added to core appears here
        // without this command being edited.
        if let Ok(serde_json::Value::Object(named)) = serde_json::to_value(&self.fields) {
            for (key, value) in &named {
                fields.nested(1, key, render_field(value));
            }
        }

        // Printed before the table, because a malformed script's instruction
        // list is *partial* and a reader needs to know that before reading it.
        if let Some(error) = &self.error {
            fields.blank().row("error", error);
        }

        fields.blank().write(w)?;

        // `description` last: it is the widest column and the one a narrow
        // terminal can afford to wrap.
        let mut table = Table::new(&["offset", "hex", "opcode", "category", "data", "description"]);
        for i in &self.instructions {
            table.row(vec![
                i.offset.to_string(),
                i.hex.clone(),
                i.opcode.clone(),
                // Through serde so the two modes cannot spell a category two
                // ways. The fallback is `Debug` rather than an empty cell: a
                // renderer must not panic, but a value that quietly disappeared
                // from one of two modes is the bug this crate is arranged
                // against.
                serde_json::to_value(i.category)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| format!("{:?}", i.category)),
                i.data.clone().unwrap_or_default(),
                i.description.unwrap_or_default().to_owned(),
            ]);
        }
        table.write(w)
    }
}

/// A `ScriptFields` value as one line.
///
/// The fields are hex strings and small arrays; anything else is handed back as
/// the JSON it is rather than guessed at.
fn render_field(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Array(items) => items
            .iter()
            .map(render_field)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// Read the script, analyse it, emit.
///
/// # Errors
///
/// If the request cannot be read, or the value is empty, is not whole bytes of
/// hex, or is past the consensus script size. **Not** if the script is
/// malformed — that is the answer, not a failure.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let request: Request = input::resolve(source.as_deref(), || {
        args.script.map(|script| Request { script })
    })?;

    let bytes = hex_bytes(&request.script, SUBJECT, Script::MAX_SIZE)?;
    ctx.emit(&AnalyzeScriptResponse::from(Script::new(bytes).analyze()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one that matters: a script that does not decode is still an answer,
    /// carrying everything that did decode plus where it stopped.
    #[test]
    fn a_broken_script_is_an_answer_rather_than_a_failure() {
        // `OP_PUSHBYTES_20` with nothing after it.
        let analysis = Script::new(vec![0x14]).analyze();
        let response = AnalyzeScriptResponse::from(analysis);

        assert!(response.error.is_some(), "the problem is reported");
        assert_eq!(response.size_bytes, 1, "…and so is everything else");
    }

    /// The kind, the fields and the instruction list are the three things a
    /// script command exists to produce, and a standard template exercises all
    /// three at once.
    #[test]
    fn a_p2pkh_script_is_recognised_and_taken_apart() {
        let bytes = hex_bytes(
            "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac",
            SUBJECT,
            Script::MAX_SIZE,
        )
        .unwrap();
        let response = AnalyzeScriptResponse::from(Script::new(bytes).analyze());

        assert_eq!(response.kind, "P2PKH");
        assert!(response.error.is_none());
        assert_eq!(response.instructions[0].opcode, "OP_DUP");
        assert_eq!(response.instructions[0].offset, 0);

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(
            json["fields"]["pubkeyHash"], "751e76e8199196d454941c45d1b3a323f1433bd6",
            "{json}"
        );
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"scrpt":"76a9"}"#).is_err());
    }
}
