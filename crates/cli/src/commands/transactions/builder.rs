//! `transactions builder` — put a transaction together.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::general::Amount;
use bitcoin_tools_core::hashes::HashParseError;
use bitcoin_tools_core::hex;
use bitcoin_tools_core::transactions::builder::{TxBuilder, TxKind};
use bitcoin_tools_core::transactions::script::Script;
// `TxOutput`: `Output` is also this crate's trait for a command's answer, and
// the two would collide in a file that needs both.
use bitcoin_tools_core::transactions::tx::{
    Input, OutPoint, Output as TxOutput, Tx, Txid, Witness,
};

use crate::input::{self, InputError, hex_bytes_allowing_empty};
use crate::output::{Context, Fields, Output};

/// What `transactions builder` accepts.
///
/// # The flags build a skeleton; a signed transaction comes from a file
///
/// `--spend` and `--pay` cover the shape most requests have: outpoints in,
/// amounts and scripts out. What they cannot express is a `scriptSig` or a
/// witness stack, because those are *per input* and a repeated flag carrying a
/// nested list is worse to type and to read than the JSON it is standing in for.
///
/// That is not a gap so much as a boundary: this command does not sign, so the
/// transactions it builds from flags are exactly the unsigned ones. Anything
/// already carrying signature data is something another tool produced, and it
/// arrives as `--input`.
///
/// `--type` is required and has no default, for the reason
/// [`converter base`](crate::commands::converter::base)'s notation flag is
/// required: it changes the bytes, the txid, and whether a witness survives at
/// all. Note that `--type segwit` with the flags alone is always an error —
/// BIP144 requires witness data, and the flags cannot carry any — which is the
/// domain saying so rather than this command second-guessing it.
// `disable_version_flag`: this command has a `--version`, and it is the
// transaction's. The root `--version` still prints the program's, and
// `propagate_version` still puts it on every other subcommand — this is the one
// place where the domain already owns the word.
#[derive(Debug, clap::Args)]
#[command(disable_version_flag = true)]
#[command(override_usage = "bt transactions builder --type <KIND> \
                            --spend <TXID:VOUT> --pay <SATS:SCRIPT>\n\
                          \x20      bt transactions builder --input <FILE>")]
pub struct Args {
    /// Which serialization: `legacy` or `segwit`.
    ///
    /// No default. It decides the bytes and therefore the txid.
    #[arg(long = "type", value_name = "KIND", required_unless_present = "input")]
    kind: Option<TxKind>,

    /// An outpoint to spend, as `TXID:VOUT`. Repeatable.
    ///
    /// The txid is in display order — the order an explorer shows and you would
    /// paste. Sequence defaults to `0xffffffff` and the scriptSig to empty.
    #[arg(long, value_name = "TXID:VOUT", required_unless_present = "input")]
    spend: Vec<OutPointArg>,

    /// An output to pay, as `SATS:SCRIPTPUBKEY`. Repeatable.
    ///
    /// The amount is in **satoshis**, always — an integer, so nothing rounds.
    #[arg(long, value_name = "SATS:SCRIPT", required_unless_present = "input")]
    pay: Vec<PaymentArg>,

    /// The transaction version. Defaults to 2.
    ///
    /// This command's `--version` is the transaction's, not the program's:
    /// `bt --version` still prints the program's.
    #[arg(long, value_name = "N")]
    version: Option<u32>,

    /// The locktime. Defaults to 0.
    #[arg(long, value_name = "N")]
    lock_time: Option<u32>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds {"type", "version"?, "lockTime"?, "inputs", "outputs"} —
    /// the HTTP API's request body, and the only way to give an input a
    /// scriptSig or a witness.
    #[arg(long, value_name = "FILE",
          conflicts_with_all = ["kind", "spend", "pay", "version", "lock_time"])]
    input: Option<PathBuf>,
}

/// An outpoint written as one argument.
///
/// Parsed here rather than as two flags because an input *is* the pair — two
/// flags would let a `--vout` be given without its txid, or drift out of order
/// once there are three inputs.
#[derive(Debug, Clone)]
pub struct OutPointArg {
    txid: String,
    vout: u32,
}

impl FromStr for OutPointArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `rsplit_once`, not `split_once`: nothing in a txid is a colon today,
        // but splitting from the right means the *last* field is the index
        // whatever precedes it.
        let (txid, vout) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("expected TXID:VOUT, got {s:?}"))?;

        Ok(OutPointArg {
            txid: txid.to_owned(),
            vout: vout
                .parse()
                .map_err(|_| format!("{vout:?} is not an output index"))?,
        })
    }
}

/// An output written as one argument.
#[derive(Debug, Clone)]
pub struct PaymentArg {
    amount: u64,
    script_pubkey: String,
}

impl FromStr for PaymentArg {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // `split_once`: the script is hex and holds no colon, and the amount is
        // the first field.
        let (amount, script) = s
            .split_once(':')
            .ok_or_else(|| format!("expected SATS:SCRIPTPUBKEY, got {s:?}"))?;

        Ok(PaymentArg {
            amount: amount
                .parse()
                .map_err(|_| format!("{amount:?} is not a whole number of satoshis"))?,
            script_pubkey: script.to_owned(),
        })
    }
}

/// One input of a build request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InputSpec {
    /// The previous transaction's id, display order.
    txid: String,
    /// Which of its outputs.
    vout: u32,
    /// The unlocking script. Empty by default, which is what an unsigned input
    /// and every native segwit input carry.
    #[serde(default)]
    script_sig: String,
    /// Defaults to `0xffffffff`, which disables both relative locktime and
    /// replace-by-fee opt-in.
    sequence: Option<u32>,
    /// The witness stack, innermost item first. Empty by default.
    #[serde(default)]
    witness: Vec<String>,
}

/// One output of a build request.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OutputSpec {
    /// Satoshis, as an integer — money is never a JSON number that could round.
    amount: u64,
    /// The locking script, hex.
    script_pubkey: String,
}

/// The resolved request, and the shape `--input` reads.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TxSpec {
    #[serde(rename = "type")]
    kind: TxKind,
    version: Option<u32>,
    lock_time: Option<u32>,
    inputs: Vec<InputSpec>,
    outputs: Vec<OutputSpec>,
}

/// Which field of which input or output went wrong.
///
/// A build request holds many hex fields, and "invalid hex" without a position
/// leaves the user to bisect their own request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Located {
    subject: &'static str,
    index: usize,
    field: &'static str,
    item: Option<usize>,
}

impl fmt::Display for Located {
    /// The position only — `input 0`, `input 0 item 2`.
    ///
    /// Not the field name: `InputError` already opens with the subject it was
    /// given, which for these calls *is* the field name, so printing it here
    /// too produced `output 0 scriptPubkey: scriptPubkey: invalid hex`. The one
    /// error that carries no noun of its own is the txid, and
    /// [`BuildFailure`]'s `Display` adds it there.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.subject, self.index)?;
        match self.item {
            Some(item) => write!(f, " item {item}"),
            None => Ok(()),
        }
    }
}

/// Why the request is not a transaction.
///
/// A field-level problem keeps the vocabulary it has everywhere else and adds
/// the position; a rule violation is the domain's own error, which already names
/// which input or output broke which rule.
#[derive(Debug, Clone, PartialEq, Eq)]
enum BuildFailure {
    /// A `txid` field was not 32 bytes of hex.
    Txid { at: Located, error: HashParseError },
    /// A hex field was not usable.
    Field { at: Located, error: InputError },
}

impl fmt::Display for BuildFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // `HashParseError` names no field, so this arm supplies one.
            BuildFailure::Txid { at, error } => write!(f, "{at}: {}: {error}", at.field),
            // `InputError` opens with the subject, which here is the field.
            BuildFailure::Field { at, error } => write!(f, "{at}: {error}"),
        }
    }
}

impl std::error::Error for BuildFailure {}

/// A built transaction, and the four sizes that matter about it.
///
/// The field names and their JSON spellings match the HTTP API's response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildTxResponse {
    txid: String,
    /// The witness txid, present only for a segwit transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    wtxid: Option<String>,
    /// Serialized length in bytes.
    size: usize,
    /// Weight units: the witness-stripped size counts four times.
    weight: usize,
    /// Virtual size — weight divided by four, rounded up. What a fee rate is
    /// quoted against.
    vsize: usize,
    raw_tx: String,
}

impl Output for BuildTxResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("txid", &self.txid)
            .maybe(0, "wtxid", self.wtxid.as_ref())
            .row("size", self.size)
            .row("weight", self.weight)
            .row("vsize", self.vsize)
            .blank()
            .row("rawTx", &self.raw_tx)
            .write(w)
    }
}

/// Read one hex field of the request, saying which one it was.
fn field_bytes(at: Located, value: &str) -> Result<Vec<u8>, BuildFailure> {
    hex_bytes_allowing_empty(value, at.field, Script::MAX_SIZE)
        .map_err(|error| BuildFailure::Field { at, error })
}

/// Turn one input spec into an input.
fn read_input(index: usize, spec: &InputSpec) -> Result<Input, BuildFailure> {
    let at = |field, item| Located {
        subject: "input",
        index,
        field,
        item,
    };

    let txid: Txid = spec.txid.parse().map_err(|error| BuildFailure::Txid {
        at: at("txid", None),
        error,
    })?;

    let witness = spec
        .witness
        .iter()
        .enumerate()
        .map(|(item, value)| field_bytes(at("witness", Some(item)), value))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Input {
        previous_output: OutPoint {
            txid,
            vout: spec.vout,
        },
        script_sig: Script::new(field_bytes(at("scriptSig", None), &spec.script_sig)?),
        sequence: spec.sequence.unwrap_or(TxBuilder::SEQUENCE_FINAL),
        witness: Witness::new(witness),
    })
}

/// Turn one output spec into an output.
fn read_output(index: usize, spec: &OutputSpec) -> Result<TxOutput, BuildFailure> {
    let at = Located {
        subject: "output",
        index,
        field: "scriptPubkey",
        item: None,
    };

    Ok(TxOutput {
        value: Amount::from_sat(spec.amount),
        script_pubkey: Script::new(field_bytes(at, &spec.script_pubkey)?),
    })
}

/// Assemble and validate.
fn build(spec: &TxSpec) -> Result<Tx> {
    let mut builder = TxBuilder::new(spec.kind);

    if let Some(version) = spec.version {
        builder = builder.version(version);
    }
    if let Some(lock_time) = spec.lock_time {
        builder = builder.lock_time(lock_time);
    }

    for (index, input) in spec.inputs.iter().enumerate() {
        builder = builder.input(read_input(index, input)?);
    }
    for (index, output) in spec.outputs.iter().enumerate() {
        builder = builder.output(read_output(index, output)?);
    }

    Ok(builder.build()?)
}

/// Read the request, build, emit.
///
/// # Errors
///
/// If the request cannot be read, a field is not usable hex, or the parts do not
/// make a transaction any node would accept — no inputs, no outputs, a duplicated
/// outpoint, the coinbase outpoint, an amount past 21 million, either half of
/// BIP144's witness rule, or a transaction past the consensus size.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();

    let spec: TxSpec = input::resolve(source.as_deref(), || {
        // `--type` is `required_unless_present = "input"`, so clap has already
        // refused a flag-built request that does not name one.
        Some(TxSpec {
            kind: args.kind?,
            version: args.version,
            lock_time: args.lock_time,
            inputs: args
                .spend
                .into_iter()
                .map(|outpoint| InputSpec {
                    txid: outpoint.txid,
                    vout: outpoint.vout,
                    script_sig: String::new(),
                    sequence: None,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: args
                .pay
                .into_iter()
                .map(|payment| OutputSpec {
                    amount: payment.amount,
                    script_pubkey: payment.script_pubkey,
                })
                .collect(),
        })
    })?;

    let tx = build(&spec)?;
    let raw = tx.encode();

    ctx.emit(&BuildTxResponse {
        txid: tx.txid().to_string(),
        wtxid: tx.segwit.then(|| tx.wtxid().to_string()),
        size: raw.len(),
        weight: tx.weight(),
        vsize: tx.vsize(),
        raw_tx: hex::encode(&raw),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TXID: &str = "aa52ef52f47e26a3e0bd0e8de4b7c0e3e2d2c1b0a9f8e7d6c5b4a39281706150";
    const SCRIPT: &str = "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac";

    fn spec() -> TxSpec {
        TxSpec {
            kind: TxKind::Legacy,
            version: None,
            lock_time: None,
            inputs: vec![InputSpec {
                txid: TXID.to_owned(),
                vout: 0,
                script_sig: String::new(),
                sequence: None,
                witness: Vec::new(),
            }],
            outputs: vec![OutputSpec {
                amount: 100_000,
                script_pubkey: SCRIPT.to_owned(),
            }],
        }
    }

    /// The pair is one argument, so a `vout` cannot arrive without its txid or
    /// drift out of order once there are three inputs.
    #[test]
    fn an_outpoint_argument_is_the_pair() {
        let parsed: OutPointArg = format!("{TXID}:3").parse().unwrap();
        assert_eq!(parsed.txid, TXID);
        assert_eq!(parsed.vout, 3);

        assert!(TXID.parse::<OutPointArg>().is_err(), "no index");
        assert!(format!("{TXID}:x").parse::<OutPointArg>().is_err());
    }

    /// The amount is satoshis and an integer, so a fee calculation cannot lose
    /// one to a double.
    #[test]
    fn a_payment_argument_is_satoshis_and_a_script() {
        let parsed: PaymentArg = format!("100000:{SCRIPT}").parse().unwrap();
        assert_eq!(parsed.amount, 100_000);
        assert_eq!(parsed.script_pubkey, SCRIPT);

        assert!(format!("0.001:{SCRIPT}").parse::<PaymentArg>().is_err());
        assert!(SCRIPT.parse::<PaymentArg>().is_err(), "no amount");
    }

    /// Everything but `type` carries the domain's own default, so a minimal
    /// request builds the same transaction on both front ends.
    #[test]
    fn the_defaults_are_the_domains_own() {
        let tx = build(&spec()).unwrap();

        assert_eq!(tx.version, TxBuilder::DEFAULT_VERSION);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.inputs[0].sequence, TxBuilder::SEQUENCE_FINAL);
        assert!(tx.inputs[0].script_sig.as_bytes().is_empty());
    }

    /// A field-level problem says which input and which field, so a request with
    /// six inputs does not have to be bisected by hand.
    #[test]
    fn a_broken_field_names_its_position() {
        let mut spec = spec();
        spec.outputs[0].script_pubkey = "zz".to_owned();

        let message = build(&spec).unwrap_err().to_string();

        // The position, then the field, each once. `Located` owns "which one"
        // and the error owns "which field"; when both printed the field the
        // message read `output 0 scriptPubkey: scriptPubkey: …`.
        assert!(message.starts_with("output 0: scriptPubkey: "), "{message}");
        assert_eq!(message.matches("scriptPubkey").count(), 1, "{message}");
    }

    /// BIP144 both ways: the domain owns the rule and this command does not
    /// second-guess it — which is also why `--type segwit` from flags alone is
    /// an error rather than a silently-legacy transaction.
    #[test]
    fn segwit_without_a_witness_is_refused() {
        let mut spec = spec();
        spec.kind = TxKind::Segwit;

        assert!(build(&spec).is_err(), "no witness data");
    }

    #[test]
    fn the_type_is_required_in_a_request_file_too() {
        let json = r#"{"inputs":[],"outputs":[]}"#;
        assert!(serde_json::from_str::<TxSpec>(json).is_err());
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        let json = r#"{"type":"legacy","inputs":[],"outputs":[],"locktime":0}"#;
        assert!(
            serde_json::from_str::<TxSpec>(json).is_err(),
            "the field is lockTime"
        );
    }
}
