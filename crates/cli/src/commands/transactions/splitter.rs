//! `transactions splitter` — every wire field, as the bytes it occupies.

use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use clap::ArgGroup;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};

use bitcoin_tools_core::transactions::tx::{
    InputBreakdown, OutputBreakdown, Tx, TxBreakdown, WitnessBreakdown,
};

use crate::input::{self, hex_bytes};
use crate::output::{Context, Fields, Output};

/// The noun this command's errors use.
const SUBJECT: &str = "transaction";

/// What `transactions splitter` accepts.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bitcoin-tools transactions splitter <HEX>\n\
                          \x20      bitcoin-tools transactions splitter --input <FILE>")]
#[command(group = ArgGroup::new("source").args(["tx", "input"]).required(true))]
pub struct Args {
    /// The raw transaction, as hex.
    #[arg(value_name = "HEX")]
    tx: Option<String>,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds a `tx` field of hex — the same shape the HTTP API takes. This
    /// is how to pass a transaction too long for a shell argument, which most
    /// real ones are.
    #[arg(long, value_name = "FILE")]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    tx: String,
}

/// One input, as the bytes it occupies.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InputView {
    txid: String,
    vout: String,
    script_sig_size: String,
    script_sig: String,
    sequence: String,
}

/// One output, as the bytes it occupies.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OutputView {
    amount: String,
    script_pubkey_size: String,
    script_pubkey: String,
}

/// One input's witness stack.
#[derive(Debug, Serialize)]
struct WitnessItemView<'a> {
    size: &'a str,
    item: &'a str,
}

/// A witness stack, keyed by position.
///
/// Hand-written `Serialize` because the shape is `{"stackItems": "…", "0": {…},
/// "1": {…}}` — a count beside numbered entries, which no derive produces. It is
/// the API's shape, and this is what makes the two identical.
#[derive(Debug)]
pub struct WitnessView(WitnessBreakdown);

impl Serialize for WitnessView {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(1 + self.0.items.len()))?;
        map.serialize_entry("stackItems", &self.0.stack_items)?;

        for (i, item) in self.0.items.iter().enumerate() {
            map.serialize_entry(
                &i.to_string(),
                &WitnessItemView {
                    size: &item.size,
                    item: &item.item,
                },
            )?;
        }

        map.end()
    }
}

impl From<InputBreakdown> for InputView {
    fn from(i: InputBreakdown) -> Self {
        InputView {
            txid: i.txid,
            vout: i.vout,
            script_sig_size: i.script_sig_size,
            script_sig: i.script_sig,
            sequence: i.sequence,
        }
    }
}

impl From<OutputBreakdown> for OutputView {
    fn from(o: OutputBreakdown) -> Self {
        OutputView {
            amount: o.amount,
            script_pubkey_size: o.script_pubkey_size,
            script_pubkey: o.script_pubkey,
        }
    }
}

/// A transaction, field by field, in wire order.
///
/// Every value is the **hex of the bytes as they appear**, not a decoded number:
/// the point of the command is to show which bytes are which, and rendering the
/// version as `2` rather than `02000000` would hide the thing being asked about.
///
/// The field names and their JSON spellings match the HTTP API's response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTxResponse {
    txid: String,
    /// The witness txid, present only for a segwit transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    wtxid: Option<String>,
    version: String,
    /// BIP144's `00` marker, present only for a segwit transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    marker: Option<String>,
    /// BIP144's `01` flag, likewise.
    #[serde(skip_serializing_if = "Option::is_none")]
    flag: Option<String>,
    input_count: String,
    inputs: Vec<InputView>,
    output_count: String,
    outputs: Vec<OutputView>,
    /// One stack per input, present only for a segwit transaction.
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<Vec<WitnessView>>,
    locktime: String,
    raw_tx: String,
}

impl From<TxBreakdown> for SplitTxResponse {
    fn from(b: TxBreakdown) -> Self {
        SplitTxResponse {
            txid: b.txid,
            wtxid: b.wtxid,
            version: b.version,
            marker: b.marker,
            flag: b.flag,
            input_count: b.input_count,
            inputs: b.inputs.into_iter().map(Into::into).collect(),
            output_count: b.output_count,
            outputs: b.outputs.into_iter().map(Into::into).collect(),
            witness: b
                .witness
                .map(|stacks| stacks.into_iter().map(WitnessView).collect()),
            locktime: b.locktime,
            raw_tx: b.raw_tx,
        }
    }
}

impl Output for SplitTxResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields
            .row("txid", &self.txid)
            .maybe(0, "wtxid", self.wtxid.as_ref())
            .blank()
            .row("version", &self.version)
            .maybe(0, "marker", self.marker.as_ref())
            .maybe(0, "flag", self.flag.as_ref())
            .row("inputCount", &self.input_count);

        for (i, input) in self.inputs.iter().enumerate() {
            fields
                .heading(1, format!("input {i}"))
                .nested(2, "txid", &input.txid)
                .nested(2, "vout", &input.vout)
                .nested(2, "scriptSigSize", &input.script_sig_size)
                .nested(2, "scriptSig", &input.script_sig)
                .nested(2, "sequence", &input.sequence);
        }

        fields.row("outputCount", &self.output_count);

        for (i, output) in self.outputs.iter().enumerate() {
            fields
                .heading(1, format!("output {i}"))
                .nested(2, "amount", &output.amount)
                .nested(2, "scriptPubkeySize", &output.script_pubkey_size)
                .nested(2, "scriptPubkey", &output.script_pubkey);
        }

        if let Some(stacks) = &self.witness {
            for (i, stack) in stacks.iter().enumerate() {
                fields.heading(1, format!("witness {i}")).nested(
                    2,
                    "stackItems",
                    &stack.0.stack_items,
                );

                for (n, item) in stack.0.items.iter().enumerate() {
                    fields.nested(2, &format!("{n} size"), &item.size).nested(
                        2,
                        &format!("{n} item"),
                        &item.item,
                    );
                }
            }
        }

        fields
            .row("locktime", &self.locktime)
            .blank()
            .row("rawTx", &self.raw_tx)
            .write(w)
    }
}

/// Decode the transaction and print its fields.
///
/// # Errors
///
/// If the request cannot be read, the value is not hex or is past the size cap,
/// or the bytes are not a transaction. A broken transaction *is* a failure here,
/// unlike a broken script: once the field boundaries stop lining up there is no
/// partial answer.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let request: Request = input::resolve(source.as_deref(), || args.tx.map(|tx| Request { tx }))?;

    let bytes = hex_bytes(&request.tx, SUBJECT, Tx::MAX_SIZE)?;
    let tx = Tx::decode(&bytes)?;

    ctx.emit(&SplitTxResponse::from(tx.breakdown()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every value is the bytes as they appear, not a decoded number — the
    /// version of a version 2 transaction is `02000000`, and rendering it as
    /// `2` would hide the thing this command exists to show.
    #[test]
    fn every_field_is_the_bytes_it_occupies() {
        let raw = "0200000001a0b1c2d3e4f5060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                   00000000000000000001a086010000000000160014751e76e8199196d454941c45d1b3a32\
                   3f1433bd600000000";
        let bytes = hex_bytes(raw, SUBJECT, Tx::MAX_SIZE).unwrap();
        let response = SplitTxResponse::from(Tx::decode(&bytes).unwrap().breakdown());

        assert_eq!(response.version, "02000000");
        assert_eq!(response.input_count, "01");
        assert_eq!(response.locktime, "00000000");
        assert!(response.witness.is_none(), "no witness on a legacy tx");
        assert!(response.wtxid.is_none(), "and so no wtxid");
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"transaction":"0200"}"#).is_err());
    }
}
