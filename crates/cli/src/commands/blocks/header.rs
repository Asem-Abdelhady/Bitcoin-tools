//! `blocks header` — the eighty bytes as fields.

use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;

use bitcoin_tools_core::blocks::{BlockHeader, Target};

use crate::output::{Context, Fields, Output, yes_no};

super::header_args!("header");

/// A header, field by field, with what its `bits` mean.
///
/// The field names and their JSON spellings match the HTTP API's response.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHeaderResponse {
    /// The hash these eighty bytes produce, in display order.
    block_hash: String,
    /// The version, as a signed-looking `u32` — the upper bits carry BIP9
    /// signalling rather than a version number.
    version: u32,
    /// The same value in hex, which is how signalling bits are read.
    version_hex: String,
    /// The previous block's hash, display order.
    prev_block: String,
    /// The merkle root over this block's transactions, display order.
    merkle_root: String,
    /// The claimed time, as a Unix timestamp. A miner's claim, loosely
    /// constrained by consensus rather than measured.
    time: u32,
    /// The compact difficulty target, hex.
    bits: String,
    /// The nonce the miner settled on.
    nonce: u32,
    /// The 256-bit target `bits` expands to. `null` when the compact form is
    /// one of the encodings that has no target — negative, or overflowing.
    target: Option<String>,
    /// Why the target is absent, present only when it is.
    #[serde(skip_serializing_if = "Option::is_none")]
    target_error: Option<String>,
    /// How much harder this target is than the easiest one. `null` when the
    /// arithmetic does not produce a finite number.
    difficulty: Option<f64>,
    /// Whether this header's own hash is at or below its own target.
    ///
    /// The field that closes the loop: it checks the header against the rule it
    /// states, rather than asking anyone to trust either half.
    meets_target: bool,
}

impl From<BlockHeader> for BlockHeaderResponse {
    fn from(header: BlockHeader) -> Self {
        let difficulty = header.bits.difficulty();
        let target = header.target();

        BlockHeaderResponse {
            block_hash: header.block_hash().to_string(),
            version: header.version,
            version_hex: format!("{:08x}", header.version),
            prev_block: header.prev_block.to_string(),
            merkle_root: header.merkle_root.to_string(),
            time: header.time,
            bits: header.bits.to_string(),
            nonce: header.nonce,
            target: target.as_ref().ok().map(Target::to_hex),
            target_error: target.as_ref().err().map(ToString::to_string),
            // A target that expands to zero makes the division infinite, and
            // `null` is the honest answer where `inf` is not even valid JSON.
            difficulty: difficulty.is_finite().then_some(difficulty),
            meets_target: header.meets_target(),
        }
    }
}

impl Output for BlockHeaderResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("blockHash", &self.block_hash)
            .row(
                "version",
                format!("{} ({})", self.version, self.version_hex),
            )
            .row("prevBlock", &self.prev_block)
            .row("merkleRoot", &self.merkle_root)
            .row("time", self.time)
            .row("bits", &self.bits)
            .row("nonce", self.nonce)
            .blank()
            .maybe(0, "target", self.target.as_ref())
            .maybe(0, "targetError", self.target_error.as_ref())
            // `{:?}` and not `{}`: `Display` for an f64 prints 1 where JSON
            // prints 1.0, and the two modes spelling one number differently is
            // exactly what `both_modes_carry_the_same_values` is for. Debug for
            // a float is the shortest representation that round-trips, which is
            // what serde_json emits too.
            .maybe(0, "difficulty", self.difficulty.map(|d| format!("{d:?}")))
            .row("meetsTarget", yes_no(self.meets_target))
            .write(w)
    }
}

/// Decode the header and print its fields.
///
/// # Errors
///
/// If the request cannot be read, or the value is not eighty bytes of hex.
pub fn run(args: Args, ctx: Context) -> Result<()> {
    let header = super::decode(&args.request()?)?;
    ctx.emit(&BlockHeaderResponse::from(header))?;

    Ok(())
}
