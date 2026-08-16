//! `blocks hash` — the hash a header produces.

use std::io::{self, Write};

use anyhow::Result;
use serde::Serialize;

use bitcoin_tools_core::hex;

use crate::output::{Context, Fields, Output};

super::header_args!("hash");

/// One hash, both ways round.
///
/// Both, rather than a choice, because they are the same 32 bytes and the pair
/// is the answer: an explorer shows one and the header contains the other, and a
/// user comparing the two needs to see that they correspond.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockHashResponse {
    /// The hash as it is written down and searched for — big-endian display
    /// order, which is why it appears to start with zeros.
    block_hash: String,
    /// The same bytes in the order they occupy in the next block's header.
    block_hash_wire_order: String,
}

impl Output for BlockHashResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        Fields::new()
            .row("blockHash", &self.block_hash)
            .row("wireOrder", &self.block_hash_wire_order)
            .write(w)
    }
}

/// Decode the header, hash it, emit.
///
/// # Errors
///
/// If the request cannot be read, or the value is not eighty bytes of hex.
pub fn run(args: Args, ctx: Context) -> Result<()> {
    let header = super::decode(&args.request()?)?;
    let hash = header.block_hash();

    ctx.emit(&BlockHashResponse {
        block_hash: hash.to_string(),
        block_hash_wire_order: hex::encode(&hash.to_wire()),
    })?;

    Ok(())
}
