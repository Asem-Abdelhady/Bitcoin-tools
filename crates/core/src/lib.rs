//! Decode and inspect Bitcoin's data formats.
//!
//! Pure computation over bytes: no I/O, no network, no framework. A CLI and a
//! web server both sit on top of this crate without either shaping it.
//!
//! # Layers
//!
//! Nothing imports upward. Keeping this true is what stops the same checksum
//! loop being written five times.
//!
//! | | Modules | Depends on |
//! |---|---|---|
//! | L0 | [`hex`], [`bytes`], [`network`] | nothing |
//! | L1 | [`hashes`], [`general`] | L0 |
//! | L2 | [`encoding`], [`crypto`] | L1 |
//! | L3 | [`keys`] | L2 |
//! | L4 | [`hd`], [`transactions`], [`blocks`] | L3 |
//!
//! # Example
//!
//! ```
//! use bitcoin_tools_core::transactions::script::{Script, ScriptKind};
//!
//! let script = Script::from_hex("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac")?;
//! assert_eq!(script.kind(), ScriptKind::P2PKH);
//! assert!(script.to_asm().starts_with("OP_DUP OP_HASH160 OP_PUSHBYTES_20"));
//! # Ok::<_, bitcoin_tools_core::hex::HexError>(())
//! ```

// A library must not abort its caller: every failure is a returned error. The
// lints live here rather than in Cargo's `[lints]` so they cover the library
// only — an assertion in a test *should* panic, that is what it is for.
#![warn(missing_debug_implementations)]
#![warn(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// `clippy::indexing_slicing` is deliberately *not* enabled. Every index in
// this crate is preceded by an explicit length check, usually on the same
// line; routing them through `.get()` would add an unreachable error path to
// each one and make the script template matcher markedly harder to read.
// `bytes::Reader` is the answer for anything walking untrusted input.
//
// `missing_docs` is *not on yet*, and should be before this crate is
// published. Turning it on today reports ~138 public items — overwhelmingly
// error-variant fields in `bytes`, `hex`, `network`, `transactions::tx` and
// `transactions::script` — and that sweep is its own change rather than a
// rider on whichever feature happens to be in flight. `general` and `hashes`
// already pass it. This is the next piece of work, not a someday.

// Internal, and outside the layering: a macro, not a dependency. It generates
// the `as_str`/`Display`/`FromStr`/`Unknown…` set that every small named enum
// in the crate wants, and is private, so nothing here is reachable from
// outside the crate.
mod parse;

// L0 — primitives. Everything else reads and writes through these.
pub mod bytes;
pub mod hex;
pub mod network;

// L1
pub mod general;
pub mod hashes;

// L2
pub mod crypto;
pub mod encoding;

// L3
pub mod keys;

// L4
pub mod blocks;
pub mod hd;
pub mod transactions;
