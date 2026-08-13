//! § 5 — Transactions and scripts.
//!
//! ## Files
//!
//! | File | Feature |
//! |---|---|
//! | `tx.rs` | 5.2 Transaction Splitter — `Tx`, `Txid`, decode/encode, `TxBreakdown` |
//! | `builder.rs` | 5.1 Transaction Builder — `TxBuilder`, `TxKind`, `BuildError` |
//! | `script/` | 5.3 Script — `Script`, `Opcode`, `Instruction` |
//!
//! `Tx` and `TxBreakdown` are two views of one thing and the split is
//! deliberate. `Tx` is the structure — typed fields, arithmetic, hashing.
//! `TxBreakdown` is the *byte layout*: every wire field as the literal hex it
//! occupies, in serialization order. A wallet wants the first; a person asking
//! "what are these 300 bytes" wants the second, and flattening them into one
//! type would make each half carry the other's baggage.
//!
//! `builder.rs` (5.1) is the inverse of `tx.rs` — and turned out **not** to be
//! a second serializer. The plan here used to say it would write bytes, and so
//! needed a `bytes::Writer` before it could exist. Writing it disproved that:
//! `Tx::encode` already turns a transaction into consensus bytes, so the
//! builder assembles a `Tx` and returns it. Duplicating the encoder would have
//! meant two places that must agree about marker, flag, varints and witness
//! order — which is the bug the shared `Writer` was meant to prevent, arrived
//! at by a different route.
//!
//! What `TxBuilder` adds instead is the checks: the combinations of parts that
//! serialize cleanly and are still rejected by every node.
//!
//! ## Re-exports
//!
//! Named individually rather than globbed. `script` and `tx` both define a
//! decode error, and `pub use script::*; pub use tx::*;` put `DecodeError` and
//! `TxDecodeError` in one namespace looking like variants of a single type,
//! while giving every item two public paths for a consumer to pick between.
//! Everything not listed here is reached at its own path — `script::Opcode`,
//! `tx::TxBreakdown`.

pub mod builder;
pub mod script;
pub mod tx;

pub use builder::{BuildError, TxBuilder, TxKind};
pub use script::{Script, ScriptAnalysis, ScriptFields, ScriptKind};
pub use tx::{Input, OutPoint, Output, Tx, Txid, Witness};
