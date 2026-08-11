//! § 5 — Transactions and scripts.
//!
//! ## Files
//!
//! | File | Feature |
//! |---|---|
//! | `tx.rs` | 5.2 Transaction Splitter — `Tx`, `Txid`, decode/encode, `TxBreakdown` |
//! | `builder.rs` | 5.1 Transaction Builder — *planned* |
//! | `script/` | 5.3 Script — `Script`, `Opcode`, `Instruction` |
//!
//! `Tx` and `TxBreakdown` are two views of one thing and the split is
//! deliberate. `Tx` is the structure — typed fields, arithmetic, hashing.
//! `TxBreakdown` is the *byte layout*: every wire field as the literal hex it
//! occupies, in serialization order. A wallet wants the first; a person asking
//! "what are these 300 bytes" wants the second, and flattening them into one
//! type would make each half carry the other's baggage.
//!
//! `builder.rs` (5.1) is the inverse of `tx.rs`: it writes bytes rather than
//! reading them, which is why [`bytes::Writer`](crate::bytes) needs to exist
//! before it does.
//!
//! ## Re-exports
//!
//! Named individually rather than globbed. `script` and `tx` both define a
//! decode error, and `pub use script::*; pub use tx::*;` put `DecodeError` and
//! `TxDecodeError` in one namespace looking like variants of a single type,
//! while giving every item two public paths for a consumer to pick between.
//! Everything not listed here is reached at its own path — `script::Opcode`,
//! `tx::TxBreakdown`.

pub mod script;
pub mod tx;

pub use script::{Script, ScriptAnalysis, ScriptFields, ScriptKind};
pub use tx::{Input, OutPoint, Output, Tx, Txid, Witness};
