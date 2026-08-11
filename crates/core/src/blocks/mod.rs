//! § 6 — Block headers.
//!
//! ## Planned
//!
//! | File | Feature |
//! |---|---|
//! | `header.rs` | 6.2 Block Header — version, prev block, merkle root, time, bits, nonce; 6.1 Block Hash |
//! | `merkle.rs` | Merkle root from a list of leaf hashes |
//!
//! A header is exactly 80 bytes and reads through
//! [`bytes::Reader`](crate::bytes::Reader) like any other consensus structure.
//! `bits` is a compact difficulty target, so it needs its own type — the
//! natural mistake is to show a caller the raw `u32`, which is not the number
//! anyone wants.
//!
//! ## Merkle takes hashes, not txids
//!
//! The obvious signature for a merkle root is `fn root(txids: &[Txid])`, and
//! it is wrong: `blocks` and `transactions` are both L4, so that is a sideways
//! import the layering does not permit, and it would make block code depend on
//! transaction code for something that is pure hashing.
//!
//! Take [`hashes::Hash<32>`](crate::hashes) instead. `Txid` and `BlockHash`
//! are both `Hash<32>` with different meaning attached, the merkle algorithm
//! does not care which it was handed, and the dependency points down to L1
//! where it belongs.
