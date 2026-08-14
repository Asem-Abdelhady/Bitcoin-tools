//! Block headers.
//!
//! ## Files
//!
//! | File | Feature |
//! |---|---|
//! | `header.rs` | 6.2 Block Header — version, prev block, merkle root, time, bits, nonce; 6.1 Block Hash |
//! | `target.rs` | the `bits` field: [`CompactTarget`], [`Target`], difficulty |
//! | `merkle.rs` | merkle root from a list of leaf hashes |
//!
//! A header is exactly eighty bytes and reads through
//! [`bytes::Reader`](crate::bytes::Reader) like any other consensus structure.
//! `bits` is a compact difficulty target, so it has its own file as well as
//! its own type — the natural mistake is to show a caller the raw `u32`, which
//! is not the number anyone wants, and the expansion, the overflow rules and
//! the difficulty ratio together are more than a header decoder should carry.
//!
//! ## What a header can and cannot answer
//!
//! [`BlockHeader::meets_target`] is a complete proof-of-work check *for a
//! header in isolation*, and that is the boundary of this module. Whether
//! `bits` is the value the retargeting rules require, whether the timestamp
//! beats the median of the last eleven blocks, whether this header extends the
//! most-worked chain — each needs headers this one does not carry. Consensus
//! validation is a chain's job, not a decoder's, and stopping here is what
//! keeps this module from turning into a node.
//!
//! There is likewise no `Block` type. A full block is a header followed by its
//! transactions, and [`transactions`](crate::transactions) is L4 like this
//! module, so decoding one here would be the sideways import the layering
//! forbids. A caller holding both can already put them together: decode the
//! header, decode the transactions, and check
//! [`merkle::root`] against
//! [`BlockHeader::merkle_root`].
//!
//! ## Merkle takes hashes, not txids
//!
//! The obvious signature for a merkle root is `fn root(txids: &[Txid])`, and
//! it is wrong for the same reason: `blocks` and `transactions` are both L4.
//! It would also make block code depend on transaction code for something that
//! is pure hashing.
//!
//! [`merkle::root`] takes [`hashes::Hash<32>`](crate::hashes::Hash) instead.
//! `Txid` and `BlockHash` are both `Hash<32>` with different meaning attached,
//! the merkle algorithm does not care which it was handed, and the dependency
//! points down to L1 where it belongs. Callers go through
//! [`Txid::to_hash`](crate::transactions::Txid::to_hash).
//!
//! ## …but it must not *return* a bare `Hash<32>`
//!
//! Taking one is right; handing one back is a trap. A merkle root and a block
//! hash are both displayed reversed, and `Hash<N>`'s `Display` is the forward
//! one — byte order is a property of the meaning, not the width, so the
//! generic deliberately does not decide it. [`merkle::root`] therefore returns
//! a [`MerkleRoot`], and a header hashes to a [`BlockHash`], each a newtype
//! whose one-line `Display` states its convention, exactly as
//! [`Txid`](crate::transactions::Txid) does. Returning the bare type would
//! print every block hash forwards and nothing would catch it.
//!
//! ## Re-exports
//!
//! Named individually, as in [`transactions`](crate::transactions): `root` and
//! `root_checked` are short names that only read correctly qualified, so
//! [`merkle`] stays a module a caller reaches through.
//!
//! [`HeaderBreakdown`] and [`HeaderDecodeError`] *do* come forward, where
//! `transactions` leaves `TxBreakdown` and `TxDecodeError` at their own paths.
//! That is not an inconsistency to tidy up: that module's reason is a name
//! collision — `script` and `tx` each define a decode error, and re-exporting
//! both would put `DecodeError` and `TxDecodeError` in one namespace looking
//! like variants of a single type. This module has one decode error and one
//! breakdown, and `HeaderDecodeError` is what [`BlockHeader::decode`] returns,
//! so a caller who has `use blocks::BlockHeader` should not need a second path
//! to name it.

pub mod header;
pub mod merkle;
pub mod target;

pub use header::{BlockHash, BlockHeader, HeaderBreakdown, HeaderDecodeError};
pub use merkle::{MerkleError, MerkleRoot};
pub use target::{CompactTarget, CompactTargetError, ParseCompactTargetError, Target};
