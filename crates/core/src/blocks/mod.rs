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
//!
//! ## …but it must not *return* a bare `Hash<32>`
//!
//! Taking one is right; handing one back is a trap. A merkle root and a block
//! hash are both displayed reversed, and `Hash<N>`'s `Display` is the forward
//! one — byte order is a property of the meaning, not the width, so the
//! generic deliberately does not decide it. `root()` therefore returns a
//! `MerkleRoot`, and a header hashes to a `BlockHash`, each a newtype whose
//! one-line `Display` states its convention, exactly as
//! [`Txid`](crate::transactions::tx::Txid) does. Returning the bare type would
//! print every block hash forwards and nothing would catch it.
