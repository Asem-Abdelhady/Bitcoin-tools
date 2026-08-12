//! The merkle root of a list of hashes, and the duplicate-sibling flaw.
//!
//! Takes [`Hash<32>`](crate::hashes::Hash) rather than
//! [`Txid`](crate::transactions::Txid): the algorithm does not care what the
//! leaves mean, and `blocks` and `transactions` are both L4, so taking the
//! transaction type would be a sideways import for something that is pure
//! hashing. Call [`Txid::to_hash`](crate::transactions::Txid::to_hash) on the
//! way in.

use std::fmt;

use crate::hashes::hash::reversed_hash;
use crate::hashes::{Hash, hash256};

reversed_hash! {
    /// The root of a merkle tree of transactions.
    ///
    /// Thirty-two bytes in *internal* (wire) order, displayed reversed — the
    /// order block explorers print and the order the `merkleRoot` field of
    /// every vector in this crate is written in.
    ///
    /// It exists so that [`root`] cannot hand back a bare `Hash<32>`, whose
    /// `Display` is the forward one: a merkle root printed forwards is wrong
    /// in a way nothing downstream can detect.
    MerkleRoot, subject: "merkle root", in: "block header"
}

/// Why a list of leaves has no trustworthy root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MerkleError {
    /// No leaves. A block always contains at least its coinbase, so an empty
    /// list is a caller mistake rather than a tree with a root.
    Empty,
    /// Two adjacent siblings were identical, so this list is not the only one
    /// with this root. See [`root_checked`] for what that means.
    DuplicateSiblings {
        /// Rows above the leaves: `0` is the leaf row itself.
        level: usize,
        /// Index of the *first* of the two within that row.
        index: usize,
    },
}

impl fmt::Display for MerkleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MerkleError::Empty => f.write_str("a merkle tree needs at least one leaf"),
            MerkleError::DuplicateSiblings { level, index } => write!(
                f,
                "leaves {index} and {} of level {level} are identical, \
                 so this root is ambiguous",
                index + 1
            ),
        }
    }
}

impl std::error::Error for MerkleError {}

/// The merkle root of `leaves`, or `None` if there are none.
///
/// This is the consensus computation: pair the hashes up, HASH256 each pair,
/// repeat, and duplicate the last hash of any row that has an odd length. It
/// answers what a block header *would* commit to, which is what a tool
/// checking an existing block needs — including for the ambiguous lists
/// [`root_checked`] refuses.
///
/// ```
/// use bitcoin_tools_core::blocks::merkle;
/// use bitcoin_tools_core::hashes::Hash;
///
/// // Block 170: the first transaction to anyone but the miner.
/// let coinbase = "b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082";
/// let payment = "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16";
/// let leaves = [
///     Hash::<32>::from_hex_reversed(coinbase)?,
///     Hash::<32>::from_hex_reversed(payment)?,
/// ];
///
/// assert_eq!(
///     merkle::root(&leaves).map(|r| r.to_string()).as_deref(),
///     Some("7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff"),
/// );
/// # Ok::<_, bitcoin_tools_core::hashes::HashParseError>(())
/// ```
///
/// A single leaf is its own root, with no hashing at all — which is why a
/// block with one transaction has a merkle root equal to its coinbase txid.
#[must_use]
pub fn root(leaves: &[Hash<32>]) -> Option<MerkleRoot> {
    fold(leaves).map(|(root, _)| root)
}

/// The merkle root, refusing a list whose root does not identify it.
///
/// Duplicating the last hash of an odd row means a list of *n* leaves and the
/// same list with its last leaf repeated hash to the same root — CVE-2012-2459,
/// which crashed nodes in 2012 and is still why Bitcoin Core carries a
/// `mutated` flag out of its merkle computation. The signature of the flaw is
/// two identical adjacent siblings, since no honest block repeats a
/// transaction.
///
/// Use this when the list is *input* and the root is a conclusion. Use
/// [`root`] when the root is a given — validating a header you already have,
/// where the ambiguous value is exactly the one you need to reproduce.
///
/// # Errors
///
/// [`MerkleError::Empty`] for no leaves, or
/// [`MerkleError::DuplicateSiblings`] locating the first identical pair.
///
/// ```
/// use bitcoin_tools_core::blocks::merkle::{self, MerkleError};
/// use bitcoin_tools_core::hashes::Hash;
///
/// let a = Hash::<32>::from_bytes([1; 32]);
/// let b = Hash::<32>::from_bytes([2; 32]);
///
/// // Three leaves: the third is duplicated to pair it, and `[a, b, b]`
/// // therefore has the same root as `[a, b, b, b]`.
/// assert_eq!(merkle::root(&[a, b, b]), merkle::root(&[a, b, b, b]));
///
/// // Which is why the second of those is refused.
/// assert!(merkle::root_checked(&[a, b, b]).is_ok());
/// assert_eq!(
///     merkle::root_checked(&[a, b, b, b]),
///     Err(MerkleError::DuplicateSiblings { level: 0, index: 2 }),
/// );
/// ```
pub fn root_checked(leaves: &[Hash<32>]) -> Result<MerkleRoot, MerkleError> {
    match fold(leaves) {
        None => Err(MerkleError::Empty),
        Some((_, Some(e))) => Err(e),
        Some((root, None)) => Ok(root),
    }
}

/// The one loop: the root, and the first identical sibling pair seen on the
/// way up. Both callers want the same walk, and doing it twice would mean two
/// chances to disagree about which rows get padded.
fn fold(leaves: &[Hash<32>]) -> Option<(MerkleRoot, Option<MerkleError>)> {
    if leaves.is_empty() {
        return None;
    }
    let mut row: Vec<[u8; 32]> = leaves.iter().map(|h| h.to_bytes()).collect();
    let mut duplicate = None;
    let mut level = 0;

    while row.len() > 1 {
        // Before padding, so an odd row is not mistaken for the flaw: the
        // copy this loop is about to make is the *fix* for an odd row, and
        // flagging it would make every second block look mutated.
        let mut i = 0;
        while i + 1 < row.len() {
            if duplicate.is_none() && row[i] == row[i + 1] {
                duplicate = Some(MerkleError::DuplicateSiblings { level, index: i });
            }
            i += 2;
        }

        if row.len() % 2 == 1 {
            if let Some(&last) = row.last() {
                row.push(last);
            }
        }

        let mut next = Vec::with_capacity(row.len() / 2);
        let mut i = 0;
        while i + 1 < row.len() {
            let mut pair = [0u8; 64];
            pair[..32].copy_from_slice(&row[i]);
            pair[32..].copy_from_slice(&row[i + 1]);
            next.push(hash256(&pair));
            i += 2;
        }
        row = next;
        level += 1;
    }

    row.first()
        .map(|&bytes| (MerkleRoot::from_wire(bytes), duplicate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> Hash<32> {
        Hash::from_bytes([n; 32])
    }

    #[test]
    fn one_leaf_is_its_own_root_and_none_is_no_root() {
        let only = leaf(7);
        assert_eq!(root(&[only]), Some(MerkleRoot::from_hash(only)));
        assert_eq!(root(&[]), None);
        assert_eq!(root_checked(&[]), Err(MerkleError::Empty));
    }

    #[test]
    fn a_pair_is_hash256_of_the_two_concatenated() {
        let (a, b) = (leaf(1), leaf(2));
        let mut expected = [0u8; 64];
        expected[..32].copy_from_slice(a.as_bytes());
        expected[32..].copy_from_slice(b.as_bytes());

        assert_eq!(
            root(&[a, b]),
            Some(MerkleRoot::from_wire(hash256(&expected))),
            "the leaves are concatenated in wire order, left first"
        );
        assert_ne!(root(&[a, b]), root(&[b, a]), "order is part of the tree");
    }

    /// CVE-2012-2459, in three lines. This is the property `root_checked`
    /// exists to refuse, so the test asserts the collision is real before
    /// asserting that it is caught — a rejection test that never demonstrates
    /// what it rejects can pass against a decoder that rejects everything.
    #[test]
    fn an_odd_row_makes_two_lists_share_a_root() {
        let (a, b, c) = (leaf(1), leaf(2), leaf(3));

        assert_eq!(
            root(&[a, b, c]),
            root(&[a, b, c, c]),
            "the duplicated leaf is indistinguishable from a real one"
        );
        assert!(
            root_checked(&[a, b, c]).is_ok(),
            "an odd row is not itself the flaw"
        );
        assert_eq!(
            root_checked(&[a, b, c, c]),
            Err(MerkleError::DuplicateSiblings { level: 0, index: 2 })
        );
    }

    #[test]
    fn duplicates_are_found_above_the_leaves_too() {
        // Four distinct leaves whose two branches happen to collide cannot be
        // constructed by hand, so build the case one row up instead: eight
        // leaves where rows 0 and 1 are clean and row 2 is not.
        let leaves: Vec<Hash<32>> = (0..4).map(leaf).collect();
        let doubled: Vec<Hash<32>> = leaves.iter().chain(leaves.iter()).copied().collect();

        assert_eq!(
            root_checked(&doubled),
            Err(MerkleError::DuplicateSiblings { level: 2, index: 0 }),
            "the two halves are identical, which only shows up at their join"
        );
        // …and the row-0 and row-1 pairs really are all distinct, so `level`
        // is not just reporting the first row it looked at.
        assert!(root_checked(&leaves).is_ok());
    }

    #[test]
    fn a_root_states_its_byte_order() {
        let root = MerkleRoot::from_wire([0xab; 32]);
        assert_eq!(root.to_string(), root.to_hash().to_hex_reversed());
        assert_eq!(
            root.to_string().parse::<MerkleRoot>(),
            Ok(root),
            "Display and FromStr agree, so a displayed root reads back"
        );
    }
}
