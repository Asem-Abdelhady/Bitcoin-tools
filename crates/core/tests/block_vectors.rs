//! Block headers against real mainnet blocks, which are their acceptance
//! criteria.
//!
//! Three suites, each testing something the others cannot:
//!
//! - **Headers** — eighty bytes in, six fields and a hash out, then back to
//!   the same eighty bytes.
//! - **Targets** — the `bits` of ten blocks expanded and turned into the
//!   difficulty every explorer prints. The exponents run from `0x1d` down to
//!   `0x17` with none missing, so the shift is exercised at seven widths
//!   rather than at the one difficulty 1 happens to use.
//! - **Merkle roots** — recomputed from the block's own transaction list and
//!   checked against the root the header commits to. Eight blocks, from one
//!   transaction up to 457, which is the case that covers odd rows: 457
//!   halves to 229, 115, 58, 29, 15 and 8, so the duplicate-the-last rule
//!   fires five times in a single tree.
//!
//! Every expectation comes from `bitcoin-tools-vectors`, never from a value
//! restated here.

use bitcoin_tools_core::blocks::{BlockHash, BlockHeader, CompactTarget, MerkleRoot, merkle};
use bitcoin_tools_core::hashes::Hash;
use bitcoin_tools_core::hex;
use bitcoin_tools_vectors as vectors;
use bitcoin_tools_vectors::{field, number};

/// The header decodes to the fields the vector names, hashes to the block's
/// id, and re-encodes to the bytes it came from.
#[test]
fn block_header_vectors() {
    let set = vectors::blocks();
    assert_eq!(set.len(), 10);

    for vector in &set {
        let at = format!("block {}", number(vector, "height", "a vector"));
        let raw = field(vector, "header", &at);

        let header = BlockHeader::from_hex(raw).unwrap_or_else(|e| panic!("{at}: {e}"));

        assert_eq!(
            u64::from(header.version),
            number(vector, "version", &at),
            "{at}"
        );
        assert_eq!(u64::from(header.time), number(vector, "time", &at), "{at}");
        assert_eq!(
            u64::from(header.nonce),
            number(vector, "nonce", &at),
            "{at}"
        );
        assert_eq!(
            u64::from(header.bits.to_consensus()),
            number(vector, "bits", &at),
            "{at}"
        );

        // The three hashes, each in the order it is published in — which is
        // the reversed one, and the whole reason these are not `Hash<32>`.
        assert_eq!(
            header.block_hash().to_string(),
            field(vector, "hash", &at),
            "{at}"
        );
        assert_eq!(
            header.prev_block.to_string(),
            field(vector, "prevBlock", &at),
            "{at}"
        );
        assert_eq!(
            header.merkle_root.to_string(),
            field(vector, "merkleRoot", &at),
            "{at}"
        );

        // Byte-exact both ways, so nothing was quietly normalised.
        assert_eq!(hex::encode(&header.encode()), raw, "{at}");
        assert_eq!(header.breakdown().raw_header, raw, "{at}");
        assert_eq!(
            BlockHeader::decode(&header.encode()),
            Ok(header),
            "{at}: decoding what we encoded gives back the same header"
        );

        // The displayed forms read back as the values they were printed from.
        assert_eq!(
            header.block_hash().to_string().parse::<BlockHash>(),
            Ok(header.block_hash()),
            "{at}"
        );
        assert_eq!(
            header.merkle_root.to_string().parse::<MerkleRoot>(),
            Ok(header.merkle_root),
            "{at}"
        );
    }
}

/// `bits` expands to the published target, the hash comes in under it, and the
/// difficulty matches what the explorers show.
#[test]
fn compact_target_vectors() {
    let set = vectors::blocks();
    let mut exponents: Vec<u8> = Vec::new();

    for vector in &set {
        let at = format!("block {}", number(vector, "height", "a vector"));
        let header = BlockHeader::from_hex(field(vector, "header", &at))
            .unwrap_or_else(|e| panic!("{at}: {e}"));

        let target = header.target().unwrap_or_else(|e| panic!("{at}: {e}"));
        assert_eq!(target.to_hex(), field(vector, "target", &at), "{at}");
        assert!(
            header.meets_target(),
            "{at}: a mined block's hash is under its own target"
        );

        // `difficulty` is a ratio of two 256-bit numbers evaluated in f64, so
        // it is compared relatively. Being out by one part in 10^12 would
        // still be a bug — every published difficulty here agrees with Core's
        // `GetDifficulty` to far better than that.
        let expected = vector["difficulty"]
            .as_f64()
            .unwrap_or_else(|| panic!("{at} has no difficulty"));
        let difficulty = header.bits.difficulty();
        assert!(
            (difficulty - expected).abs() <= expected * 1e-12,
            "{at}: difficulty {difficulty} is not {expected}"
        );

        // The compact form round-trips through the spelling Core prints.
        assert_eq!(
            header.bits.to_string().parse::<CompactTarget>(),
            Ok(header.bits),
            "{at}"
        );
        exponents.push(header.bits.exponent());
    }

    exponents.sort_unstable();
    exponents.dedup();
    assert_eq!(
        exponents,
        (0x17..=0x1d).collect::<Vec<u8>>(),
        "the vectors are meant to walk the exponent with no gaps"
    );
}

/// The merkle root the header commits to is the one the block's transactions
/// produce.
#[test]
fn merkle_root_vectors() {
    let set = vectors::blocks();
    let mut checked = 0;

    for vector in &set {
        let at = format!("block {}", number(vector, "height", "a vector"));
        let Some(txids) = vector["txids"].as_array() else {
            continue;
        };
        let header = BlockHeader::from_hex(field(vector, "header", &at))
            .unwrap_or_else(|e| panic!("{at}: {e}"));

        // Txids are published reversed, like every hash Bitcoin shows, so they
        // are read with the parser that undoes that. Reading them forwards
        // produces a wrong root and no error.
        let leaves: Vec<Hash<32>> = txids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                let id = id.as_str().unwrap_or_else(|| panic!("{at} txid {i}"));
                Hash::from_hex_reversed(id).unwrap_or_else(|e| panic!("{at} txid {i}: {e}"))
            })
            .collect();

        assert_eq!(
            merkle::root(&leaves),
            Some(header.merkle_root),
            "{at}: {} transactions",
            leaves.len()
        );
        // No real block repeats a transaction, so no real block trips the
        // duplicate-sibling check.
        assert_eq!(
            merkle::root_checked(&leaves),
            Ok(header.merkle_root),
            "{at}"
        );

        // A single-transaction block is the degenerate tree: its root is the
        // coinbase txid itself, with nothing hashed at all.
        if leaves.len() == 1 {
            assert_eq!(
                header.merkle_root.to_string(),
                txids[0].as_str().unwrap_or_default(),
                "{at}"
            );
        }
        checked += 1;
    }

    assert_eq!(checked, 8, "eight blocks carry their transaction list");
}
