//! Known-good Bitcoin test vectors.
//!
//! A dev-only workspace member, never published. It exists because two crates
//! assert against the same data from different angles — `core` checks that its
//! decoder reproduces each vector, and `server` checks that the HTTP response
//! equals it — and neither should reach into the other's `tests/` directory or
//! restate how to load a fixture.
//!
//! The transaction files are real mainnet transactions; the rest are the
//! official vectors from the BIPs, transcribed unchanged. A disagreement
//! between the code and a vector is a bug in the code.
//!
//! ```
//! let txs = bitcoin_tools_vectors::legacy();
//! assert!(txs.iter().all(|tx| tx["rawTx"].is_string()));
//! ```

use serde_json::Value;

/// Legacy (pre-segwit) transactions, as serialized by the splitter.
pub const LEGACY_TXS: &str = include_str!("../data/legacy_txs.json");

/// Segwit (BIP144) transactions, as serialized by the splitter.
pub const SEGWIT_TXS: &str = include_str!("../data/segwit_txs.json");

/// BIP39's English vectors: entropy, sentence, seed and master key, each with
/// the `TREZOR` passphrase the published set uses.
pub const BIP39: &str = include_str!("../data/bip39.json");

/// BIP32's four seeded test vectors, each with the chains derived from it.
pub const BIP32: &str = include_str!("../data/bip32.json");

/// BIP32's fifth vector: extended keys that must be *rejected*, each with the
/// reason the BIP gives. The half of the suite that a permissive decoder
/// fails.
pub const BIP32_INVALID: &str = include_str!("../data/bip32_invalid.json");

/// BIP49, BIP84 and BIP86's account vectors: one mnemonic, three layouts, and
/// the keys and addresses each of them derives.
pub const ACCOUNTS: &str = include_str!("../data/accounts.json");

/// Mainnet block headers, with the hash, expanded target, difficulty and
/// merkle root each one implies — and, for the smaller blocks, every txid the
/// merkle root is built from.
///
/// Ten blocks chosen for their `bits`: genesis and its neighbours at
/// difficulty 1, then seven more whose exponents walk the compact encoding
/// down from `0x1d` to `0x17` without a gap, so the expansion is exercised at
/// every width mainnet has used.
pub const BLOCKS: &str = include_str!("../data/blocks.json");

/// Parse one of the raw JSON constants into its array of vectors.
///
/// # Panics
///
/// If the JSON is not an array. The files are compiled in, so this is a build
/// error surfacing at test time, not something a caller can trigger.
#[must_use]
pub fn parse(raw: &str) -> Vec<Value> {
    match serde_json::from_str(raw) {
        Ok(Value::Array(v)) => v,
        other => panic!("vector file is not a JSON array: {other:?}"),
    }
}

/// A string field a vector is required to carry.
///
/// `at` names the vector for the failure message — `"bip39[3]"`,
/// `"block 100000"` — since a suite that loops over a file needs to say which
/// entry was wrong.
///
/// # Panics
///
/// If the field is absent or not a string. That is a defect in the vector
/// file, which is compiled in, so it is a build-time mistake surfacing at test
/// time rather than anything a caller can trigger.
#[must_use]
pub fn field<'a>(vector: &'a Value, name: &str, at: &str) -> &'a str {
    match vector[name].as_str() {
        Some(s) => s,
        None => panic!("{at} has no {name}"),
    }
}

/// A numeric field a vector is required to carry.
///
/// # Panics
///
/// If the field is absent or not a non-negative integer. See [`field`].
#[must_use]
pub fn number(vector: &Value, name: &str, at: &str) -> u64 {
    match vector[name].as_u64() {
        Some(n) => n,
        None => panic!("{at} has no {name}"),
    }
}

/// [`LEGACY_TXS`], parsed.
#[must_use]
pub fn legacy() -> Vec<Value> {
    parse(LEGACY_TXS)
}

/// [`SEGWIT_TXS`], parsed.
#[must_use]
pub fn segwit() -> Vec<Value> {
    parse(SEGWIT_TXS)
}

/// [`BIP39`], parsed.
#[must_use]
pub fn bip39() -> Vec<Value> {
    parse(BIP39)
}

/// [`BIP32`], parsed.
#[must_use]
pub fn bip32() -> Vec<Value> {
    parse(BIP32)
}

/// [`BIP32_INVALID`], parsed.
#[must_use]
pub fn bip32_invalid() -> Vec<Value> {
    parse(BIP32_INVALID)
}

/// [`ACCOUNTS`], parsed.
#[must_use]
pub fn accounts() -> Vec<Value> {
    parse(ACCOUNTS)
}

/// [`BLOCKS`], parsed.
#[must_use]
pub fn blocks() -> Vec<Value> {
    parse(BLOCKS)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The HD files are transcriptions, so the thing worth checking here is
    /// that the transcription is complete — a missing field would otherwise
    /// make a test in `core` pass by skipping the case.
    #[test]
    fn the_hd_vectors_are_whole() {
        let bip39 = bip39();
        assert_eq!(bip39.len(), 24, "BIP39 publishes 24 English vectors");
        for (i, v) in bip39.iter().enumerate() {
            for field in ["entropy", "mnemonic", "passphrase", "seed", "xprv"] {
                assert!(v[field].is_string(), "bip39[{i}] has no {field}");
            }
        }

        let bip32 = bip32();
        assert_eq!(bip32.len(), 4, "BIP32 publishes 4 seeded vectors");
        let chains: usize = bip32
            .iter()
            .map(|v| v["chains"].as_array().map_or(0, Vec::len))
            .sum();
        assert_eq!(chains, 17, "…covering 17 derivations between them");
        for (i, v) in bip32.iter().enumerate() {
            assert!(v["seed"].is_string(), "bip32[{i}] has no seed");
            for chain in v["chains"].as_array().expect("chains is an array") {
                for field in ["path", "xpub", "xprv"] {
                    assert!(chain[field].is_string(), "bip32[{i}] chain has no {field}");
                }
            }
        }

        assert_eq!(bip32_invalid().len(), 16, "…and 16 keys that must fail");
        for (i, v) in bip32_invalid().iter().enumerate() {
            assert!(
                v["key"].is_string() && v["reason"].is_string(),
                "invalid[{i}]"
            );
        }

        let accounts = accounts();
        assert_eq!(accounts.len(), 3, "BIP49, BIP84 and BIP86");
        for (i, group) in accounts.iter().enumerate() {
            assert!(group["bip"].is_u64(), "accounts[{i}] has no bip number");
            assert!(group["mnemonic"].is_string());
            let addresses = group["addresses"].as_array().expect("an array");
            assert!(!addresses.is_empty(), "accounts[{i}] derives nothing");
            for address in addresses {
                assert!(address["path"].is_string());
                assert!(address["address"].is_string());
            }
        }
    }

    /// Same reasoning as the HD files: a field missing from the transcription
    /// would make a test in `core` pass by skipping the case it was written
    /// for.
    #[test]
    fn the_block_vectors_are_whole() {
        let blocks = blocks();
        assert_eq!(blocks.len(), 10);
        for (i, b) in blocks.iter().enumerate() {
            for field in ["hash", "header", "prevBlock", "merkleRoot", "target"] {
                assert!(b[field].is_string(), "blocks[{i}] has no {field}");
            }
            for field in ["height", "version", "time", "bits", "nonce", "txCount"] {
                assert!(b[field].is_u64(), "blocks[{i}] has no {field}");
            }
            assert!(b["difficulty"].is_f64(), "blocks[{i}] has no difficulty");
            let header = b["header"].as_str().unwrap_or_default();
            assert_eq!(header.len(), 160, "blocks[{i}] is not eighty bytes");

            // The txid list is optional — the two largest blocks carry
            // thousands — but where it exists it has to be the whole block, or
            // the merkle root it is checked against is not this block's.
            if let Some(txids) = b["txids"].as_array() {
                assert_eq!(
                    txids.len() as u64,
                    b["txCount"].as_u64().unwrap_or_default(),
                    "blocks[{i}] lists some but not all of its txids"
                );
            }
        }
        let with_txids = blocks.iter().filter(|b| b["txids"].is_array()).count();
        assert_eq!(with_txids, 8, "eight blocks carry their transaction list");
    }

    #[test]
    fn every_vector_carries_a_raw_transaction() {
        for (label, set) in [("legacy", legacy()), ("segwit", segwit())] {
            assert!(!set.is_empty(), "{label} vectors are empty");
            for (i, tx) in set.iter().enumerate() {
                let raw = tx["rawTx"].as_str();
                assert!(raw.is_some(), "{label}[{i}] has no rawTx");
                let raw = raw.unwrap_or_default();
                assert!(
                    !raw.is_empty() && raw.len() % 2 == 0,
                    "{label}[{i}] rawTx is not whole bytes"
                );
            }
        }
    }
}
