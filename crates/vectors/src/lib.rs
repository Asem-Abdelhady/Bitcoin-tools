//! Known-good Bitcoin test vectors.
//!
//! A dev-only workspace member, never published. It exists because two crates
//! assert against the same data from different angles — `core` checks that its
//! decoder reproduces each vector, and `server` checks that the HTTP response
//! equals it — and neither should reach into the other's `tests/` directory or
//! restate how to load a fixture.
//!
//! Everything here is a real mainnet transaction. A disagreement between the
//! code and a vector is a bug in the code.
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

#[cfg(test)]
mod tests {
    use super::*;

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
