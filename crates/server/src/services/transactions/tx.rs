//! Transaction splitting as a use case, independent of how it was requested.

use serde::Deserialize;

use crate::services::error::ServiceError;
use crate::services::input::hex_bytes;
use bitcoin_tools_core::transactions::tx::{Tx, TxBreakdown, TxDecodeError};

/// What `/transactions/splitter` accepts.
///
/// A request shape is input policy, so it lives beside the service that
/// validates it, as [`TxSpec`](crate::services::transactions::builder::TxSpec)
/// and [`BlockHeaderRequest`](crate::services::blocks::header::BlockHeaderRequest)
/// do.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SplitTxRequest {
    /// The raw transaction, hex-encoded.
    pub tx: String,
}

/// Bad input, or valid hex that is not a transaction.
pub type TxServiceError = ServiceError<TxDecodeError>;

/// Validate a hex transaction and split it into its wire fields.
///
/// Unlike scripts, a malformed transaction *is* an error: once the field
/// boundaries stop lining up there is no meaningful partial answer.
pub fn split_hex(input: &str) -> Result<TxBreakdown, TxServiceError> {
    let bytes = hex_bytes(input, "transaction", Tx::MAX_SIZE)?;
    let tx = Tx::decode(&bytes).map_err(ServiceError::Domain)?;
    Ok(tx.breakdown())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::input::InputError;

    const LEGACY: &str = concat!(
        "010000000153b1daf7b3aade9da077083774979085b5366f9f6a929411af938da94baed3d4070000006a4730",
        "4402203dcf4f170e4391f001aad1d8a8ae96c6ce0d84a71ca743684c1d5d5f3405ede70220077d012cc96fe3",
        "17818d586216f8bbace87fd5ced54f2ec87b2b565a55dd7a59012102a7cf60791778f05df7778d8deaf4d175",
        "7cc1db18144bfc7f4f13686efd41f16affffffff02d9fc0100000000001976a914e2c0e4929f695a669826748",
        "a50e059cbf33163e788ac5d190e000000000017a9148ab9fcfe76318892b9053ce0b7e8a362b533b84d870000",
        "0000"
    );

    #[test]
    fn splits_a_legacy_tx() {
        let b = split_hex(LEGACY).unwrap();
        assert_eq!(
            b.txid,
            "05a24e27653895c2a28f3687f98910a1909cd7a011877e76b0cf746ffa5dd4a3"
        );
        assert!(b.wtxid.is_none(), "legacy tx has no wtxid field");
        assert!(b.marker.is_none() && b.flag.is_none());
        assert!(b.witness.is_none());
        assert_eq!(b.input_count, "01");
        assert_eq!(b.output_count, "02");
    }

    #[test]
    fn tolerates_prefix_and_whitespace() {
        let with_noise = format!("  0x{LEGACY}\n");
        assert_eq!(split_hex(&with_noise).unwrap(), split_hex(LEGACY).unwrap());
    }

    #[test]
    fn separates_input_problems_from_decode_problems() {
        assert_eq!(
            split_hex("   ").unwrap_err(),
            ServiceError::Input(InputError::Empty {
                subject: "transaction"
            })
        );
        assert!(matches!(
            split_hex("zzzz").unwrap_err(),
            ServiceError::Input(InputError::Hex(_))
        ));
        // Valid hex, invalid transaction.
        assert!(matches!(
            split_hex("0100").unwrap_err(),
            ServiceError::Domain(_)
        ));
    }
}
