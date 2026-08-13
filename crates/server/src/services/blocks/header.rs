//! Block header decoding as a use case, independent of how it was requested.
//!
//! One function serves both block endpoints. `/blocks/hash` and
//! `/blocks/header` take the identical eighty bytes and read them the identical
//! way; they differ only in what they render afterwards, which is a view's job
//! and so a handler's.

use serde::Deserialize;

use crate::services::error::ServiceError;
use crate::services::input::{InputError, hex_bytes};
use bitcoin_tools_core::blocks::{BlockHeader, HeaderDecodeError};

/// The noun this endpoint's messages use for its input.
const SUBJECT: &str = "block header";

/// What both block endpoints accept.
///
/// A request shape is input policy, so it lives with the service that
/// validates it rather than with either handler — and there are two handlers,
/// which is the case that makes the rule pay for itself.
///
/// The field is named for the domain, as `{"tx": …}` and `{"script": …}` are:
/// a caller should be able to guess it from the endpoint.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BlockHeaderRequest {
    /// The eighty-byte header, hex-encoded. `0x` and whitespace are tolerated.
    pub header: String,
}

/// Bad input, or usable hex that is not a block header.
pub type HeaderServiceError = ServiceError<HeaderDecodeError>;

/// Validate a hex block header and decode it.
///
/// # A fixed width has no "too large"
///
/// A header is eighty bytes exactly, so a byte over and a byte under are the
/// same mistake — the domain says so itself, and both directions answer with
/// [`WrongLength`](HeaderDecodeError::WrongLength) and one 400.
///
/// That takes one relabelling. [`hex_bytes`] is still what decides the input
/// is usable, but its size cap means "past this endpoint's ceiling", which is
/// what an oversized script or transaction is; here the same condition means
/// "not the width", so it is handed to the error that names the width.
/// Otherwise a client wanting to say "a block header is eighty bytes" would
/// have to branch on two slugs, one of which (`input-too-large`) elsewhere
/// means a 10 kB script or a 1 MB transaction. `/transactions/builder` already
/// settled this for its fixed-width `txid` field: wrong length in either
/// direction is one `invalid-txid`.
///
/// If a third fixed-width endpoint appears — and § 7's keys and signatures are
/// all fixed-width — this becomes `services::input::hex_bytes_exact` rather
/// than a third copy of the match.
pub fn decode(request: &BlockHeaderRequest) -> Result<BlockHeader, HeaderServiceError> {
    let bytes = hex_bytes(&request.header, SUBJECT, BlockHeader::SIZE).map_err(|e| match e {
        InputError::TooLarge { got_bytes, .. } => {
            ServiceError::Domain(HeaderDecodeError::WrongLength {
                got: got_bytes,
                expected: BlockHeader::SIZE,
            })
        }
        other => ServiceError::Input(other),
    })?;
    BlockHeader::decode(&bytes).map_err(ServiceError::Domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::input::InputError;
    use bitcoin_tools_core::hex::HexError;

    /// The genesis header — the one every reader can check by eye.
    const GENESIS: &str = concat!(
        "0100000000000000000000000000000000000000000000000000000000000000",
        "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
        "4b1e5e4a29ab5f49ffff001d1dac2b7c",
    );

    fn decode_hex(header: &str) -> Result<BlockHeader, HeaderServiceError> {
        decode(&BlockHeaderRequest {
            header: header.to_owned(),
        })
    }

    #[test]
    fn decodes_the_genesis_header() {
        let header = decode_hex(GENESIS).unwrap();
        assert_eq!(
            header.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(header.version, 1);
        assert_eq!(header.time, 1_231_006_505);
        assert_eq!(header.bits.to_string(), "1d00ffff");
        assert_eq!(header.nonce, 2_083_236_893);
    }

    #[test]
    fn tolerates_prefix_and_whitespace() {
        let with_noise = format!("  0x{GENESIS}\n");
        assert_eq!(
            decode_hex(&with_noise).unwrap(),
            decode_hex(GENESIS).unwrap()
        );
    }

    #[test]
    fn separates_input_problems_from_decode_problems() {
        assert_eq!(
            decode_hex("   ").unwrap_err(),
            ServiceError::Input(InputError::Empty {
                subject: "block header"
            })
        );
        assert!(matches!(
            decode_hex("zz").unwrap_err(),
            ServiceError::Input(InputError::Hex(HexError::InvalidChar { offset: 0 }))
        ));
        // Valid hex, not eighty bytes.
        assert!(matches!(
            decode_hex("0100").unwrap_err(),
            ServiceError::Domain(_)
        ));
    }

    /// Both directions of the width are one mistake with one answer, which is
    /// the whole of [`decode`]'s note.
    #[test]
    fn a_byte_over_and_a_byte_under_are_the_same_error() {
        let wrong_length = |got| {
            ServiceError::Domain(HeaderDecodeError::WrongLength {
                got,
                expected: BlockHeader::SIZE,
            })
        };

        assert_eq!(
            decode_hex(&GENESIS[..GENESIS.len() - 2]).unwrap_err(),
            wrong_length(79)
        );
        assert_eq!(
            decode_hex(&format!("{GENESIS}00")).unwrap_err(),
            wrong_length(81),
            "the shared cap fires here, but the width is what the caller hears"
        );

        // Odd digits past the cap: the size is rounded up, so the message can
        // never read "is 80 bytes" while rejecting the input for its width.
        assert_eq!(
            decode_hex(&format!("{GENESIS}0")).unwrap_err(),
            wrong_length(81)
        );
    }
}
