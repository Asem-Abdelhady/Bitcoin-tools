//! reversing byte order, as a use case.

use crate::services::input::{InputError, hex_bytes};
use crate::services::tools::HexRequest;
use bitcoin_tools_core::transactions::tx::Tx;

/// The noun this endpoint's error messages use.
///
/// Not "transaction" or "hash": the whole point is that it does not
/// care what the bytes are.
const SUBJECT: &str = "input";

/// The largest payload this endpoint will flip.
///
/// Reversal is linear and could take anything, so the cap is a policy rather
/// than a limit of the operation — and the policy is that the byte-order tool
/// must not be the stingiest door in the building. [`Tx::MAX_SIZE`] is the
/// largest hex this API accepts anywhere, so a payload some other endpoint
/// would read cannot be one this endpoint refuses.
pub const MAX_BYTES: usize = Tx::MAX_SIZE;

/// read the bytes a caller wants flipped.
///
/// The flip itself is not here, and that is the layering rather than an
/// omission: reversing is *rendering* — `hex::encode` one way, `encode_rev`
/// the other — and rendering belongs to the view. `/blocks/hash` already
/// splits exactly this way, its service returning a hash and its handler
/// writing the two byte orders. What is left for a use case is the input
/// policy, which is the whole of it.
///
/// One endpoint covers both directions, because reversal is an involution: a
/// `direction` field would decorate the request without changing what is
/// computed. Bitcoin writes hashes into blocks and transactions in one order
/// and shows them to people in the other, and this is the operation relating
/// the two — a txid copied from an explorer never appears verbatim in the raw
/// transaction that produced it.
///
/// # Why this does not call [`reverse_hex`](bitcoin_tools_core::general::reverse_hex)
///
/// [`bitcoin_tools_core::general::reverse_hex`] is hex in, hex out, and it
/// re-implements the input handling this server already has: the trimming, the
/// `0x`, and — crucially — its own answer for an empty string, which it
/// deliberately calls valid because "whether the caller should have sent
/// something is the caller's policy". This *is* that caller, and its policy is
/// `empty-input`, the same at every endpoint. Core's own docs point a caller
/// that decodes through its own input policy at
/// [`hex::encode_rev`](bitcoin_tools_core::hex::encode_rev) instead, which is
/// what the handler uses.
///
/// # Errors
///
/// [`InputError`] for an empty payload, a payload that is not whole bytes of
/// hex, or one past [`MAX_BYTES`]. There is no domain error: once bytes exist,
/// reversing them cannot fail.
pub fn decode(request: &HexRequest) -> Result<Vec<u8>, InputError> {
    hex_bytes(&request.hex, SUBJECT, MAX_BYTES)
}

#[cfg(test)]
mod tests {
    //! What is left to test here is the input policy — the two things this
    //! module decides. Everything about the flip itself is a property of the
    //! response, and `tools_api` asserts it there.

    use super::*;
    use bitcoin_tools_core::hex::HexError;

    fn request(hex: &str) -> HexRequest {
        HexRequest {
            hex: hex.to_owned(),
        }
    }

    /// Core's `reverse_hex` calls an empty string a valid input and says the
    /// decision belongs to whoever is asking. This is whoever is asking.
    #[test]
    fn empty_is_this_layers_decision_and_the_answer_is_no() {
        assert_eq!(
            decode(&request(" 0x ")).unwrap_err(),
            InputError::Empty { subject: SUBJECT }
        );
    }

    #[test]
    fn a_lone_nibble_is_not_bytes_to_reverse() {
        assert_eq!(
            decode(&request("abc")).unwrap_err(),
            InputError::Hex(HexError::OddLength { len: 3 })
        );
    }

    #[test]
    fn the_noise_people_paste_is_accepted_and_the_bytes_are_the_value() {
        assert_eq!(
            decode(&request("  0xDEADBEEF \n")).unwrap(),
            [0xde, 0xad, 0xbe, 0xef]
        );
    }

    #[test]
    fn the_cap_is_the_largest_payload_this_api_takes_anywhere() {
        assert_eq!(MAX_BYTES, Tx::MAX_SIZE);
        let too_much = "00".repeat(MAX_BYTES + 1);
        assert_eq!(
            decode(&request(&too_much)).unwrap_err(),
            InputError::TooLarge {
                subject: SUBJECT,
                max_bytes: MAX_BYTES,
                got_bytes: MAX_BYTES + 1,
            }
        );
    }
}
