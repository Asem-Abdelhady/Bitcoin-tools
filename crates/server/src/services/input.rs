//! Input validation shared by every endpoint that takes hex.
//!
//! One place decides what "usable hex input" means, so a new tool endpoint
//! inherits the trimming, the empty check, the size cap, and the error
//! vocabulary without restating any of it.

use std::fmt;

use bitcoin_tools_core::hex::{self, HexError};

use crate::services::error::ServiceError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    /// `subject` names what was expected, so messages read naturally at
    /// every endpoint without each one defining its own error type.
    Empty {
        subject: &'static str,
    },
    TooLarge {
        subject: &'static str,
        max_bytes: usize,
        got_bytes: usize,
    },
    Hex(HexError),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Empty { subject } => write!(f, "{subject} must not be empty"),
            InputError::TooLarge {
                subject,
                max_bytes,
                got_bytes,
            } => write!(
                f,
                "{subject} is {got_bytes} bytes; the maximum is {max_bytes}"
            ),
            InputError::Hex(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InputError {}

impl From<HexError> for InputError {
    fn from(e: HexError) -> Self {
        InputError::Hex(e)
    }
}

/// Normalise and decode a hex field from a request.
///
/// `subject` is the noun used in error messages ("script", "transaction").
/// The size cap is checked against the hex length *before* decoding, so an
/// oversized payload is rejected without allocating for it.
pub fn hex_bytes(
    input: &str,
    subject: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, InputError> {
    if hex::normalize(input).is_empty() {
        return Err(InputError::Empty { subject });
    }
    hex_bytes_allowing_empty(input, subject, max_bytes)
}

/// The same, for a field where empty is a real value rather than a mistake.
///
/// Most endpoints take one hex payload and an empty one is a caller error —
/// there is nothing to decode. A transaction's *parts* are not like that:
/// an unsigned input has an empty `scriptSig`, so does every native segwit
/// input, a witness stack can carry an empty item as a placeholder, and an
/// output may carry an empty (unspendable) script. Refusing those would make
/// the builder unable to express ordinary transactions.
///
/// Splitting this from [`hex_bytes`] rather than adding a flag keeps the
/// decision at the call site, where the field is named and the answer is
/// obvious, instead of behind a boolean nobody reads.
pub fn hex_bytes_allowing_empty(
    input: &str,
    subject: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, InputError> {
    let trimmed = hex::normalize(input);
    if trimmed.len() > max_bytes * 2 {
        return Err(InputError::TooLarge {
            subject,
            max_bytes,
            // Rounded *up*: an odd number of hex digits is not whole bytes, and
            // truncating produced a message that contradicted itself — 161
            // digits against an 80-byte cap read "is 80 bytes; the maximum is
            // 80". The size check runs before decoding, so this is the only
            // place that number is ever computed from a half-byte.
            got_bytes: trimmed.len().div_ceil(2),
        });
    }
    Ok(hex::decode(trimmed)?)
}

/// Decode a hex field that must be an exact number of bytes.
///
/// Most inputs have a *ceiling* — a script up to 10,000 bytes, a transaction up
/// to 1,000,000 — and for those [`hex_bytes`] is the whole story. A header, a
/// private key, a signature and a txid are not like that: they are one width,
/// and "too long" is not a different mistake from "too short". Splitting them
/// across `input-too-large` (413) and a domain error (400) would make a client
/// branch on two slugs to say one sentence, and `input-too-large` elsewhere
/// means a 10 kB script — a vocabulary that would then mean two things.
///
/// So both directions become the caller's own error, built by `wrong_width`
/// from the size actually supplied. The endpoint keeps a slug named for what it
/// parses (`invalid-block-header`, `invalid-private-key`) instead of borrowing
/// one that means something else.
///
/// The cap is still applied before decoding, so an enormous payload is refused
/// without allocating for it.
///
/// The width is a const parameter and the return is an array, so a caller that
/// needs `[u8; 32]` gets one — no `try_into`, and no `expect` asserting an
/// invariant that lives in this function. Callers state it as a type
/// annotation:
///
/// ```
/// use bitcoin_tools_server::services::error::ServiceError;
/// use bitcoin_tools_server::services::input::hex_bytes_exact;
///
/// let bytes: [u8; 4] = hex_bytes_exact("aabbccdd", "widget", |got| format!("got {got}"))?;
/// assert_eq!(bytes, [0xaa, 0xbb, 0xcc, 0xdd]);
///
/// // Either direction of the width arrives as the caller's own error.
/// let short = hex_bytes_exact::<4, _>("aabbcc", "widget", |got| format!("got {got}"));
/// assert_eq!(short, Err(ServiceError::Domain("got 3".to_string())));
/// # Ok::<_, ServiceError<String>>(())
/// ```
pub fn hex_bytes_exact<const N: usize, E>(
    input: &str,
    subject: &'static str,
    wrong_width: impl FnOnce(usize) -> E,
) -> Result<[u8; N], ServiceError<E>> {
    // Both arms that reach `wrong_width` funnel into one call, so it stays
    // `FnOnce` — a caller should be able to pass a closure that moves.
    let got = match hex_bytes(input, subject, N) {
        // `TryFrom<Vec<_>>` rather than from a slice: it moves the bytes and
        // hands the vector back on failure, so the success path is a move and
        // reads as one.
        Ok(bytes) => match <[u8; N]>::try_from(bytes) {
            Ok(exact) => return Ok(exact),
            // Short: the cap above only rejects long ones.
            Err(short) => short.len(),
        },
        Err(InputError::TooLarge { got_bytes, .. }) => got_bytes,
        Err(other) => return Err(ServiceError::Input(other)),
    };
    Err(ServiceError::Domain(wrong_width(got)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stand-in for the domain errors real callers build — the point is that
    /// the width failure arrives as *theirs*, carrying the size supplied.
    #[derive(Debug, PartialEq, Eq)]
    struct WrongWidth(usize);

    #[test]
    fn an_exact_width_reports_both_directions_as_one_error() {
        let exact = |s: &str| hex_bytes_exact::<4, _>(s, "private key", WrongWidth);

        assert_eq!(exact("aabbccdd").unwrap(), [0xaa, 0xbb, 0xcc, 0xdd]);
        assert_eq!(
            exact("aabbcc").unwrap_err(),
            ServiceError::Domain(WrongWidth(3)),
            "short is the caller's error, not an input one"
        );
        assert_eq!(
            exact("aabbccddee").unwrap_err(),
            ServiceError::Domain(WrongWidth(5)),
            "…and so is long, which `hex_bytes` alone would call TooLarge"
        );
    }

    /// Everything that is not about the width still comes back as input, so an
    /// exact-width endpoint keeps the shared vocabulary for the shared
    /// mistakes.
    #[test]
    fn only_the_width_becomes_a_domain_error() {
        let exact = |s: &str| hex_bytes_exact::<4, _>(s, "private key", WrongWidth);

        assert_eq!(
            exact("  ").unwrap_err(),
            ServiceError::Input(InputError::Empty {
                subject: "private key"
            })
        );
        assert!(matches!(
            exact("zzzzzzzz").unwrap_err(),
            ServiceError::Input(InputError::Hex(_))
        ));
    }

    #[test]
    fn decodes_and_trims() {
        assert_eq!(hex_bytes("  0xdead ", "script", 100).unwrap(), [0xde, 0xad]);
    }

    #[test]
    fn empty_after_normalising_is_empty() {
        assert_eq!(
            hex_bytes("  0x  ", "script", 100).unwrap_err(),
            InputError::Empty { subject: "script" }
        );
    }

    #[test]
    fn size_is_capped_before_decoding() {
        let err = hex_bytes(&"00".repeat(11), "transaction", 10).unwrap_err();
        assert_eq!(
            err,
            InputError::TooLarge {
                subject: "transaction",
                max_bytes: 10,
                got_bytes: 11
            }
        );
    }

    /// An odd number of digits is not whole bytes, and the cap is checked
    /// before decoding — so the reported size has to round up or the message
    /// contradicts itself.
    #[test]
    fn an_oversized_odd_length_input_does_not_report_the_cap_as_its_size() {
        let err = hex_bytes(&format!("{}0", "00".repeat(10)), "block header", 10).unwrap_err();
        assert_eq!(
            err,
            InputError::TooLarge {
                subject: "block header",
                max_bytes: 10,
                got_bytes: 11
            }
        );
        assert_eq!(
            err.to_string(),
            "block header is 11 bytes; the maximum is 10",
            "never 'is 10 bytes; the maximum is 10'"
        );
    }

    #[test]
    fn exactly_at_the_cap_is_allowed() {
        assert_eq!(hex_bytes(&"00".repeat(10), "script", 10).unwrap().len(), 10);
    }

    #[test]
    fn hex_errors_pass_through() {
        assert!(matches!(
            hex_bytes("zz", "script", 100).unwrap_err(),
            InputError::Hex(HexError::InvalidChar { offset: 0 })
        ));
        assert!(matches!(
            hex_bytes("abc", "script", 100).unwrap_err(),
            InputError::Hex(HexError::OddLength { len: 3 })
        ));
    }

    #[test]
    fn messages_name_the_subject() {
        assert_eq!(
            hex_bytes("", "transaction", 10).unwrap_err().to_string(),
            "transaction must not be empty"
        );
    }
}
