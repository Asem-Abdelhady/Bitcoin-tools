//! Input validation shared by every endpoint that takes hex.
//!
//! One place decides what "usable hex input" means, so a new tool endpoint
//! inherits the trimming, the empty check, the size cap, and the error
//! vocabulary without restating any of it.

use std::fmt;

use bitcoin_tools_core::hex::{self, HexError};

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
    let trimmed = hex::normalize(input);
    if trimmed.is_empty() {
        return Err(InputError::Empty { subject });
    }
    if trimmed.len() > max_bytes * 2 {
        return Err(InputError::TooLarge {
            subject,
            max_bytes,
            got_bytes: trimmed.len() / 2,
        });
    }
    Ok(hex::decode(trimmed)?)
}

#[cfg(test)]
mod tests {
    use super::*;

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
