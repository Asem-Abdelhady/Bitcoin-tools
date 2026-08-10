//! Script analysis as a use case, independent of how it was requested.
//!
//! Owns the input policy — what counts as an acceptable script to analyse —
//! and returns domain values. Nothing here knows about HTTP, so a CLI, a
//! batch job, or a handler reading rows out of a database can all call it.

use core::fmt;

use crate::types::transactions::script::{ParseHexError, Script, ScriptAnalysis};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptServiceError {
    Empty,
    TooLong { max_bytes: usize, got_bytes: usize },
    InvalidHex(ParseHexError),
}

impl fmt::Display for ScriptServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptServiceError::Empty => f.write_str("script must not be empty"),
            ScriptServiceError::TooLong {
                max_bytes,
                got_bytes,
            } => write!(
                f,
                "script is {got_bytes} bytes; the consensus limit is {max_bytes}"
            ),
            ScriptServiceError::InvalidHex(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ScriptServiceError {}

/// Normalise a user-supplied hex string: trim surrounding whitespace and an
/// optional `0x` prefix, both of which people paste in constantly.
fn normalize(input: &str) -> &str {
    input.trim().trim_start_matches("0x")
}

/// Validate a hex script and analyse it.
///
/// A *malformed script* is not an error here — [`ScriptAnalysis::error`]
/// carries where it broke, alongside everything that decoded successfully.
/// Only unusable input produces an `Err`.
pub fn analyze_hex(input: &str) -> Result<ScriptAnalysis, ScriptServiceError> {
    let hex = normalize(input);
    if hex.is_empty() {
        return Err(ScriptServiceError::Empty);
    }
    if hex.len() > Script::MAX_SIZE * 2 {
        return Err(ScriptServiceError::TooLong {
            max_bytes: Script::MAX_SIZE,
            got_bytes: hex.len() / 2,
        });
    }
    let script = Script::from_hex(hex).map_err(ScriptServiceError::InvalidHex)?;
    Ok(script.analyze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transactions::script::ScriptKind;

    #[test]
    fn analyses_a_p2pkh() {
        let a = analyze_hex("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac").unwrap();
        assert_eq!(a.kind, ScriptKind::P2PKH);
        assert_eq!(a.size_bytes, 25);
        assert_eq!(a.instructions.len(), 5);
        assert!(a.error.is_none());
    }

    #[test]
    fn tolerates_prefix_and_whitespace() {
        let a = analyze_hex("  0x0014275b468073affad6c1b2833d026416ec07392b7f \n").unwrap();
        assert_eq!(a.kind, ScriptKind::P2WPKH);
    }

    #[test]
    fn a_broken_script_still_analyses() {
        let a = analyze_hex("7605aabb").unwrap();
        assert_eq!(a.instructions.len(), 1);
        assert!(a.error.is_some());
    }

    #[test]
    fn rejects_unusable_input() {
        assert_eq!(analyze_hex("   ").unwrap_err(), ScriptServiceError::Empty);
        assert_eq!(analyze_hex("0x").unwrap_err(), ScriptServiceError::Empty);
        assert!(matches!(
            analyze_hex("zz").unwrap_err(),
            ScriptServiceError::InvalidHex(_)
        ));
        assert_eq!(
            analyze_hex(&"00".repeat(Script::MAX_SIZE + 1)).unwrap_err(),
            ScriptServiceError::TooLong {
                max_bytes: 10_000,
                got_bytes: 10_001
            }
        );
    }

    #[test]
    fn accepts_a_script_exactly_at_the_limit() {
        let a = analyze_hex(&"00".repeat(Script::MAX_SIZE)).unwrap();
        assert_eq!(a.size_bytes, Script::MAX_SIZE);
    }
}
