//! Script analysis as a use case, independent of how it was requested.
//!
//! Nothing here knows about HTTP, so a CLI, a batch job, or a handler reading
//! rows out of a database can all call it.

use serde::Deserialize;

use crate::services::input::{InputError, hex_bytes};
use bitcoin_tools_core::transactions::script::{Script, ScriptAnalysis};

/// What `/transactions/script` accepts.
///
/// Beside its service for the same reason as every other request shape: which
/// fields exist is input policy, not transport.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AnalyzeScriptRequest {
    /// The script, hex-encoded, exactly as it appears in a raw transaction.
    pub script: String,
}

/// Validate a hex script and analyse it.
///
/// A *malformed script* is not an error: [`ScriptAnalysis::error`] carries
/// where it broke, alongside everything that decoded successfully. Only
/// unusable input produces an `Err`.
pub fn analyze_hex(input: &str) -> Result<ScriptAnalysis, InputError> {
    let bytes = hex_bytes(input, "script", Script::MAX_SIZE)?;
    Ok(Script::new(bytes).analyze())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_tools_core::hex::HexError;
    use bitcoin_tools_core::transactions::script::ScriptKind;

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
        assert_eq!(
            analyze_hex("   ").unwrap_err(),
            InputError::Empty { subject: "script" }
        );
        assert_eq!(
            analyze_hex("0x").unwrap_err(),
            InputError::Empty { subject: "script" }
        );
        assert!(matches!(
            analyze_hex("zz").unwrap_err(),
            InputError::Hex(HexError::InvalidChar { offset: 0 })
        ));
        assert_eq!(
            analyze_hex(&"00".repeat(Script::MAX_SIZE + 1)).unwrap_err(),
            InputError::TooLarge {
                subject: "script",
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
