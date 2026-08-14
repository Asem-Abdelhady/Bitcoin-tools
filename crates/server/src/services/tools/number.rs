//! the number converter, as a use case.

use serde::Deserialize;

use bitcoin_tools_core::general::{Base, Number, ParseNumberError};

/// What `/tools/number` accepts.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NumberRequest {
    /// The value, as a string.
    ///
    /// A string rather than a JSON number, and the type refuses one: this
    /// endpoint exists so a 256-bit private key can be read in decimal, and a
    /// JSON number is a double in most consumers — exact only below 2^53. A
    /// field that quietly returned a *different* number from the one sent
    /// would defeat the whole point.
    pub value: String,
    /// Which base `value` is written in: `binary`, `decimal` or
    /// `hexadecimal`.
    ///
    /// Required, with no default, for the same reason `/transactions/builder`
    /// requires `type`: the answer changes. `10` is two, ten or sixteen, and
    /// nothing about the string says which — a caller who omitted this and got
    /// a default would be told a confident wrong answer.
    pub base: Base,
}

/// read a number in one base, ready to render in all three.
///
/// The domain's parser does the whole job, including the trimming, the empty
/// check and the digit-count cap, so this is the request shape and nothing
/// else. That is the use case: the policy here is *which fields exist and what
/// they may be*, and there is no second step to sequence.
///
/// The base's own prefix (`0x`, `0b`) is accepted; another base's is not
/// stripped, so `0x10` read as decimal fails on the `x` rather than quietly
/// answering sixteen.
///
/// # Errors
///
/// [`ParseNumberError`] if the value is empty, holds a character that is not a
/// digit in that base, or is longer than [`Number::MAX_DIGITS`].
pub fn convert(request: &NumberRequest) -> Result<Number, ParseNumberError> {
    Number::parse(&request.value, request.base)
}

#[cfg(test)]
mod tests {
    //! Only what this crate decides.
    //!
    //! `convert` is `Number::parse` with a request wrapped round it, so an
    //! assertion about digits, bases or the group order would be testing the
    //! domain through a delegator and restating its expectations in a second
    //! file. `tools_api` owns the behaviour end to end; what is left here is
    //! the request shape, whose attributes are this module's own.

    use super::*;

    #[test]
    fn the_base_is_required_and_the_value_must_be_a_string() {
        assert!(
            serde_json::from_str::<NumberRequest>(r#"{"value":"10"}"#).is_err(),
            "a missing base must not default to one: 10 is two, ten or sixteen"
        );
        assert!(
            serde_json::from_str::<NumberRequest>(r#"{"value":10,"base":"decimal"}"#).is_err(),
            "a JSON number cannot carry the values this endpoint exists for"
        );
        assert!(
            serde_json::from_str::<NumberRequest>(r#"{"value":"10","base":"decimal","x":1}"#)
                .is_err(),
            "a typo is a mistake, not a field to ignore"
        );
        assert!(
            serde_json::from_str::<NumberRequest>(r#"{"value":"10","base":"decimal"}"#).is_ok()
        );
    }
}
