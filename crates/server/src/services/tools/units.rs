//! 1.3 — the unit converter, as a use case.

use serde::Deserialize;

use bitcoin_tools_core::general::{Amount, Denomination, ParseAmountError};

/// What `/tools/units` accepts.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnitsRequest {
    /// The amount, as a string.
    ///
    /// A string rather than a JSON number, and the type refuses one. This is
    /// the field where a double would do real damage: `0.1 + 0.2` losing a
    /// satoshi is a bug that has shipped in real wallets, and the domain holds
    /// money in integer satoshis precisely so it cannot happen here. Accepting
    /// `0.00000001` as a double and converting it back would be inventing an
    /// amount.
    pub amount: String,
    /// Which unit `amount` is written in: `satoshi`, `microbitcoin`,
    /// `millibitcoin` or `bitcoin`.
    ///
    /// Required, with no default. `1` is a satoshi or a hundred million of
    /// them, and there is no reading of the request that makes one of those
    /// the obvious intent.
    pub denomination: Denomination,
}

/// 1.3 — read an amount in one unit, ready to render in all four.
///
/// # This does not enforce the 21-million cap
///
/// [`Amount`] deliberately does not, and neither does this: a malformed
/// transaction can declare any `u64` as an output value, and a tool that
/// refused to *represent* such a value could not show you the transaction that
/// contains it. The cap is a question rather than a precondition —
/// [`Amount::is_money_range`] — and the response reports the answer instead of
/// turning it into a rejection.
///
/// What is refused is a quantity that does not exist: more satoshis than fit
/// in a `u64`, or a fraction finer than the unit can hold. `0.1 sat` is not a
/// small amount, it is not an amount.
///
/// # Errors
///
/// [`ParseAmountError`] for an empty or negative value, a stray character, a
/// second decimal point, precision past the unit, or a total past `u64`
/// satoshis.
pub fn convert(request: &UnitsRequest) -> Result<Amount, ParseAmountError> {
    Amount::parse(&request.amount, request.denomination)
}

#[cfg(test)]
mod tests {
    //! Only what this crate decides — see the note in
    //! [`number`](super::super::number)'s tests. Precision, negatives, the
    //! 21-million question and every rendering are the domain's, asserted over
    //! HTTP in `tools_api` rather than twice.

    use super::*;

    #[test]
    fn the_denomination_is_required_and_the_amount_must_be_a_string() {
        assert!(
            serde_json::from_str::<UnitsRequest>(r#"{"amount":"1"}"#).is_err(),
            "one is a satoshi or a hundred million of them, and the request has to say"
        );
        assert!(
            serde_json::from_str::<UnitsRequest>(r#"{"amount":0.1,"denomination":"bitcoin"}"#)
                .is_err(),
            "a double is how a wallet loses a satoshi"
        );
        assert!(
            serde_json::from_str::<UnitsRequest>(r#"{"amount":"1","denomination":"btc"}"#).is_err(),
            "the domain's FromStr aliases are deliberately not the wire contract"
        );
        assert!(
            serde_json::from_str::<UnitsRequest>(r#"{"amount":"1","denomination":"bitcoin"}"#)
                .is_ok()
        );
    }
}
