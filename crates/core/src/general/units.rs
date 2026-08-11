//! 1.3 — Unit Converter: one amount in satoshis, µBTC, mBTC and BTC.
//!
//! # Money is an integer
//!
//! [`Amount`] is a count of satoshis and nothing else. Denominations exist
//! only at the edges, in [`Amount::parse`] and [`Amount::to_string_in`], and
//! the arithmetic in between is `u64`. No value in this module is ever a
//! float: `0.1 + 0.2` is not `0.3`, and a wallet that loses a satoshi that way
//! has a real bug that no amount of rounding at the display layer fixes.
//!
//! Converting is therefore not arithmetic on a quantity — it is choosing where
//! to put a decimal point in an integer that never changes.
//!
//! # An `Amount` is not a *valid* amount
//!
//! Nothing here rejects a value above 21 million BTC, and that is deliberate.
//! [`Output::value`](crate::transactions::tx::Output) is an `Amount`, and a
//! transaction that declares a nonsensical output value is a real thing that
//! turns up on a decoder's doorstep — this crate's job is to show it, not to
//! refuse to represent it. Re-encoding has to reproduce the bytes that came
//! in, which a type that clamped or rejected could not do.
//!
//! So the range check is a question you ask ([`Amount::is_money_range`]),
//! never a precondition of holding the value. Bitcoin Core draws the same
//! line: `CAmount` is a plain integer and `MoneyRange()` is a separate call.

use std::fmt;
use std::str::FromStr;

use crate::parse::name_table;

/// A unit an amount can be written in.
///
/// The four the tool converts between. Each is a fixed power of ten of a
/// satoshi, which is what makes the conversion exact.
///
/// Deliberately **not** `#[non_exhaustive]`, unlike [`Network`](crate::network::Network)
/// and [`Base`](crate::general::Base). Those may grow a variant — testnet4
/// exists, octal is imaginable — and neither promises a fixed-size list. This
/// one does: [`Denomination::all`] returns `[Denomination; 4]`, so a fifth
/// variant would change that signature and break every caller regardless of
/// what the attribute claimed. Given the two cannot both be true, the exhaustive
/// enum is worth more — a `match` needs no `_` arm, so if a unit ever were
/// added the compiler would name every place that renders one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum Denomination {
    /// The base unit. One satoshi is indivisible on-chain.
    Satoshi,
    /// 100 satoshis. Also called a "bit".
    MicroBitcoin,
    /// 100 000 satoshis.
    MilliBitcoin,
    /// 100 000 000 satoshis.
    Bitcoin,
}

impl Denomination {
    /// Digits after the decimal point this unit can express. A satoshi is
    /// indivisible, so its answer is zero — `0.5 sat` is not an amount.
    ///
    /// This is the one number that defines a denomination; everything else
    /// about it is derived.
    #[must_use]
    pub const fn decimals(self) -> u32 {
        match self {
            Denomination::Satoshi => 0,
            Denomination::MicroBitcoin => 2,
            Denomination::MilliBitcoin => 5,
            Denomination::Bitcoin => 8,
        }
    }

    /// How many satoshis make one of this unit.
    ///
    /// Derived from [`Denomination::decimals`] rather than tabulated beside
    /// it. Two tables would be one fact written twice, and a fifth unit could
    /// be added to one and forgotten in the other — the sort of disagreement
    /// that renders in a unit a caller cannot parse back.
    #[must_use]
    pub const fn sats_per_unit(self) -> u64 {
        10u64.pow(self.decimals())
    }

    /// Every denomination, in ascending order — the four rows a converter
    /// shows. Having the list here means a caller cannot render three of them
    /// and silently forget the fourth.
    #[must_use]
    pub const fn all() -> [Denomination; 4] {
        [
            Denomination::Satoshi,
            Denomination::MicroBitcoin,
            Denomination::MilliBitcoin,
            Denomination::Bitcoin,
        ]
    }
}

name_table! {
    /// Accepts the symbols case-insensitively, plus the plurals and
    /// spelled-out names people type, and `ubtc`/`bit` for µBTC — the `µ` is
    /// awkward to enter and every tool in this space takes a plain `u` for it.
    Denomination => UnknownDenomination,
    kind: "denomination",
    expected: "sat, µBTC, mBTC, or BTC",
    {
        // Case is handled by the matcher, so each spelling appears once.
        // `ubtc` is a separate entry rather than a case of `µBTC`: `u` and `µ`
        // are different characters, not different cases of one.
        Satoshi      => "sat", "sats", "satoshi", "satoshis";
        MicroBitcoin => "µBTC", "ubtc", "bit", "bits", "microbitcoin";
        MilliBitcoin => "mBTC", "millibitcoin";
        Bitcoin      => "BTC", "bitcoin";
    }
}

/// Why a string was not an amount.
//
// Not `Copy`, because `UnknownUnit` owns the string it is reporting. Worth
// stating: every other parse error in the crate is `Copy`, and this one gave
// that up to keep hold of what the caller actually typed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseAmountError {
    /// Nothing but whitespace, or a bare decimal point.
    Empty,
    /// A leading `-`. Called out separately from an invalid character because
    /// it is a plausible thing to type: this type is unsigned, and a balance
    /// change that can go either way is a different type from an amount.
    Negative,
    /// A character that is neither a digit nor the decimal point. The offset
    /// is a byte offset into the trimmed string.
    InvalidChar { offset: usize },
    /// A second decimal point, at this byte offset in the trimmed string.
    MoreThanOnePoint { offset: usize },
    /// More significant fractional digits than the unit can hold — the one
    /// error that exists to stop money being silently rounded away.
    /// `0.000000001 BTC` is a tenth of a satoshi, which is not an amount.
    ///
    /// How many digits were allowed is [`Denomination::decimals`]; carrying it
    /// here as well would be two public fields that can be seen to disagree.
    TooPrecise {
        /// The unit the amount was being read in.
        denomination: Denomination,
    },
    /// More satoshis than fit in a `u64`, which is past any amount Bitcoin
    /// can represent on the wire.
    TooLarge,
    /// The text after the number named no unit this crate knows. Only
    /// [`Amount::from_str`] produces this; [`Amount::parse`] is told its
    /// denomination rather than reading one.
    UnknownUnit(UnknownDenomination),
}

impl fmt::Display for ParseAmountError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseAmountError::Empty => f.write_str("expected an amount, got nothing"),
            ParseAmountError::Negative => f.write_str("an amount cannot be negative"),
            ParseAmountError::InvalidChar { offset } => {
                write!(f, "not a digit or decimal point at byte {offset}")
            }
            ParseAmountError::MoreThanOnePoint { offset } => {
                write!(f, "a second decimal point at byte {offset}")
            }
            ParseAmountError::TooPrecise { denomination } => write!(
                f,
                "{denomination} has {} decimal places; \
                 anything finer is not a whole number of satoshis",
                denomination.decimals()
            ),
            ParseAmountError::TooLarge => f.write_str("more satoshis than fit in 64 bits"),
            ParseAmountError::UnknownUnit(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ParseAmountError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseAmountError::UnknownUnit(e) => Some(e),
            _ => None,
        }
    }
}

impl From<UnknownDenomination> for ParseAmountError {
    fn from(e: UnknownDenomination) -> Self {
        ParseAmountError::UnknownUnit(e)
    }
}

/// An amount of bitcoin, counted in satoshis.
///
/// ```
/// use bitcoin_tools_core::general::{Amount, Denomination};
///
/// let amount = Amount::parse("0.00015", Denomination::Bitcoin)?;
/// assert_eq!(amount.to_sat(), 15_000);
///
/// // The same amount, in each unit the converter shows.
/// assert_eq!(amount.to_string_in(Denomination::Satoshi), "15000");
/// assert_eq!(amount.to_string_in(Denomination::MicroBitcoin), "150");
/// assert_eq!(amount.to_string_in(Denomination::MilliBitcoin), "0.15");
/// assert_eq!(amount.to_string_in(Denomination::Bitcoin), "0.00015");
/// # Ok::<_, bitcoin_tools_core::general::ParseAmountError>(())
/// ```
///
/// # Serialization
///
/// With the `serde` feature, an `Amount` serializes as its **satoshi count, as
/// a JSON number** — the same shape `Output::value` had when it was a bare
/// `u64`, so this type's arrival did not change any wire format.
///
/// That is a contract with one sharp edge worth stating rather than
/// discovering. JSON numbers are IEEE-754 doubles in most consumers, which
/// hold integers exactly only below 2^53. Every *consensus-valid* amount is
/// safe: [`Amount::MAX_MONEY`] is 2.1 × 10^15, comfortably under 9.0 × 10^15.
/// A malformed transaction's absurd value is not — `u64::MAX` satoshis reads
/// back in JavaScript as 18446744073709552000.
///
/// This is the one place the "represent whatever the bytes said" rule meets a
/// format that cannot. A consumer needing exactness for malformed data should
/// read the hex, which is lossless and is what
/// [`TxBreakdown`](crate::transactions::tx::TxBreakdown) already reports for
/// output amounts.
//
// Unlike `Number`, deriving `Ord` here is correct: this is one fixed-width
// integer, so the derive compares the value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Amount(u64);

impl Amount {
    /// Zero satoshis.
    pub const ZERO: Amount = Amount(0);

    /// One satoshi, the smallest amount that exists.
    pub const ONE_SAT: Amount = Amount(1);

    /// 21 000 000 BTC, the total that will ever be issued.
    ///
    /// A bound to *check against*, not one this type enforces — see the module
    /// docs. Nothing prevents constructing an `Amount` above it, because a
    /// malformed transaction can declare one and a decoder has to show it.
    pub const MAX_MONEY: Amount = Amount(21_000_000 * Denomination::Bitcoin.sats_per_unit());

    /// An amount from a raw satoshi count.
    #[must_use]
    pub const fn from_sat(sats: u64) -> Self {
        Amount(sats)
    }

    /// The satoshi count. The only lossless view of an amount, which is why
    /// everything else in the crate stores this.
    #[must_use]
    pub const fn to_sat(self) -> u64 {
        self.0
    }

    /// True if this is at most [`Amount::MAX_MONEY`].
    ///
    /// The question a validator asks and a decoder does not. Bitcoin Core's
    /// `MoneyRange()`.
    #[must_use]
    pub const fn is_money_range(self) -> bool {
        self.0 <= Self::MAX_MONEY.0
    }

    /// Read an amount written in `denomination`.
    ///
    /// Surrounding whitespace is trimmed. A decimal point is allowed with
    /// digits on either or both sides, so `1`, `1.`, `.5` and `0.5` all parse.
    ///
    /// Fractional digits past what the unit can express are rejected rather
    /// than rounded — but only if they are significant, so `1.0 sat` is one
    /// satoshi while `0.1 sat` is an error.
    ///
    /// The split is not arbitrary: a trailing zero is a property of the
    /// *notation*, not of the value, so `1.0 sat` and `1 sat` denote the same
    /// quantity and accepting the first rounds nothing. `0.1 sat` denotes a
    /// quantity that does not exist. Being strict in both directions would be
    /// worse either way round — rejecting `1.0 sat` refuses a correct spelling
    /// of a real amount, and accepting `0.1 sat` invents one.
    ///
    /// # Errors
    ///
    /// [`ParseAmountError`] for an empty or negative input, a stray character,
    /// a second decimal point, more precision than the unit holds, or a value
    /// past `u64` satoshis.
    ///
    /// ```
    /// use bitcoin_tools_core::general::{Amount, Denomination};
    ///
    /// assert_eq!(Amount::parse("1", Denomination::Bitcoin)?.to_sat(), 100_000_000);
    /// assert_eq!(Amount::parse("0.00000001", Denomination::Bitcoin)?.to_sat(), 1);
    ///
    /// // A tenth of a satoshi is not an amount, and is not quietly rounded.
    /// assert!(Amount::parse("0.000000001", Denomination::Bitcoin).is_err());
    /// # Ok::<_, bitcoin_tools_core::general::ParseAmountError>(())
    /// ```
    pub fn parse(s: &str, denomination: Denomination) -> Result<Self, ParseAmountError> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ParseAmountError::Empty);
        }
        if trimmed.starts_with('-') {
            return Err(ParseAmountError::Negative);
        }

        let mut point = None;
        for (offset, &c) in trimmed.as_bytes().iter().enumerate() {
            match c {
                b'0'..=b'9' => {}
                b'.' if point.is_none() => point = Some(offset),
                b'.' => return Err(ParseAmountError::MoreThanOnePoint { offset }),
                _ => return Err(ParseAmountError::InvalidChar { offset }),
            }
        }

        let (whole, fraction) = match point {
            // The point is one ASCII byte, so these indices are char
            // boundaries: every byte before here was matched as a digit.
            Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
            None => (trimmed, ""),
        };
        if whole.is_empty() && fraction.is_empty() {
            // A lone ".".
            return Err(ParseAmountError::Empty);
        }

        let decimals = denomination.decimals() as usize;
        // Digits past the unit's precision are acceptable only if they are
        // zeros: `1.50 sat` is 1, `1.05 sat` is not a number of satoshis.
        if fraction.len() > decimals && fraction[decimals..].bytes().any(|b| b != b'0') {
            return Err(ParseAmountError::TooPrecise { denomination });
        }
        let significant = &fraction[..decimals.min(fraction.len())];

        let whole: u64 = if whole.is_empty() {
            0
        } else {
            whole.parse().map_err(|_| ParseAmountError::TooLarge)?
        };
        let sats = whole
            .checked_mul(denomination.sats_per_unit())
            .ok_or(ParseAmountError::TooLarge)?;

        if significant.is_empty() {
            return Ok(Amount(sats));
        }
        // Right-pad the fraction to the unit's precision, so `0.5 BTC` is
        // 50000000 satoshis rather than 5.
        let scale = 10u64.pow((decimals - significant.len()) as u32);
        let fraction: u64 = significant
            .parse::<u64>()
            .map_err(|_| ParseAmountError::TooLarge)?
            .checked_mul(scale)
            .ok_or(ParseAmountError::TooLarge)?;
        sats.checked_add(fraction)
            .map(Amount)
            .ok_or(ParseAmountError::TooLarge)
    }

    /// Write this amount in `denomination`, without a unit suffix.
    ///
    /// Trailing zeros in the fraction are dropped and the point goes with them
    /// when nothing is left, so one bitcoin is `"1"` rather than `"1.00000000"`
    /// — the value, not a field of fixed width.
    #[must_use]
    pub fn to_string_in(self, denomination: Denomination) -> String {
        let per_unit = denomination.sats_per_unit();
        let whole = self.0 / per_unit;
        let fraction = self.0 % per_unit;
        if fraction == 0 {
            return whole.to_string();
        }
        let width = denomination.decimals() as usize;
        let mut out = format!("{whole}.{fraction:0width$}");
        // `fraction` is non-zero, so this always leaves a digit after the
        // point and can never strip the point itself.
        while out.ends_with('0') {
            out.pop();
        }
        out
    }

    /// This amount in every denomination, ascending — the whole point of 1.3.
    ///
    /// ```
    /// use bitcoin_tools_core::general::{Amount, Denomination};
    ///
    /// let all = Amount::from_sat(150).to_strings();
    /// assert_eq!(all, [
    ///     (Denomination::Satoshi, "150".to_string()),
    ///     (Denomination::MicroBitcoin, "1.5".to_string()),
    ///     (Denomination::MilliBitcoin, "0.0015".to_string()),
    ///     (Denomination::Bitcoin, "0.0000015".to_string()),
    /// ]);
    /// ```
    #[must_use]
    pub fn to_strings(self) -> [(Denomination, String); 4] {
        Denomination::all().map(|d| (d, self.to_string_in(d)))
    }

    /// Sum, or `None` on overflow.
    ///
    /// Amounts are added when totalling a transaction's outputs, where the
    /// inputs are untrusted: a malformed transaction can carry values that
    /// overflow, so the checked form is the only one offered.
    #[must_use]
    pub const fn checked_add(self, other: Self) -> Option<Self> {
        match self.0.checked_add(other.0) {
            Some(sats) => Some(Amount(sats)),
            None => None,
        }
    }

    /// Difference, or `None` if it would go below zero.
    #[must_use]
    pub const fn checked_sub(self, other: Self) -> Option<Self> {
        match self.0.checked_sub(other.0) {
            Some(sats) => Some(Amount(sats)),
            None => None,
        }
    }
}

/// Satoshis, with the unit named.
///
/// An amount printed without its unit is ambiguous in a way a hash never is —
/// `1` could be four different amounts — so the bare `Display` says which one
/// it chose. Use [`Amount::to_string_in`] to pick.
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("{} {}", self.0, Denomination::Satoshi))
    }
}

impl FromStr for Amount {
    type Err = ParseAmountError;

    /// Reads back what [`Display`](fmt::Display) writes, and a little more:
    /// `"1500 sat"`, `"0.5 BTC"`, `"0.5BTC"` with no space, or a bare number,
    /// which is taken as satoshis.
    ///
    /// The inverse exists because the printed form is otherwise a dead end —
    /// a CLI that prints an amount and pipes it into the next command needs
    /// something to read it with, and every other `Display` in this crate has
    /// a way back.
    ///
    /// # Errors
    ///
    /// Everything [`Amount::parse`] reports, plus
    /// [`ParseAmountError::UnknownUnit`] when the trailing text names no unit.
    ///
    /// ```
    /// use bitcoin_tools_core::general::Amount;
    ///
    /// let amount = Amount::from_sat(1500);
    /// assert_eq!(amount.to_string(), "1500 sat");
    /// assert_eq!(amount.to_string().parse(), Ok(amount));
    ///
    /// assert_eq!("0.5 BTC".parse::<Amount>()?.to_sat(), 50_000_000);
    /// assert_eq!("42".parse::<Amount>()?.to_sat(), 42);
    /// # Ok::<_, bitcoin_tools_core::general::ParseAmountError>(())
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        // The number runs up to the first character that cannot be part of
        // one; whatever follows is the unit.
        let split = trimmed
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(trimmed.len());
        let (number, unit) = trimmed.split_at(split);
        if number.is_empty() {
            // Nothing numeric at the front, so there is no unit to blame.
            // Let the amount parser report where the string actually broke.
            return Amount::parse(trimmed, Denomination::Satoshi);
        }
        let unit = unit.trim();
        let denomination = if unit.is_empty() {
            Denomination::Satoshi
        } else {
            unit.parse()?
        };
        Amount::parse(number, denomination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_amount_in_every_unit() {
        // 1 BTC, the round case.
        let btc = Amount::from_sat(100_000_000);
        assert_eq!(btc.to_string_in(Denomination::Satoshi), "100000000");
        assert_eq!(btc.to_string_in(Denomination::MicroBitcoin), "1000000");
        assert_eq!(btc.to_string_in(Denomination::MilliBitcoin), "1000");
        assert_eq!(btc.to_string_in(Denomination::Bitcoin), "1");

        // One satoshi, the other end.
        let sat = Amount::ONE_SAT;
        assert_eq!(sat.to_string_in(Denomination::Satoshi), "1");
        assert_eq!(sat.to_string_in(Denomination::MicroBitcoin), "0.01");
        assert_eq!(sat.to_string_in(Denomination::MilliBitcoin), "0.00001");
        assert_eq!(sat.to_string_in(Denomination::Bitcoin), "0.00000001");

        // Zero is zero everywhere, with no decimal point.
        for d in Denomination::all() {
            assert_eq!(Amount::ZERO.to_string_in(d), "0", "{d}");
        }
    }

    #[test]
    fn trailing_zeros_are_not_part_of_an_amount() {
        assert_eq!(
            Amount::from_sat(150_000_000).to_string_in(Denomination::Bitcoin),
            "1.5"
        );
        assert_eq!(
            Amount::from_sat(100_000_001).to_string_in(Denomination::Bitcoin),
            "1.00000001"
        );
        assert_eq!(
            Amount::from_sat(120_000_000).to_string_in(Denomination::Bitcoin),
            "1.2"
        );
    }

    /// Every unit must read back what it wrote, at values that exercise each
    /// boundary between them.
    #[test]
    fn parsing_and_rendering_are_inverses() {
        let values = [
            0u64,
            1,
            99,
            100,
            101,
            99_999,
            100_000,
            100_001,
            99_999_999,
            100_000_000,
            100_000_001,
            150_000_000,
            2_100_000_000_000_000,
            u64::MAX,
        ];
        for sats in values {
            let amount = Amount::from_sat(sats);
            for d in Denomination::all() {
                let text = amount.to_string_in(d);
                assert_eq!(
                    Amount::parse(&text, d),
                    Ok(amount),
                    "{sats} sat rendered as {text} {d} did not read back"
                );
            }
        }
    }

    /// `parsing_and_rendering_are_inverses` is self-consistency: if µBTC were
    /// 1000 satoshis everywhere, every round trip in it would still pass. This
    /// is the external check — fixed-point string formatting, which is an
    /// independent definition of "move the decimal point".
    #[test]
    fn rendering_agrees_with_fixed_point_formatting() {
        for sats in [
            0u64,
            1,
            9,
            10,
            99,
            100,
            101,
            999,
            1_000,
            99_999,
            100_000,
            100_001,
            12_345_678,
            99_999_999,
            100_000_000,
            100_000_001,
            150_000_000,
            2_100_000_000_000_000,
            u64::MAX,
        ] {
            for d in Denomination::all() {
                let places = d.decimals() as usize;
                // Zero-pad to at least one digit before the point, then split
                // the last `places` digits off as the fraction.
                let padded = format!("{sats:0width$}", width = places + 1);
                let (whole, fraction) = padded.split_at(padded.len() - places);
                let whole = whole.trim_start_matches('0');
                let whole = if whole.is_empty() { "0" } else { whole };
                let expected = match fraction.trim_end_matches('0') {
                    "" => whole.to_string(),
                    trimmed => format!("{whole}.{trimmed}"),
                };
                assert_eq!(
                    Amount::from_sat(sats).to_string_in(d),
                    expected,
                    "{sats} sat in {d}"
                );
            }
        }
    }

    #[test]
    fn parses_the_forms_people_type() {
        let btc = Denomination::Bitcoin;
        assert_eq!(Amount::parse("1", btc), Ok(Amount::from_sat(100_000_000)));
        assert_eq!(Amount::parse("1.", btc), Ok(Amount::from_sat(100_000_000)));
        assert_eq!(Amount::parse(".5", btc), Ok(Amount::from_sat(50_000_000)));
        assert_eq!(Amount::parse("0.5", btc), Ok(Amount::from_sat(50_000_000)));
        assert_eq!(
            Amount::parse("  1.5  ", btc),
            Ok(Amount::from_sat(150_000_000))
        );
        // Leading zeros carry no information.
        assert_eq!(
            Amount::parse("0001", btc),
            Ok(Amount::from_sat(100_000_000))
        );
        // A short fraction is right-padded, not read as an integer.
        assert_eq!(Amount::parse("0.1", btc), Ok(Amount::from_sat(10_000_000)));
    }

    /// The one rule that protects money: precision is never silently dropped.
    #[test]
    fn refuses_to_round_money_away() {
        assert_eq!(
            Amount::parse("0.000000001", Denomination::Bitcoin),
            Err(ParseAmountError::TooPrecise {
                denomination: Denomination::Bitcoin
            })
        );
        assert_eq!(
            Amount::parse("0.1", Denomination::Satoshi),
            Err(ParseAmountError::TooPrecise {
                denomination: Denomination::Satoshi
            })
        );
        assert_eq!(
            Amount::parse("0.001", Denomination::MicroBitcoin),
            Err(ParseAmountError::TooPrecise {
                denomination: Denomination::MicroBitcoin
            })
        );
        // …but a zero past the precision loses nothing, so it is allowed.
        assert_eq!(
            Amount::parse("1.0", Denomination::Satoshi),
            Ok(Amount::ONE_SAT)
        );
        assert_eq!(
            Amount::parse("0.000000010", Denomination::Bitcoin),
            Ok(Amount::ONE_SAT)
        );
        assert_eq!(
            Amount::parse("1.500", Denomination::MicroBitcoin),
            Ok(Amount::from_sat(150))
        );
    }

    #[test]
    fn rejects_what_is_not_an_amount() {
        let btc = Denomination::Bitcoin;
        assert_eq!(Amount::parse("", btc), Err(ParseAmountError::Empty));
        assert_eq!(Amount::parse("   ", btc), Err(ParseAmountError::Empty));
        assert_eq!(Amount::parse(".", btc), Err(ParseAmountError::Empty));
        assert_eq!(Amount::parse("-1", btc), Err(ParseAmountError::Negative));
        assert_eq!(
            Amount::parse("1.2.3", btc),
            Err(ParseAmountError::MoreThanOnePoint { offset: 3 })
        );
        assert_eq!(
            Amount::parse("1,5", btc),
            Err(ParseAmountError::InvalidChar { offset: 1 })
        );
        assert_eq!(
            Amount::parse("1 BTC", btc),
            Err(ParseAmountError::InvalidChar { offset: 1 }),
            "the unit is an argument, not part of the string"
        );
        // Past u64 satoshis, in the unit that reaches it soonest.
        assert_eq!(
            Amount::parse("184467440737.09551616", btc),
            Err(ParseAmountError::TooLarge)
        );
        assert_eq!(
            Amount::parse("99999999999999999999", btc),
            Err(ParseAmountError::TooLarge)
        );
    }

    /// The boundary `u64::MAX` sits at: 18446744073.70955161 BTC parses, and
    /// one satoshi more does not.
    #[test]
    fn the_largest_representable_amount() {
        let max = Amount::from_sat(u64::MAX);
        let text = max.to_string_in(Denomination::Bitcoin);
        assert_eq!(text, "184467440737.09551615");
        assert_eq!(Amount::parse(&text, Denomination::Bitcoin), Ok(max));
        assert_eq!(
            Amount::parse("184467440737.09551616", Denomination::Bitcoin),
            Err(ParseAmountError::TooLarge)
        );
    }

    #[test]
    fn max_money_is_a_question_not_a_rule() {
        assert_eq!(Amount::MAX_MONEY.to_sat(), 2_100_000_000_000_000);
        assert_eq!(
            Amount::MAX_MONEY.to_string_in(Denomination::Bitcoin),
            "21000000"
        );
        assert!(Amount::MAX_MONEY.is_money_range());
        assert!(Amount::ZERO.is_money_range());
        // Above it is still a perfectly constructible amount — a decoder has
        // to be able to show a malformed transaction's absurd output value.
        let absurd = Amount::from_sat(Amount::MAX_MONEY.to_sat() + 1);
        assert!(!absurd.is_money_range());
        assert_eq!(absurd.to_sat(), 2_100_000_000_000_001);
        assert!(!Amount::from_sat(u64::MAX).is_money_range());
    }

    #[test]
    fn arithmetic_is_checked() {
        let a = Amount::from_sat(3);
        assert_eq!(a.checked_add(Amount::ONE_SAT), Some(Amount::from_sat(4)));
        assert_eq!(a.checked_sub(Amount::ONE_SAT), Some(Amount::from_sat(2)));
        assert_eq!(
            a.checked_sub(Amount::from_sat(4)),
            None,
            "amounts are unsigned"
        );
        assert_eq!(
            Amount::from_sat(u64::MAX).checked_add(Amount::ONE_SAT),
            None
        );
    }

    #[test]
    fn amounts_order_and_default_by_value() {
        assert!(Amount::ONE_SAT > Amount::ZERO);
        assert!(Amount::MAX_MONEY > Amount::from_sat(100_000_000));
        assert_eq!(Amount::default(), Amount::ZERO);
        let mut v = [Amount::from_sat(100), Amount::ZERO, Amount::from_sat(2)];
        v.sort();
        assert_eq!(
            v,
            [Amount::ZERO, Amount::from_sat(2), Amount::from_sat(100)]
        );
    }

    #[test]
    fn display_names_the_unit_it_chose() {
        assert_eq!(Amount::from_sat(1500).to_string(), "1500 sat");
        assert_eq!(Amount::ZERO.to_string(), "0 sat");
        // Width and alignment are honoured, so a column of these lines up.
        assert_eq!(format!("{:>12}", Amount::from_sat(1500)), "    1500 sat");
        assert_eq!(format!("{:>6}", Denomination::Bitcoin), "   BTC");
    }

    /// Every other `Display` in the crate has a way back; this one does too.
    #[test]
    fn amounts_read_back_from_what_display_wrote() {
        for sats in [0u64, 1, 1500, 100_000_000, u64::MAX] {
            let amount = Amount::from_sat(sats);
            assert_eq!(amount.to_string().parse(), Ok(amount), "{sats}");
        }
    }

    #[test]
    fn from_str_takes_a_unit_or_assumes_satoshis() {
        assert_eq!("42".parse(), Ok(Amount::from_sat(42)));
        assert_eq!("42 sat".parse(), Ok(Amount::from_sat(42)));
        assert_eq!("0.5 BTC".parse(), Ok(Amount::from_sat(50_000_000)));
        // The space is optional, and the unit's aliases all work.
        assert_eq!("0.5BTC".parse(), Ok(Amount::from_sat(50_000_000)));
        assert_eq!("  1.5 mbtc ".parse(), Ok(Amount::from_sat(150_000)));
        assert_eq!("1 bit".parse(), Ok(Amount::from_sat(100)));

        assert_eq!(
            "1 BCH".parse::<Amount>(),
            Err(ParseAmountError::UnknownUnit(UnknownDenomination(
                "BCH".to_owned()
            )))
        );
        // A string with no leading number is reported as a broken amount
        // rather than as an unknown unit — there is no number for a unit to
        // belong to.
        assert_eq!(
            "abc".parse::<Amount>(),
            Err(ParseAmountError::InvalidChar { offset: 0 })
        );
        assert_eq!("".parse::<Amount>(), Err(ParseAmountError::Empty));
        assert_eq!("-1 BTC".parse::<Amount>(), Err(ParseAmountError::Negative));
        // The precision rule still applies once the unit is known.
        assert_eq!(
            "0.1 sat".parse::<Amount>(),
            Err(ParseAmountError::TooPrecise {
                denomination: Denomination::Satoshi
            })
        );
    }

    #[test]
    fn denomination_reads_back_from_the_symbol_it_prints() {
        for d in Denomination::all() {
            assert_eq!(d.to_string().parse(), Ok(d), "{d}");
        }
        for (text, expected) in [
            ("sat", Denomination::Satoshi),
            ("SATS", Denomination::Satoshi),
            ("  satoshi ", Denomination::Satoshi),
            ("µBTC", Denomination::MicroBitcoin),
            ("ubtc", Denomination::MicroBitcoin),
            ("bit", Denomination::MicroBitcoin),
            ("mBTC", Denomination::MilliBitcoin),
            ("btc", Denomination::Bitcoin),
            ("Bitcoin", Denomination::Bitcoin),
        ] {
            assert_eq!(text.parse(), Ok(expected), "{text}");
        }
        assert_eq!(
            "BCH".parse::<Denomination>(),
            Err(UnknownDenomination("BCH".to_owned()))
        );
        assert_eq!("kBTC".parse::<Denomination>().unwrap_err().input(), "kBTC");
    }

    /// The table lists `µBTC` once, in the case it is written in, and case
    /// folding does the rest — so this pins the two ends of that: an
    /// ASCII-case variant of the µ spelling resolves, and a *different
    /// character* that merely looks like µ does not.
    #[test]
    fn micro_is_matched_by_case_not_by_shape() {
        for spelling in ["µBTC", "µbtc", "ΜBTC"] {
            let parsed = spelling.parse::<Denomination>();
            if spelling == "ΜBTC" {
                // U+039C GREEK CAPITAL LETTER MU is not U+00B5 MICRO SIGN.
                assert!(parsed.is_err(), "{spelling} is not the micro sign");
            } else {
                assert_eq!(parsed, Ok(Denomination::MicroBitcoin), "{spelling}");
            }
        }
        // And the ASCII stand-in is its own entry, not a case of the µ one.
        assert_eq!("UBTC".parse(), Ok(Denomination::MicroBitcoin));
    }

    /// The scales themselves, stated once against literals rather than against
    /// the formula that produces them — otherwise this asserts `10^d == 10^d`.
    #[test]
    fn each_unit_has_the_scale_bitcoin_gives_it() {
        assert_eq!(Denomination::Satoshi.sats_per_unit(), 1);
        assert_eq!(Denomination::MicroBitcoin.sats_per_unit(), 100);
        assert_eq!(Denomination::MilliBitcoin.sats_per_unit(), 100_000);
        assert_eq!(Denomination::Bitcoin.sats_per_unit(), 100_000_000);
    }
}
