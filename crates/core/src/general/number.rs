//! Number Converter: one value in base 2, 10 or 16, shown in all three.
//!
//! # Why this is arbitrary-precision
//!
//! The obvious implementation is `u64::from_str_radix` and `format!("{:b}")`,
//! and it is wrong for this crate. The numbers Bitcoin actually asks people to
//! read in more than one base are 256-bit: a private key as a decimal
//! integer, the secp256k1 group order a key must fall below, a difficulty
//! target, a hash treated as the number it has to be less than. A converter
//! that stops at 64 bits would refuse every one of them, and
//! [`keys`](crate::keys) would then carry a second, private implementation of
//! decimal rendering — the copy worth not writing.
//!
//! So [`Number`] is an unsigned integer of no particular width, held as
//! big-endian bytes. Nothing here is a general bignum library: parsing is
//! multiply-accumulate and decimal rendering is repeated division, both
//! quadratic in the width. That is the whole arithmetic requirement of this
//! crate.
//!
//! Being quadratic, both doors into the type are bounded:
//! [`Number::MAX_DIGITS`] for text through [`Number::parse`], and
//! [`Number::MAX_BYTES`] for bytes through [`Number::try_from_be_bytes`].
//! [`Number::from_be_bytes`] is the deliberate exception — infallible for the
//! fixed-size arrays a caller already holds, and therefore the one entry point
//! that must not be handed a length that came from a request.
//!
//! # A number is not a byte string
//!
//! [`hex`] decodes *byte strings*, so it rejects an odd number of
//! digits — half a byte is not a byte. A number written in hex has no such
//! rule: `fff` is 4095, and demanding `0fff` would be inventing a constraint
//! the value does not have. That is why parsing here does not route through
//! [`hex::decode`], and it is the one place in the crate
//! where hex digits are read by something other than that function.
//!
//! Widths do not survive the trip either. `00ff` and `ff` are the same number
//! and render identically, because leading zeros are a property of a *field*,
//! not of a value. Going back into a fixed-width field is therefore an
//! explicit step: a 32-byte key parsed from decimal has no array to fall back
//! on, so it wants [`Number::to_be_bytes_padded`]; a caller that already holds
//! the array is rendering bytes rather than a number and wants
//! [`hex::encode`] on it directly.

use std::cmp::Ordering;
use std::fmt;
use std::fmt::Write as _;

use crate::hex;
use crate::parse::name_table;

/// The bases this converter reads and writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Base {
    /// Base 2, written with `0` and `1`.
    Binary,
    /// Base 10.
    Decimal,
    /// Base 16, read in either case and written in lower.
    Hexadecimal,
}

impl Base {
    /// How many distinct digits this base has: 2, 10 or 16.
    #[must_use]
    pub const fn radix(self) -> u8 {
        match self {
            Base::Binary => 2,
            Base::Decimal => 10,
            Base::Hexadecimal => 16,
        }
    }

    /// The prefix people write in front of a literal in this base, if there is
    /// a conventional one. Accepted on input, never emitted on output.
    #[must_use]
    pub const fn prefix(self) -> Option<&'static str> {
        match self {
            Base::Binary => Some("0b"),
            Base::Decimal => None,
            Base::Hexadecimal => Some("0x"),
        }
    }
}

name_table! {
    /// Accepts the canonical names case-insensitively, plus the short forms
    /// and the radix itself — `hex`, `16` and `hexadecimal` are all things a
    /// person types into a `--base` flag.
    ///
    /// This exists so a CLI built with `--no-default-features` can read a base
    /// from an argument without hand-writing the match that the `serde`
    /// feature would otherwise be the only source of.
    Base => UnknownBase,
    kind: "base",
    expected: "binary, decimal, or hexadecimal",
    {
        Binary      => "binary", "bin", "b", "2";
        Decimal     => "decimal", "dec", "d", "10";
        Hexadecimal => "hexadecimal", "hex", "h", "16";
    }
}

/// Why a string was not a number in the base it was read as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseNumberError {
    /// Nothing was left after trimming and removing any base prefix. A number
    /// has no empty spelling — unlike a byte string, where `""` is the empty
    /// sequence and a perfectly good value.
    Empty {
        /// The base it was being read in.
        base: Base,
    },
    /// A character that is not a digit in this base.
    ///
    /// The offset is a byte offset into the *trimmed, prefix-stripped* string,
    /// matching how [`hex::HexError`] reports one.
    InvalidDigit {
        /// Byte offset into the trimmed, prefix-stripped string.
        offset: usize,
        /// The base it was being read in.
        base: Base,
    },
    /// More digits than [`Number::MAX_DIGITS`]. Parsing is quadratic, so this
    /// is a guard against a pasted megabyte, not a statement about how large a
    /// number may be.
    TooManyDigits {
        /// Digits supplied.
        digits: usize,
        /// The limit, [`Number::MAX_DIGITS`].
        max: usize,
    },
}

impl fmt::Display for ParseNumberError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseNumberError::Empty { base } => {
                write!(f, "expected a {base} number, got nothing")
            }
            ParseNumberError::InvalidDigit { offset, base } => {
                write!(f, "not a {base} digit at byte {offset}")
            }
            ParseNumberError::TooManyDigits { digits, max } => {
                write!(f, "{digits} digits is past the {max} this parser accepts")
            }
        }
    }
}

impl std::error::Error for ParseNumberError {}

/// A byte buffer was wider than [`Number::MAX_BYTES`].
///
/// Its own type rather than a [`ParseNumberError`] variant, because nothing
/// was being parsed: the caller handed over bytes, and only the length is in
/// question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TooManyBytes {
    /// How many bytes were offered.
    pub bytes: usize,
    /// The limit, [`Number::MAX_BYTES`].
    pub max: usize,
}

impl fmt::Display for TooManyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} bytes is past the {} this type will do quadratic work on",
            self.bytes, self.max
        )
    }
}

impl std::error::Error for TooManyBytes {}

/// An unsigned integer of arbitrary width.
///
/// Held as big-endian bytes in minimal form: no leading zero byte, except that
/// zero itself is a single `0x00`. Two `Number`s are equal exactly when they
/// are the same value, so `00ff` and `ff` compare equal.
///
/// ```
/// use bitcoin_tools_core::general::{Base, Number};
///
/// // The secp256k1 group order, the number every private key must fall below.
/// let n = Number::parse(
///     "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
///     Base::Hexadecimal,
/// )?;
///
/// assert_eq!(
///     n.to_decimal(),
///     "115792089237316195423570985008687907852837564279074904382605163141518161494337"
/// );
/// assert_eq!(n.to_binary().len(), 256);
/// # Ok::<_, bitcoin_tools_core::general::ParseNumberError>(())
/// ```
//
// `Ord` is written by hand below, never derived: a derive would compare the
// byte vectors lexicographically and sort 255 (`[0xff]`) above 256
// (`[0x01, 0x00]`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Number {
    /// Big-endian, minimal form. Never empty; `[0]` is zero.
    be: Vec<u8>,
}

impl Number {
    /// Longest input [`Number::parse`] accepts, in digits.
    ///
    /// Both parsing and decimal rendering are quadratic in the digit count, so
    /// an unbounded input is a hang waiting to happen. This sits far above
    /// anything Bitcoin produces — a 256-bit value is 78 decimal digits — and
    /// exists only so a pasted file is rejected instead of chewed on.
    pub const MAX_DIGITS: usize = 4096;

    /// Widest value this type will do quadratic work on, in bytes.
    ///
    /// The same limit as [`Number::MAX_DIGITS`] seen from the byte side:
    /// hexadecimal packs the most value per digit, so `MAX_DIGITS` hex digits
    /// is the widest thing `parse` can produce, and a byte buffer is held to
    /// the same bound. For scale, the cost at this limit is milliseconds;
    /// 16 KiB is most of a second, which is why the door exists.
    pub const MAX_BYTES: usize = Self::MAX_DIGITS / 2;

    /// Read a number written in `base`.
    ///
    /// Surrounding whitespace is trimmed, and the base's own prefix (`0x`,
    /// `0b`) is accepted if present. Leading zeros are allowed and dropped —
    /// they carry no information about a value.
    ///
    /// Only the prefix belonging to `base` is removed, because the prefixes
    /// are not reserved characters in every base: `0b10` read as hexadecimal
    /// is the number 2832, and stripping `0b` there would quietly return 16
    /// instead. A prefix from another base is left in place to be judged as
    /// digits, which is how `0x10` fails in base 10.
    ///
    /// # Errors
    ///
    /// [`ParseNumberError`] if the string is empty, holds a character that is
    /// not a digit in this base, or is longer than [`Number::MAX_DIGITS`].
    ///
    /// ```
    /// use bitcoin_tools_core::general::{Base, Number};
    ///
    /// let n = Number::parse("2100000000000000", Base::Decimal)?;
    /// assert_eq!(n.to_hex(), "775f05a074000");
    ///
    /// // Same value, three spellings, one number.
    /// assert_eq!(Number::parse("fff", Base::Hexadecimal)?, Number::parse("4095", Base::Decimal)?);
    /// # Ok::<_, bitcoin_tools_core::general::ParseNumberError>(())
    /// ```
    pub fn parse(s: &str, base: Base) -> Result<Self, ParseNumberError> {
        let trimmed = s.trim();
        let digits = match base.prefix() {
            Some(p) => trimmed.strip_prefix(p).unwrap_or(trimmed),
            None => trimmed,
        };
        if digits.is_empty() {
            return Err(ParseNumberError::Empty { base });
        }
        if digits.len() > Self::MAX_DIGITS {
            return Err(ParseNumberError::TooManyDigits {
                digits: digits.len(),
                max: Self::MAX_DIGITS,
            });
        }

        // Characters to digit values, then one shared multiply-accumulate.
        let mut values = Vec::with_capacity(digits.len());
        for (offset, &c) in digits.as_bytes().iter().enumerate() {
            let Some(value) = digit_value(c, base) else {
                return Err(ParseNumberError::InvalidDigit { offset, base });
            };
            values.push(value);
        }
        Ok(Number::from_digits(&values, base.radix()))
    }

    /// Take a big-endian byte array as a number, dropping leading zeros.
    ///
    /// This is the entry point for a value that is already bytes rather than
    /// text — a 32-byte private key whose decimal form has to be shown.
    ///
    /// **Unbounded.** [`Number::MAX_DIGITS`] guards [`Number::parse`], not this,
    /// and [`Number::to_decimal`] is quadratic in the width: a 16 KiB buffer
    /// costs most of a second to render. That is fine for the fixed-size
    /// arrays this exists for, and wrong for anything whose length came from a
    /// request — use [`Number::try_from_be_bytes`] there.
    #[must_use]
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        Number::from_minimal(bytes.to_vec())
    }

    /// [`Number::from_be_bytes`] with the width checked first.
    ///
    /// The one to reach for when the length is attacker-controlled — a decoded
    /// request body, a field read off the wire — since it is the only way in
    /// that cannot be handed more bytes than this type will render in
    /// reasonable time.
    ///
    /// # Errors
    ///
    /// [`TooManyBytes`] if `bytes` is longer than [`Number::MAX_BYTES`].
    /// Leading zeros count: they are stripped after the check, so the answer
    /// does not depend on the value.
    pub fn try_from_be_bytes(bytes: &[u8]) -> Result<Self, TooManyBytes> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(TooManyBytes {
                bytes: bytes.len(),
                max: Self::MAX_BYTES,
            });
        }
        Ok(Number::from_be_bytes(bytes))
    }

    /// Read a number from its digits in `radix`, most significant first.
    ///
    /// Digit *values*, not characters: `[1, 0]` in radix 16 is 16. Any digit
    /// at or above `radix` is undefined rather than rejected — every caller
    /// inside this crate produces digits from its own alphabet and has already
    /// validated them, and returning a `Result` here would push an unreachable
    /// error path into all of them.
    ///
    /// This is the multiply-accumulate half of the crate's bignum arithmetic,
    /// shared so it exists once. [`Number::parse`] uses it for bases 2, 10 and
    /// 16; [`base58`](crate::encoding::base58) uses it for 58.
    ///
    /// **Unbounded, and quadratic in the digit count.** Every caller imposes
    /// its own cap before reaching here — `MAX_DIGITS` for `parse`, `MAX_LEN`
    /// for base58 — because the sensible limit differs per format. A new
    /// caller owes one.
    pub(crate) fn from_digits(digits: &[u8], radix: u8) -> Self {
        let radix = u16::from(radix);
        // Little-endian while accumulating, so a carry pushes onto the end
        // rather than shifting the buffer, then reversed once at the end.
        let mut le: Vec<u8> = Vec::with_capacity(digits.len());
        for &digit in digits {
            // Widest intermediate is 0xff * 0xff + 0xfe = 65279, so `u16`
            // cannot overflow for any radix a `u8` can express.
            let mut carry = u16::from(digit);
            for byte in &mut le {
                let acc = u16::from(*byte) * radix + carry;
                *byte = acc as u8;
                carry = acc >> 8;
            }
            while carry > 0 {
                le.push(carry as u8);
                carry >>= 8;
            }
        }
        le.reverse();
        Number::from_minimal(le)
    }

    /// This number's digits in `radix`, most significant first, with no
    /// leading zeros. `[0]` for zero, so the result is never empty.
    ///
    /// The repeated-division half of the shared arithmetic, and the inverse of
    /// [`Number::from_digits`]. Quadratic in the width, like everything else
    /// that walks the whole value once per digit — and unbounded, so a caller
    /// that did not get its value through a checked door owes its own cap.
    pub(crate) fn to_digits(&self, radix: u8) -> Vec<u8> {
        let radix = u16::from(radix);
        // Divide in place over one buffer, least significant digit out first.
        // `start` walks past the leading zeros each pass leaves behind, so the
        // working value shrinks and this terminates.
        let mut work = self.be.clone();
        let mut start = 0;
        let mut digits = Vec::new();
        while start < work.len() {
            let mut remainder = 0u16;
            for byte in &mut work[start..] {
                // `remainder < radix <= 255`, so this peaks at 65279.
                let acc = (remainder << 8) | u16::from(*byte);
                *byte = (acc / radix) as u8;
                remainder = acc % radix;
            }
            digits.push(remainder as u8);
            while start < work.len() && work[start] == 0 {
                start += 1;
            }
        }
        if digits.is_empty() {
            // Only reachable if `be` were empty, which the invariant forbids.
            digits.push(0);
        }
        digits.reverse();
        digits
    }

    /// Strip leading zeros, keeping one byte for zero itself.
    fn from_minimal(mut be: Vec<u8>) -> Self {
        let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
        be.drain(..start);
        if be.is_empty() {
            be.push(0);
        }
        Number { be }
    }

    /// The value as big-endian bytes, with no leading zeros. Never empty:
    /// zero is `[0]`.
    ///
    /// Borrowed, hence `as_` rather than the `to_be_bytes` of the primitive
    /// integers — that one returns an owned array, and a name that suggests a
    /// copy is being made where none is would be a trap.
    #[must_use]
    pub fn as_be_bytes(&self) -> &[u8] {
        &self.be
    }

    /// Big-endian bytes, left-padded with zeros to exactly `len`.
    ///
    /// The minimal form is right for a *value*, and wrong the moment one has
    /// to go back into a fixed-width field: a private key parsed from decimal
    /// is 32 bytes however few of them are significant. Without this every
    /// such caller writes the same padding loop.
    ///
    /// `None` if the value needs more than `len` bytes, which is a different
    /// answer from a truncated one.
    #[must_use]
    pub fn to_be_bytes_padded(&self, len: usize) -> Option<Vec<u8>> {
        // Zero is stored as `[0]`, so it needs no bytes and fits any width.
        let significant = if self.is_zero() { 0 } else { self.be.len() };
        if significant > len {
            return None;
        }
        let mut out = vec![0u8; len];
        out[len - significant..].copy_from_slice(&self.be[self.be.len() - significant..]);
        Some(out)
    }

    /// True for zero, the one value with a leading zero byte.
    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.be == [0]
    }

    /// Number of significant bits — the width of [`Number::to_binary`], and 1
    /// for zero.
    #[must_use]
    pub fn bits(&self) -> usize {
        match self.be.first() {
            // Zero, and the empty case the invariant forbids. `to_binary`
            // renders both as "0", one character wide.
            Some(&0) | None => 1,
            Some(&top) => self.be.len() * 8 - top.leading_zeros() as usize,
        }
    }

    /// Base 2, no prefix, no leading zeros.
    #[must_use]
    pub fn to_binary(&self) -> String {
        let mut out = String::with_capacity(self.be.len() * 8);
        for (i, byte) in self.be.iter().enumerate() {
            // The first byte is non-zero by the type's invariant (or the
            // number is zero, where `{:b}` gives the "0" we want), so only it
            // is written without padding.
            let _ = if i == 0 {
                write!(out, "{byte:b}")
            } else {
                write!(out, "{byte:08b}")
            };
        }
        out
    }

    /// Base 10.
    ///
    /// Quadratic in the width: each pass divides the whole value by 10 to peel
    /// off one digit. Bounded for anything built through [`Number::parse`] or
    /// [`Number::try_from_be_bytes`]; see [`Number::from_be_bytes`] for the
    /// one way in that is not.
    #[must_use]
    pub fn to_decimal(&self) -> String {
        self.to_digits(10)
            .into_iter()
            .map(|d| char::from(b'0' + d))
            .collect()
    }

    /// Base 16, lowercase, no prefix, no leading zero digit.
    #[must_use]
    pub fn to_hex(&self) -> String {
        let encoded = hex::encode(&self.be);
        // `be` is minimal, so at most one leading zero *nibble* can appear,
        // from a first byte below 0x10. Zero is `[0]` -> "00" -> "0".
        match encoded.strip_prefix('0') {
            Some(rest) if !rest.is_empty() => rest.to_string(),
            _ => encoded,
        }
    }

    /// Render in `base`, for a caller that has one as a value.
    #[must_use]
    pub fn to_base(&self, base: Base) -> String {
        match base {
            Base::Binary => self.to_binary(),
            Base::Decimal => self.to_decimal(),
            Base::Hexadecimal => self.to_hex(),
        }
    }
}

/// Decimal, the spelling a bare number is usually written in.
impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_decimal())
    }
}

/// Numeric order, which is why this is written rather than derived.
///
/// Minimal form makes it two comparisons: the canonical byte length is the
/// leading term, and equal-length big-endian bytes already compare
/// numerically. It agrees with the derived [`PartialEq`] for the same reason —
/// one value has exactly one representation.
///
/// The type exists partly for this: a private key at or above the secp256k1
/// group order has to be rejected, and that is a comparison between two
/// 256-bit numbers.
impl Ord for Number {
    fn cmp(&self, other: &Self) -> Ordering {
        self.be
            .len()
            .cmp(&other.be.len())
            .then_with(|| self.be.cmp(&other.be))
    }
}

impl PartialOrd for Number {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl From<u64> for Number {
    fn from(v: u64) -> Self {
        Number::from_be_bytes(&v.to_be_bytes())
    }
}

impl From<u128> for Number {
    fn from(v: u128) -> Self {
        Number::from_be_bytes(&v.to_be_bytes())
    }
}

/// The digit's value, or `None` if the character is not a digit in this base.
const fn digit_value(c: u8, base: Base) -> Option<u8> {
    let value = match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return None,
    };
    if value < base.radix() {
        Some(value)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every base agrees about one value, in both directions.
    fn assert_spellings(binary: &str, decimal: &str, hexadecimal: &str) {
        for (text, base) in [
            (binary, Base::Binary),
            (decimal, Base::Decimal),
            (hexadecimal, Base::Hexadecimal),
        ] {
            let n = Number::parse(text, base)
                .unwrap_or_else(|e| panic!("{text} as {base} failed to parse: {e}"));
            assert_eq!(n.to_binary(), binary, "{text} as {base} -> binary");
            assert_eq!(n.to_decimal(), decimal, "{text} as {base} -> decimal");
            assert_eq!(n.to_hex(), hexadecimal, "{text} as {base} -> hex");
        }
    }

    #[test]
    fn one_value_three_spellings() {
        assert_spellings("0", "0", "0");
        assert_spellings("1", "1", "1");
        assert_spellings("1010", "10", "a");
        assert_spellings("11111111", "255", "ff");
        assert_spellings("100000000", "256", "100");
        assert_spellings("111111111111", "4095", "fff");
    }

    /// The width this type exists for: the secp256k1 group order, the bound
    /// every private key sits below, in all three spellings.
    #[test]
    fn handles_a_256_bit_value() {
        assert_spellings(
            concat!(
                "1111111111111111111111111111111111111111111111111111111111111111",
                "1111111111111111111111111111111111111111111111111111111111111110",
                "1011101010101110110111001110011010101111010010001010000000111011",
                "1011111111010010010111101000110011010000001101100100000101000001",
            ),
            "115792089237316195423570985008687907852837564279074904382605163141518161494337",
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        );
    }

    #[test]
    fn leading_zeros_are_not_part_of_a_value() {
        assert_eq!(
            Number::parse("00ff", Base::Hexadecimal).unwrap(),
            Number::parse("ff", Base::Hexadecimal).unwrap()
        );
        assert_eq!(Number::parse("0000", Base::Decimal).unwrap().to_hex(), "0");
        assert_eq!(Number::parse("007", Base::Decimal).unwrap().to_hex(), "7");
    }

    /// The reason this does not route through `hex::decode`, which requires
    /// whole bytes.
    #[test]
    fn an_odd_number_of_hex_digits_is_a_number_not_a_broken_byte_string() {
        assert_eq!(Number::parse("fff", Base::Hexadecimal).unwrap().bits(), 12);
        assert_eq!(
            Number::parse("fff", Base::Hexadecimal)
                .unwrap()
                .to_decimal(),
            "4095"
        );
    }

    #[test]
    fn accepts_the_prefix_belonging_to_its_own_base() {
        assert_eq!(
            Number::parse(" 0xff ", Base::Hexadecimal)
                .unwrap()
                .to_decimal(),
            "255"
        );
        assert_eq!(
            Number::parse("0b1010", Base::Binary).unwrap().to_decimal(),
            "10"
        );
        // …and not another base's, which is a typo rather than a value.
        assert!(matches!(
            Number::parse("0x10", Base::Decimal),
            Err(ParseNumberError::InvalidDigit { offset: 1, .. })
        ));
    }

    /// `0b` is not a prefix in base 16 — it is two hex digits. Stripping it
    /// would silently turn 2832 into 16, so only the base's own prefix is ever
    /// removed, and only in that base.
    #[test]
    fn the_binary_prefix_is_a_valid_hex_value() {
        assert_eq!(
            Number::parse("0b10", Base::Hexadecimal).unwrap(),
            Number::parse("2832", Base::Decimal).unwrap()
        );
        assert_eq!(
            Number::parse("0b10", Base::Hexadecimal).unwrap().to_hex(),
            "b10"
        );
        // The same string in base 2 *is* prefixed, and is the number 2.
        assert_eq!(
            Number::parse("0b10", Base::Binary).unwrap().to_decimal(),
            "2"
        );
    }

    #[test]
    fn rejects_digits_that_do_not_belong_to_the_base() {
        assert!(matches!(
            Number::parse("102", Base::Binary),
            Err(ParseNumberError::InvalidDigit { offset: 2, .. })
        ));
        assert!(matches!(
            Number::parse("12a", Base::Decimal),
            Err(ParseNumberError::InvalidDigit { offset: 2, .. })
        ));
        assert!(matches!(
            Number::parse("abg", Base::Hexadecimal),
            Err(ParseNumberError::InvalidDigit { offset: 2, .. })
        ));
        // Offsets are byte offsets into the prefix-stripped string.
        assert!(matches!(
            Number::parse("0xabé", Base::Hexadecimal),
            Err(ParseNumberError::InvalidDigit { offset: 2, .. })
        ));
    }

    #[test]
    fn a_number_has_no_empty_spelling() {
        for base in [Base::Binary, Base::Decimal, Base::Hexadecimal] {
            assert_eq!(
                Number::parse("", base),
                Err(ParseNumberError::Empty { base })
            );
            assert_eq!(
                Number::parse("   ", base),
                Err(ParseNumberError::Empty { base })
            );
        }
        // A prefix and nothing else is equally not a number.
        assert_eq!(
            Number::parse("0x", Base::Hexadecimal),
            Err(ParseNumberError::Empty {
                base: Base::Hexadecimal
            })
        );
    }

    #[test]
    fn rejects_an_input_too_long_to_chew_on() {
        let huge = "1".repeat(Number::MAX_DIGITS + 1);
        assert_eq!(
            Number::parse(&huge, Base::Decimal),
            Err(ParseNumberError::TooManyDigits {
                digits: Number::MAX_DIGITS + 1,
                max: Number::MAX_DIGITS,
            })
        );
        // Exactly at the limit still parses.
        assert!(Number::parse(&"1".repeat(Number::MAX_DIGITS), Base::Binary).is_ok());
    }

    #[test]
    fn orders_by_value_not_by_bytes() {
        let n = |v: u64| Number::from(v);
        // The case a derived `Ord` gets wrong: 255 is one byte, 256 is two.
        assert!(n(255) < n(256));
        assert!(n(256) > n(255));
        assert_eq!(n(255).cmp(&n(255)), Ordering::Equal);
        // Agrees with u64 across a spread that crosses byte boundaries.
        let values = [0u64, 1, 254, 255, 256, 65_535, 65_536, u64::MAX];
        for a in values {
            for b in values {
                assert_eq!(
                    n(a).cmp(&n(b)),
                    a.cmp(&b),
                    "{a} vs {b} ordered differently from u64"
                );
            }
        }
        // Past u64: the group order against a key one below it.
        let order = Number::parse(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            Base::Hexadecimal,
        )
        .unwrap();
        let below = Number::parse(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140",
            Base::Hexadecimal,
        )
        .unwrap();
        assert!(below < order, "3.1 has to be able to make this comparison");
        assert!(Number::from(1u64) < order);
        // Ordering and equality agree, because the form is canonical.
        assert_eq!(
            Number::parse("00ff", Base::Hexadecimal).unwrap(),
            Number::from(255u64)
        );
        assert_eq!(
            Number::parse("00ff", Base::Hexadecimal)
                .unwrap()
                .cmp(&Number::from(255u64)),
            Ordering::Equal
        );
    }

    #[test]
    fn pads_back_into_a_fixed_width_field() {
        let n = Number::from(255u64);
        assert_eq!(n.to_be_bytes_padded(1), Some(vec![0xff]));
        assert_eq!(n.to_be_bytes_padded(4), Some(vec![0, 0, 0, 0xff]));
        assert_eq!(n.to_be_bytes_padded(32).map(|v| v.len()), Some(32));
        // Too narrow is None, never a truncated answer.
        assert_eq!(Number::from(256u64).to_be_bytes_padded(1), None);
        // Zero fits any width, including none at all.
        let zero = Number::from(0u64);
        assert_eq!(zero.to_be_bytes_padded(32), Some(vec![0u8; 32]));
        assert_eq!(zero.to_be_bytes_padded(0), Some(vec![]));
        // A 32-byte key parsed from decimal comes back the width it must be.
        let key = Number::parse(
            "115792089237316195423570985008687907852837564279074904382605163141518161494336",
            Base::Decimal,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&key.to_be_bytes_padded(32).unwrap()),
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
        );
    }

    #[test]
    fn a_width_from_a_request_has_a_door_to_be_stopped_at() {
        let ok = vec![0xffu8; Number::MAX_BYTES];
        assert!(Number::try_from_be_bytes(&ok).is_ok());
        let too_wide = vec![0xffu8; Number::MAX_BYTES + 1];
        assert_eq!(
            Number::try_from_be_bytes(&too_wide),
            Err(TooManyBytes {
                bytes: Number::MAX_BYTES + 1,
                max: Number::MAX_BYTES,
            })
        );
        // The check is on the buffer, not the value, so leading zeros count —
        // otherwise the answer would depend on data the caller cannot see.
        assert!(Number::try_from_be_bytes(&vec![0u8; Number::MAX_BYTES + 1]).is_err());
        // The widest thing `parse` can produce still fits the byte limit.
        let widest = Number::parse(&"f".repeat(Number::MAX_DIGITS), Base::Hexadecimal).unwrap();
        assert_eq!(widest.as_be_bytes().len(), Number::MAX_BYTES);
        assert!(Number::try_from_be_bytes(widest.as_be_bytes()).is_ok());
    }

    #[test]
    fn base_reads_back_from_the_name_it_prints() {
        for base in [Base::Binary, Base::Decimal, Base::Hexadecimal] {
            assert_eq!(base.to_string().parse(), Ok(base));
        }
        for (text, base) in [
            ("hex", Base::Hexadecimal),
            ("  HEX ", Base::Hexadecimal),
            ("16", Base::Hexadecimal),
            ("bin", Base::Binary),
            ("2", Base::Binary),
            ("dec", Base::Decimal),
            ("10", Base::Decimal),
        ] {
            assert_eq!(text.parse(), Ok(base), "{text}");
        }
        assert_eq!(
            "octal".parse::<Base>(),
            Err(UnknownBase("octal".to_owned()))
        );
        assert_eq!(
            "8".parse::<Base>().unwrap_err().input(),
            "8",
            "the error keeps what was typed"
        );
    }

    #[test]
    fn bytes_round_trip_as_values() {
        let key = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let n = Number::from_be_bytes(&key);
        // The leading zero byte is a property of the field, not the value.
        assert_eq!(n.as_be_bytes(), &key[1..]);
        assert_eq!(n.to_hex(), "112233445566778899aabbccddeeff");
        assert_eq!(Number::from_be_bytes(&[]), Number::from_be_bytes(&[0, 0]));
        assert!(Number::from_be_bytes(&[0; 32]).is_zero());
        assert_eq!(Number::from_be_bytes(&[0; 32]).to_decimal(), "0");
    }

    #[test]
    fn to_base_and_display_agree_with_the_named_renderers() {
        let n = Number::parse("48879", Base::Decimal).unwrap();
        assert_eq!(n.to_base(Base::Binary), n.to_binary());
        assert_eq!(n.to_base(Base::Decimal), n.to_decimal());
        assert_eq!(n.to_base(Base::Hexadecimal), n.to_hex());
        assert_eq!(n.to_string(), "48879");
        assert_eq!(n.to_hex(), "beef");
    }

    /// std is the oracle wherever the value is small enough to have one. This
    /// is what actually pins the hand-rolled decimal division and the parser's
    /// multiply-accumulate to being arithmetic rather than merely consistent
    /// with themselves.
    #[test]
    fn agrees_with_std_wherever_a_u64_can_check_it() {
        for v in [
            0u64,
            1,
            9,
            10,
            15,
            16,
            255,
            256,
            4095,
            65_535,
            65_536,
            1_000_000,
            2_100_000_000_000_000,
            u64::from(u32::MAX),
            u64::MAX,
            u64::MAX - 1,
        ] {
            let n = Number::from(v);
            assert_eq!(n.to_decimal(), v.to_string(), "decimal of {v}");
            assert_eq!(n.to_hex(), format!("{v:x}"), "hex of {v}");
            assert_eq!(n.to_binary(), format!("{v:b}"), "binary of {v}");
            assert_eq!(n.bits(), format!("{v:b}").len(), "bits of {v}");
            // …and each spelling parses back to the same value.
            assert_eq!(Number::parse(&v.to_string(), Base::Decimal).unwrap(), n);
            assert_eq!(
                Number::parse(&format!("{v:x}"), Base::Hexadecimal).unwrap(),
                n
            );
            assert_eq!(Number::parse(&format!("{v:b}"), Base::Binary).unwrap(), n);
            // The `From` impls are the same value by another door.
            assert_eq!(Number::from(u128::from(v)), n);
        }
    }

    /// Past `u64` there is no oracle, so require the renderings to be mutually
    /// consistent at widths and top-byte values where a carry or a dropped
    /// leading nibble would show up.
    #[test]
    fn rendering_round_trips_far_past_a_primitive_integer() {
        for len in 1..=40usize {
            for top in [0x01u8, 0x0f, 0x10, 0x80, 0xff] {
                let mut bytes = vec![top];
                bytes.extend((0..len).map(|i| (i as u8).wrapping_mul(37).wrapping_add(top)));
                let n = Number::from_be_bytes(&bytes);
                for base in [Base::Binary, Base::Decimal, Base::Hexadecimal] {
                    let text = n.to_base(base);
                    assert_eq!(
                        Number::parse(&text, base).unwrap(),
                        n,
                        "{len}-byte value starting {top:#04x} did not round trip via {base}"
                    );
                }
                // Hex is the one rendering with an independent definition —
                // the crate's own codec, minus the leading nibble.
                assert_eq!(n.to_hex(), hex::encode(&bytes).trim_start_matches('0'));
            }
        }
    }
}
