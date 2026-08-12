//! The `bits` field: a 256-bit threshold squeezed into four bytes.
//!
//! A header's `bits` is not a difficulty and not a number anyone reads. It is
//! a floating-point encoding of the *target* — the value the block hash has to
//! come in under — with an eight-bit exponent and a 23-bit mantissa. Handing a
//! caller the raw `u32` is the mistake this module exists to prevent: it looks
//! like an integer, compares like an integer, and is neither.
//!
//! Three renderings of the same four bytes, from block 100,000:
//!
//! | | Value | What it is |
//! |---|---|---|
//! | [`CompactTarget`] | `1b04864c` | the encoding, as the header carries it |
//! | [`Target`] | `000000000004864c0000…` | the threshold the hash must come under |
//! | [`CompactTarget::difficulty`] | `14484.16` | that threshold against the easiest one |

use std::fmt;
use std::str::FromStr;

use crate::hashes::Hash;
use crate::hex::{self, HexError};

/// The exponent that leaves the mantissa where difficulty 1 puts it. Above it
/// the target grows by a byte each step, below it shrinks.
const DIFFICULTY_ONE_EXPONENT: i32 = 29;

/// The mantissa of difficulty 1, and so the numerator every difficulty is a
/// fraction of.
const DIFFICULTY_ONE_MANTISSA: u32 = 0x0000_ffff;

/// The mantissa: the low 23 bits.
const MANTISSA_MASK: u32 = 0x007f_ffff;

/// The 24th bit. A target is a threshold and has no sign, so this can only
/// mean a malformed encoding — but four arbitrary bytes can set it, and four
/// arbitrary bytes are what a decoder is handed.
const SIGN_BIT: u32 = 0x0080_0000;

/// A proof-of-work threshold, as a block header encodes it.
///
/// Four bytes: one of exponent and three of mantissa, meaning
/// `mantissa · 256^(exponent-3)`. The encodable targets are therefore coarse —
/// this is a float, and retargeting rounds into it.
///
/// [`fmt::Display`] and [`FromStr`] use the eight-hex-digit spelling
/// (`1d00ffff`) that Bitcoin Core's `getblockheader` prints. That is the
/// *value* in hex, not the header's bytes: the header stores the same `u32`
/// little-endian, so the same field reads `ffff001d` in
/// [`HeaderBreakdown::bits`](crate::blocks::HeaderBreakdown::bits).
///
/// ```
/// use bitcoin_tools_core::blocks::CompactTarget;
///
/// let bits: CompactTarget = "1d00ffff".parse()?;
/// assert_eq!(bits.to_consensus(), 486_604_799);
/// assert_eq!(bits.difficulty(), 1.0, "the genesis block's target");
/// assert_eq!(
///     bits.target()?.to_hex(),
///     "00000000ffff0000000000000000000000000000000000000000000000000000",
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
///
/// # Not ordered
///
/// Deliberately no `Ord`, because the only ordering this type could derive is
/// the wrong one. Comparing the raw `u32` agrees with comparing the thresholds
/// for the canonical encodings a miner produces, and stops agreeing for the
/// ones a decoder is handed: `1c7fffff` sorts below `1d000100` as a number
/// while encoding a target about eight million times larger. A type named for
/// a threshold that compares as something else is a trap, so thresholds are
/// compared where they are thresholds — [`Target`] derives the ordering that
/// *is* numeric.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// The easiest target Bitcoin has used, and the one difficulty is measured
    /// against: the genesis block's `bits`, and mainnet's limit ever since.
    pub const DIFFICULTY_ONE: Self = CompactTarget(0x1d00_ffff);

    /// Wrap the `u32` a header carries.
    #[must_use]
    pub const fn from_consensus(bits: u32) -> Self {
        CompactTarget(bits)
    }

    /// The `u32` a header carries.
    #[must_use]
    pub const fn to_consensus(self) -> u32 {
        self.0
    }

    /// The top byte: where the mantissa sits, counted in bytes from the bottom
    /// of the 256-bit value.
    #[must_use]
    pub const fn exponent(self) -> u8 {
        (self.0 >> 24) as u8
    }

    /// The low 23 bits. The 24th is the sign flag, not part of the number —
    /// see [`CompactTarget::is_negative`].
    ///
    /// Note [`CompactTarget::difficulty`] does **not** use this: it divides by
    /// all twenty-four bits, sign included, because Core's `GetDifficulty`
    /// does. The two readings differ only for an encoding that has no target
    /// at all, and matching Core is worth more there than internal tidiness.
    #[must_use]
    pub const fn mantissa(self) -> u32 {
        self.0 & MANTISSA_MASK
    }

    /// True if the sign bit is set on a non-zero mantissa, which no real
    /// target has.
    ///
    /// The mantissa has to be non-zero for this to mean anything, which is
    /// Core's rule too: every exponent with a zero mantissa encodes the same
    /// zero, sign bit or not.
    #[must_use]
    pub const fn is_negative(self) -> bool {
        self.0 & SIGN_BIT != 0 && self.mantissa() != 0
    }

    /// Expand to the 256-bit threshold.
    ///
    /// # Errors
    ///
    /// [`CompactTargetError::Negative`] if the sign bit is set on a non-zero
    /// mantissa, or [`CompactTargetError::Overflow`] if the mantissa is
    /// shifted past the top of 256 bits. Both are encodings Core's
    /// `SetCompact` flags and `CheckProofOfWork` rejects, and both are
    /// reachable from four arbitrary bytes.
    ///
    /// A zero mantissa is *not* an error. It expands to [`Target::ZERO`], a
    /// well-formed encoding of a threshold no hash can come under.
    pub fn target(self) -> Result<Target, CompactTargetError> {
        let mantissa = self.mantissa();
        let exponent = usize::from(self.exponent());
        if mantissa == 0 {
            return Ok(Target::ZERO);
        }
        if self.is_negative() {
            return Err(CompactTargetError::Negative { bits: self.0 });
        }
        // Core's three overflow cases are one rule counted byte by byte: the
        // mantissa's *significant* bytes have to land inside the 32. A
        // mantissa of 0xff needs one byte, so it survives one exponent higher
        // than a mantissa of 0xffff, which survives one higher again.
        if exponent > 34
            || (mantissa > 0xff && exponent > 33)
            || (mantissa > 0xffff && exponent > 32)
        {
            return Err(CompactTargetError::Overflow { bits: self.0 });
        }

        let mut bytes = [0u8; Target::SIZE];
        if exponent <= 3 {
            // A shift *right*: the mantissa is wider than the value, and the
            // bottom bytes fall off. Core does the same, silently.
            let value = mantissa >> (8 * (3 - exponent));
            bytes[Target::SIZE - 4..].copy_from_slice(&value.to_be_bytes());
        } else {
            // The mantissa's three bytes end `exponent` bytes above the bottom
            // of the value, so the last of them lands at `SIZE - exponent + 2`.
            // A *leading* byte can notionally land above the top, and that is
            // precisely the case the overflow rule above allowed — because it
            // is zero, and carries nothing.
            for (i, byte) in mantissa.to_be_bytes()[1..].iter().enumerate() {
                if let Some(index) = (Target::SIZE + i).checked_sub(exponent) {
                    bytes[index] = *byte;
                }
            }
        }
        Ok(Target(bytes))
    }

    /// How much harder this target is than [`CompactTarget::DIFFICULTY_ONE`].
    ///
    /// The ratio of the two thresholds, which is Bitcoin Core's
    /// `GetDifficulty` — computed on the compact form directly, so it needs no
    /// 256-bit division and matches what every explorer prints.
    ///
    /// Two degenerate inputs, both matching Core: a zero mantissa gives
    /// [`f64::INFINITY`], and an encoding with the sign bit set gives a number
    /// that means nothing, since a negative target has no difficulty. Ask
    /// [`CompactTarget::target`] if you need to know which.
    #[must_use]
    pub fn difficulty(self) -> f64 {
        // The sign bit is deliberately *not* masked off here: Core's
        // `GetDifficulty` divides by the low 24 bits as they stand. For every
        // real header the bit is clear and the two readings are the same
        // number.
        let mantissa = self.0 & (MANTISSA_MASK | SIGN_BIT);
        let mut shift = i32::from(self.exponent());
        let mut difficulty = f64::from(DIFFICULTY_ONE_MANTISSA) / f64::from(mantissa);
        while shift < DIFFICULTY_ONE_EXPONENT {
            difficulty *= 256.0;
            shift += 1;
        }
        while shift > DIFFICULTY_ONE_EXPONENT {
            difficulty /= 256.0;
            shift -= 1;
        }
        difficulty
    }
}

impl fmt::Display for CompactTarget {
    /// The eight hex digits `getblockheader` prints — the value, not the
    /// header's little-endian bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl FromStr for CompactTarget {
    type Err = ParseCompactTargetError;

    /// Exactly eight hex digits, `0x` and surrounding whitespace allowed.
    ///
    /// Exactly eight, not "up to eight": `bits` is a fixed four-byte field, so
    /// a short string is a truncated one. Zero-extending `1d00ff` would turn a
    /// bad paste into exponent 0 — a target of zero and a difficulty of
    /// infinity — with nothing to notice, which is the same reason
    /// [`Hash::from_hex`](crate::hashes::Hash::from_hex) refuses a short
    /// digest instead of padding it.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(hex::normalize(s))?;
        <[u8; 4]>::try_from(&bytes[..])
            .map(|bytes| CompactTarget(u32::from_be_bytes(bytes)))
            .map_err(|_| ParseCompactTargetError::WrongLength { got: bytes.len() })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CompactTarget {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Why a string was not a compact target.
///
/// The same two shapes as [`HashParseError`](crate::hashes::HashParseError),
/// for the same reason: a fixed-width field read from text can fail at the
/// codec or at the width, and a caller fixing the input needs to know which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseCompactTargetError {
    /// Not hex, or an odd number of digits.
    Hex(HexError),
    /// Hex, but not four bytes.
    WrongLength {
        /// Bytes decoded, where four were required.
        got: usize,
    },
}

impl fmt::Display for ParseCompactTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseCompactTargetError::Hex(e) => write!(f, "{e}"),
            ParseCompactTargetError::WrongLength { got } => write!(
                f,
                "expected eight hex digits, e.g. 1d00ffff, got {got} bytes"
            ),
        }
    }
}

impl std::error::Error for ParseCompactTargetError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParseCompactTargetError::Hex(e) => Some(e),
            ParseCompactTargetError::WrongLength { .. } => None,
        }
    }
}

impl From<HexError> for ParseCompactTargetError {
    fn from(e: HexError) -> Self {
        ParseCompactTargetError::Hex(e)
    }
}

/// Why four bytes did not encode a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompactTargetError {
    /// The sign bit was set on a non-zero mantissa. A target is a threshold,
    /// so there is no negative one to hand back.
    Negative {
        /// The encoding, as the header carried it.
        bits: u32,
    },
    /// The mantissa is shifted past the top of 256 bits, so the target it
    /// names cannot be represented.
    Overflow {
        /// The encoding, as the header carried it.
        bits: u32,
    },
}

impl fmt::Display for CompactTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CompactTargetError::Negative { bits } => {
                write!(f, "compact target {bits:08x} has the sign bit set")
            }
            CompactTargetError::Overflow { bits } => {
                write!(f, "compact target {bits:08x} does not fit in 256 bits")
            }
        }
    }
}

impl std::error::Error for CompactTargetError {}

/// The 256-bit threshold a block hash has to come in under, big-endian.
///
/// Big-endian is not a rendering choice, it is what makes the type usable:
/// comparing thirty-two big-endian bytes lexicographically *is* comparing the
/// numbers, so the derived [`Ord`] is the numeric one and [`Target::is_met_by`]
/// is a byte comparison. Stored the other way round the derive would be
/// silently wrong.
///
/// This is the opposite of every hash in this crate, which stores wire order —
/// a target has no wire order of its own, because headers carry the compact
/// form and never the expanded one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Target([u8; Target::SIZE]);

impl Target {
    /// Width in bytes.
    pub const SIZE: usize = 32;

    /// A threshold no hash can come under.
    pub const ZERO: Self = Target([0; Target::SIZE]);

    /// Take a threshold that is already big-endian.
    #[must_use]
    pub const fn from_be_bytes(bytes: [u8; Target::SIZE]) -> Self {
        Target(bytes)
    }

    /// The threshold, big-endian.
    #[must_use]
    pub const fn to_be_bytes(self) -> [u8; Target::SIZE] {
        self.0
    }

    /// Sixty-four hex digits, most significant first — with the leading zeros
    /// that make a target recognisable.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Whether a hash comes in at or under this threshold, which is what "the
    /// proof of work is valid" means.
    ///
    /// Reads the digest the way the consensus rule does — little-endian, so
    /// the leading zeros a block hash is famous for are the *trailing* zero
    /// bytes of the serialization. Getting that backwards compares an enormous
    /// number against the threshold and rejects every real block, which is why
    /// this takes [`Hash<32>`](crate::hashes::Hash), the crate's one type that
    /// is documented to hold wire order, rather than a bare `[u8; 32]` that a
    /// displayed string decodes into just as readily. A caller holding the
    /// explorer form comes through
    /// [`Hash::from_hex_reversed`](crate::hashes::Hash::from_hex_reversed).
    ///
    /// It does not take a [`BlockHash`](crate::blocks::BlockHash), which would
    /// be the tighter type, because that lives one file up and would make the
    /// two modules import each other.
    ///
    /// ```
    /// use bitcoin_tools_core::blocks::{BlockHash, CompactTarget};
    ///
    /// let genesis: BlockHash =
    ///     "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".parse()?;
    /// let target = CompactTarget::DIFFICULTY_ONE.target()?;
    ///
    /// assert!(target.is_met_by(&genesis.to_hash()));
    /// # Ok::<_, Box<dyn std::error::Error>>(())
    /// ```
    #[must_use]
    pub fn is_met_by(&self, hash: &Hash<32>) -> bool {
        let mut big_endian = *hash.as_bytes();
        big_endian.reverse();
        big_endian <= self.0
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Target {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sixty-four hex digits ending in `tail`, which is how a target is
    /// written and the only readable way to state one in a test.
    fn target_hex(tail: &str) -> String {
        format!("{tail:0>64}")
    }

    fn expand(bits: u32) -> Result<Target, CompactTargetError> {
        CompactTarget::from_consensus(bits).target()
    }

    /// Bitcoin Core's `arith_uint256` compact-encoding cases. They are where
    /// the exponent-below-3, sign-bit and overflow corners come from —
    /// corners no real header reaches, and so ones an implementation that only
    /// ever saw real headers would get wrong undetected.
    #[test]
    fn core_compact_encoding_cases() {
        // A zero mantissa is zero at every exponent, sign bit or not.
        for bits in [
            0x0000_0000,
            0x0012_3456,
            0x0100_3456,
            0x0200_0056,
            0x0300_0000,
            0x0080_0000,
        ] {
            assert_eq!(expand(bits), Ok(Target::ZERO), "{bits:08x}");
        }

        // Exponents at or below 3 shift the mantissa down, not up.
        assert_eq!(
            expand(0x0112_3456).map(|t| t.to_hex()),
            Ok(target_hex("12"))
        );
        assert_eq!(
            expand(0x0212_3456).map(|t| t.to_hex()),
            Ok(target_hex("1234"))
        );
        assert_eq!(
            expand(0x0312_3456).map(|t| t.to_hex()),
            Ok(target_hex("123456"))
        );
        assert_eq!(
            expand(0x0412_3456).map(|t| t.to_hex()),
            Ok(target_hex("12345600"))
        );
        assert_eq!(
            expand(0x0500_9234).map(|t| t.to_hex()),
            Ok(target_hex("92340000"))
        );

        // The largest exponent a three-byte mantissa fits at, and one past it.
        assert_eq!(
            expand(0x2012_3456).map(|t| t.to_hex()),
            Ok("1234560000000000000000000000000000000000000000000000000000000000".to_string())
        );
        assert_eq!(
            expand(0x2112_3456),
            Err(CompactTargetError::Overflow { bits: 0x2112_3456 })
        );
        assert_eq!(
            expand(0xff12_3456),
            Err(CompactTargetError::Overflow { bits: 0xff12_3456 })
        );

        // A narrower mantissa survives higher, because the bytes that would
        // land above the top are the zero ones.
        assert_eq!(
            expand(0x2100_3456).map(|t| t.to_hex()),
            Ok("3456000000000000000000000000000000000000000000000000000000000000".to_string())
        );
        assert_eq!(
            expand(0x2200_0056).map(|t| t.to_hex()),
            Ok("5600000000000000000000000000000000000000000000000000000000000000".to_string())
        );

        // The sign bit, at three different exponents.
        for bits in [0x0092_3456u32, 0x0180_3456, 0x0492_3456] {
            assert_eq!(
                expand(bits),
                Err(CompactTargetError::Negative { bits }),
                "{bits:08x}"
            );
            assert!(CompactTarget::from_consensus(bits).is_negative());
        }
    }

    #[test]
    fn difficulty_one_is_the_genesis_target() {
        let bits = CompactTarget::DIFFICULTY_ONE;
        assert_eq!(bits.to_consensus(), 486_604_799);
        assert_eq!(bits.exponent(), 0x1d);
        assert_eq!(bits.mantissa(), 0x0000_ffff);
        assert!(!bits.is_negative());
        assert_eq!(bits.difficulty(), 1.0);
        assert_eq!(
            bits.target().map(|t| t.to_hex()),
            Ok(target_hex(
                "ffff0000000000000000000000000000000000000000000000000000"
            ))
        );
    }

    #[test]
    fn halving_the_target_doubles_the_difficulty() {
        let easy = CompactTarget::DIFFICULTY_ONE;
        let hard = CompactTarget::from_consensus(0x1c7f_ff80); // the same target, halved
        assert!((hard.difficulty() / easy.difficulty() - 2.0).abs() < 1e-9);
        assert!(
            hard.target().expect("expands") < easy.target().expect("expands"),
            "a harder target is a smaller number, and Ord has to agree"
        );
        assert_eq!(
            CompactTarget::from_consensus(0x1d00_0000).difficulty(),
            f64::INFINITY,
            "a zero target is unreachable, and Core says so with an infinity"
        );
    }

    #[test]
    fn a_hash_is_compared_little_endian() {
        let target = CompactTarget::DIFFICULTY_ONE
            .target()
            .expect("difficulty 1 expands");

        // The genesis hash in wire order: the zeros an explorer shows at the
        // front are the last four bytes of the serialization.
        const GENESIS: &str = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        let genesis = Hash::<32>::from_hex_reversed(GENESIS).expect("thirty-two bytes");
        assert_eq!(genesis.as_bytes()[28..], [0, 0, 0, 0]);
        assert!(target.is_met_by(&genesis));

        // Reading the same string forwards — the mistake `Hash` has two named
        // parsers to prevent — reads 0x6fe28c0a… as the top of the number,
        // which is nowhere near under the threshold.
        let displayed = Hash::<32>::from_hex(GENESIS).expect("thirty-two bytes");
        assert!(
            !target.is_met_by(&displayed),
            "byte order is the whole check"
        );

        // A hash exactly equal to the target meets it; anything is above zero.
        let mut exactly = target.to_be_bytes();
        exactly.reverse();
        assert!(target.is_met_by(&Hash::from_bytes(exactly)));
        assert!(!Target::ZERO.is_met_by(&genesis));
    }

    #[test]
    fn the_hex_spelling_round_trips() {
        for s in ["1d00ffff", "1b04864c", "170f48e4", "00000000"] {
            let bits: CompactTarget = s.parse().expect("eight hex digits");
            assert_eq!(bits.to_string(), s);
        }
        assert_eq!("0x1d00ffff".parse(), Ok(CompactTarget::DIFFICULTY_ONE));
        assert_eq!("  1D00FFFF\n".parse(), Ok(CompactTarget::DIFFICULTY_ONE));
    }

    /// `bits` is four bytes wide, so a short string is a truncated one — and
    /// zero-extending it produces a target of zero and a difficulty of
    /// infinity, which is the kind of answer that looks like data.
    #[test]
    fn a_short_spelling_is_refused_rather_than_padded() {
        assert_eq!(
            "1d00ff".parse::<CompactTarget>(),
            Err(ParseCompactTargetError::WrongLength { got: 3 })
        );
        assert_eq!(
            "".parse::<CompactTarget>(),
            Err(ParseCompactTargetError::WrongLength { got: 0 })
        );
        assert_eq!(
            "1d00ffffaa".parse::<CompactTarget>(),
            Err(ParseCompactTargetError::WrongLength { got: 5 })
        );
        // …and the codec's own failures stay the codec's, with the offset.
        assert!(matches!(
            "1d00fff".parse::<CompactTarget>(),
            Err(ParseCompactTargetError::Hex(_)),
        ));
        assert!(matches!(
            "zzzzzzzz".parse::<CompactTarget>(),
            Err(ParseCompactTargetError::Hex(_)),
        ));
    }

    /// The one comparison this type deliberately does not offer. `Ord` on the
    /// encoding would look like `Ord` on the threshold and disagree with it,
    /// so thresholds are compared as [`Target`]s — where the bytes are
    /// big-endian and the derive is the numeric one.
    #[test]
    fn a_bigger_encoding_is_not_a_bigger_target() {
        let (low, high) = (
            CompactTarget::from_consensus(0x1c7f_ffff),
            CompactTarget::from_consensus(0x1d00_0100),
        );
        assert!(low.to_consensus() < high.to_consensus());
        assert!(
            low.target().expect("expands") > high.target().expect("expands"),
            "the smaller encoding is the larger threshold, which is why \
             CompactTarget has no Ord"
        );
    }
}
