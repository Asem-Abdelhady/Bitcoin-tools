//! Bech32 and Bech32m.
//!
//! The encoding behind every address that starts `bc1`. Three parts, and this
//! module hands back all three: a human-readable prefix, a data part of
//! five-bit groups, and six characters of checksum.
//!
//! # Why there are two of them
//!
//! Bech32's checksum has a flaw found after it shipped: appending or deleting
//! a `q` immediately before the checksum leaves the checksum valid. It cannot
//! affect witness v0, whose program lengths are fixed at 20 and 32 bytes, so
//! BIP350 left v0 alone and defined **bech32m** — the same algorithm with one
//! different constant — for v1 and up. Which constant a string used is
//! recoverable from its checksum, so [`decode`] reports it rather than asking.
//!
//! An address whose witness version and variant disagree is invalid, and
//! checking that pair is [`keys::address`](crate::keys::address)' job: this
//! module knows about strings, not about witness programs.
//!
//! # It is not base32
//!
//! The alphabet is ordered so that similar-looking characters are far apart in
//! the code, which is what makes the checksum's error-detection guarantee hold
//! against the mistakes people actually make. `1`, `b`, `i` and `o` are absent
//! entirely, and `1` doubles as the separator for that reason.

use std::fmt;

use crate::bytes;
use crate::parse::name_table;

/// The five-bit alphabet. Index is the value.
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse of [`CHARSET`]: character to value, `0xff` for anything outside it.
const VALUES: [u8; 128] = {
    let mut table = [0xffu8; 128];
    let mut i = 0;
    while i < CHARSET.len() {
        table[CHARSET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Characters of checksum at the end of the data part.
pub const CHECKSUM_LEN: usize = 6;

/// Longest string this codec accepts, from BIP173.
///
/// Ninety characters is not a property of the algorithm — it is the length at
/// which bech32's error-detection guarantee is proven. Beyond it the checksum
/// still computes, but it stops being the checksum anyone analysed, so a
/// longer string is refused rather than half-checked. (Lightning invoices are
/// bech32 and are much longer; they knowingly give the guarantee up. This
/// codec exists for addresses.)
pub const MAX_LENGTH: usize = 90;

/// Longest human-readable prefix, also from BIP173.
pub const MAX_HRP_LENGTH: usize = 83;

/// The character separating the prefix from the data.
///
/// `1` is not in the alphabet, so it can appear inside a prefix without
/// ambiguity — which is why the separator is the *last* one in the string.
pub const SEPARATOR: char = '1';

/// Which of the two checksum constants a string uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    /// BIP173. Witness version 0 — P2WPKH and P2WSH.
    Bech32,
    /// BIP350. Witness versions 1 to 16 — P2TR, and whatever comes next.
    Bech32m,
}

name_table! {
    spelling Variant {
        Bech32 => "bech32";
        Bech32m => "bech32m";
    }
}

impl Variant {
    /// The constant the checksum is computed against.
    #[must_use]
    const fn constant(self) -> u32 {
        match self {
            Variant::Bech32 => 1,
            Variant::Bech32m => 0x2bc8_30a3,
        }
    }

    /// Which variant a checksum residue names, if either.
    #[must_use]
    const fn from_residue(residue: u32) -> Option<Self> {
        match residue {
            1 => Some(Variant::Bech32),
            0x2bc8_30a3 => Some(Variant::Bech32m),
            _ => None,
        }
    }

    /// The variant a witness version must be encoded with: bech32 for v0,
    /// bech32m for everything above it.
    #[must_use]
    pub const fn for_witness_version(version: u8) -> Self {
        if version == 0 {
            Variant::Bech32
        } else {
            Variant::Bech32m
        }
    }
}

/// Why a string is not valid Bech32.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bech32Error {
    /// No [`SEPARATOR`] anywhere in the string.
    MissingSeparator,
    /// The prefix is empty — the separator was the first character.
    EmptyHrp,
    /// A prefix longer than [`MAX_HRP_LENGTH`].
    HrpTooLong {
        /// Characters in the prefix.
        len: usize,
    },
    /// A prefix character outside the printable ASCII range `33..=126`.
    InvalidHrpChar {
        /// Byte offset into the string.
        offset: usize,
        /// The byte found.
        byte: u8,
    },
    /// Upper and lower case in the same string. Bech32 permits either, whole
    /// strings at a time, so that an address can be rendered as a QR code in
    /// the more compact alphanumeric mode — but never mixed, because mixing
    /// removes the case-insensitivity the checksum relies on.
    MixedCase,
    /// Longer than [`MAX_LENGTH`].
    TooLong {
        /// Characters supplied.
        len: usize,
        /// The limit, [`MAX_LENGTH`].
        max: usize,
    },
    /// A data part too short to hold a checksum, let alone a payload.
    DataTooShort {
        /// Characters after the separator.
        len: usize,
    },
    /// A data character outside the alphabet. `1`, `b`, `i` and `o` are the
    /// ones people expect to work: they are excluded on purpose.
    InvalidChar {
        /// Byte offset into the string.
        offset: usize,
    },
    /// A byte outside ASCII. Bech32 is an ASCII format, and this is checked
    /// before anything else: Unicode case folding is not the identity, so a
    /// non-ASCII character that folds *to* an alphabet character would
    /// otherwise give one value a second spelling with a valid checksum.
    NotAscii {
        /// Byte offset of the first non-ASCII byte.
        offset: usize,
    },
    /// The checksum matches neither constant, so the string is corrupt — or
    /// is bech32 of some third variant this crate does not know.
    BadChecksum,
    /// A data value of 32 or more was handed to [`encode`]. The data part is
    /// five bits per group; anything larger has no character.
    InvalidDataValue {
        /// Index into the data slice.
        index: usize,
        /// The value found, which must be below 32.
        value: u8,
    },
}

impl fmt::Display for Bech32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bech32Error::MissingSeparator => {
                write!(f, "no {SEPARATOR:?} separating the prefix from the data")
            }
            Bech32Error::EmptyHrp => f.write_str("the human-readable prefix is empty"),
            Bech32Error::HrpTooLong { len } => write!(
                f,
                "a human-readable prefix is at most {MAX_HRP_LENGTH} characters, got {len}"
            ),
            Bech32Error::InvalidHrpChar { offset, byte } => write!(
                f,
                "{byte:#04x} at byte {offset} is not printable ASCII, so it cannot be in a prefix"
            ),
            Bech32Error::MixedCase => f.write_str("mixed upper and lower case"),
            Bech32Error::TooLong { len, max } => {
                write!(f, "{len} characters is past the {max} bech32 allows")
            }
            Bech32Error::DataTooShort { len } => write!(
                f,
                "{len} characters is too short to carry a {CHECKSUM_LEN}-character checksum"
            ),
            Bech32Error::InvalidChar { offset } => {
                write!(f, "not a bech32 character at byte {offset}")
            }
            Bech32Error::NotAscii { offset } => {
                write!(f, "bech32 is ASCII, and byte {offset} is not")
            }
            Bech32Error::BadChecksum => {
                f.write_str("the checksum matches neither bech32 nor bech32m")
            }
            Bech32Error::InvalidDataValue { index, value } => {
                write!(
                    f,
                    "data value {value} at index {index} does not fit five bits"
                )
            }
        }
    }
}

impl std::error::Error for Bech32Error {}

/// A bech32 string taken apart.
///
/// The three fields are the three parts of the string, which is the split this
/// module exists to expose. `data` is *without* the checksum: the checksum is
/// its own field, because "which characters are the checksum" is a question a
/// tool should be able to answer by pointing.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Decoded {
    /// The human-readable prefix, lowercased.
    pub hrp: String,
    /// The payload, one five-bit group per element, every value below 32.
    pub data: Vec<u8>,
    /// The six checksum groups, in the same five-bit form.
    pub checksum: [u8; CHECKSUM_LEN],
    /// Which constant the checksum verified against — and therefore which of
    /// the two encodings this string is.
    pub variant: Variant,
}

impl Decoded {
    /// The checksum as it appears in the string.
    #[must_use]
    pub fn checksum_chars(&self) -> String {
        chars_for(&self.checksum)
    }
}

/// Render five-bit groups as the characters they are written with.
///
/// The alphabet is not public — its *order* is the format, and handing it out
/// as an array invites a second decoder. This is the one thing a caller
/// legitimately wants from it: a caller holding a checksum from
/// [`checksum`] and wanting to show it, without encoding a whole string and
/// slicing the end off.
///
/// Values of 32 or more are masked into range; [`encode`] is where they are
/// refused.
#[must_use]
pub fn chars_for(groups: &[u8]) -> String {
    groups
        .iter()
        .map(|&v| char::from(CHARSET[usize::from(v) & 31]))
        .collect()
}

/// BIP173's `bech32_polymod` over five-bit values.
///
/// A BCH code over GF(32). The five generator constants are what give the
/// guarantee: any four or fewer errors in a string of up to 90 characters are
/// always detected.
fn polymod(values: &[u8]) -> u32 {
    const GENERATOR: [u32; 5] = [
        0x3b6a_57b2,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ];
    let mut chk = 1u32;
    for &value in values {
        let top = chk >> 25;
        chk = (chk & 0x01ff_ffff) << 5 ^ u32::from(value);
        for (i, generator) in GENERATOR.iter().enumerate() {
            if top >> i & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

/// The prefix, spread into the checksum's input: high bits, a zero, low bits.
///
/// The prefix is covered by the checksum but is *not* five-bit data, so it is
/// folded in this way rather than encoded. That is what stops a valid address
/// for one network from also being a valid address for another.
fn expand_hrp(hrp: &str) -> Vec<u8> {
    let mut expanded = Vec::with_capacity(hrp.len() * 2 + 1);
    expanded.extend(hrp.bytes().map(|b| b >> 5));
    expanded.push(0);
    expanded.extend(hrp.bytes().map(|b| b & 0x1f));
    expanded
}

/// Check a prefix, and reject a string that is too long or mixed in case.
fn check_hrp(hrp: &str) -> Result<(), Bech32Error> {
    if hrp.is_empty() {
        return Err(Bech32Error::EmptyHrp);
    }
    if hrp.len() > MAX_HRP_LENGTH {
        return Err(Bech32Error::HrpTooLong { len: hrp.len() });
    }
    // 33..=126 is printable ASCII, so this also closes the encoding path
    // against the non-ASCII bytes `decode` refuses outright.
    for (offset, byte) in hrp.bytes().enumerate() {
        if !(33..=126).contains(&byte) {
            return Err(Bech32Error::InvalidHrpChar { offset, byte });
        }
    }
    Ok(())
}

/// Encode a prefix and five-bit data as a bech32 string.
///
/// The prefix is lowercased; the output is lowercase throughout, which is the
/// form BIP173 requires for anything being *produced*. Uppercase is legal to
/// read and exists for QR codes.
///
/// # Errors
///
/// [`Bech32Error::EmptyHrp`], [`Bech32Error::HrpTooLong`] or
/// [`Bech32Error::InvalidHrpChar`] for a prefix that cannot be encoded,
/// [`Bech32Error::InvalidDataValue`] for a group of 32 or more, or
/// [`Bech32Error::TooLong`] if the finished string would exceed
/// [`MAX_LENGTH`].
///
/// ```
/// use bitcoin_tools_core::encoding::bech32::{self, Variant};
///
/// // BIP173's own example of an empty data part.
/// assert_eq!(bech32::encode("a", &[], Variant::Bech32)?, "a12uel5l");
/// # Ok::<_, bitcoin_tools_core::encoding::bech32::Bech32Error>(())
/// ```
pub fn encode(hrp: &str, data: &[u8], variant: Variant) -> Result<String, Bech32Error> {
    let hrp = hrp.to_ascii_lowercase();
    check_hrp(&hrp)?;
    for (index, &value) in data.iter().enumerate() {
        if value >= 32 {
            return Err(Bech32Error::InvalidDataValue { index, value });
        }
    }

    let length = hrp.len() + 1 + data.len() + CHECKSUM_LEN;
    if length > MAX_LENGTH {
        return Err(Bech32Error::TooLong {
            len: length,
            max: MAX_LENGTH,
        });
    }

    let mut out = String::with_capacity(length);
    out.push_str(&hrp);
    out.push(SEPARATOR);
    for &value in data.iter().chain(checksum(&hrp, data, variant).iter()) {
        out.push(char::from(CHARSET[usize::from(value) & 31]));
    }
    Ok(out)
}

/// The six checksum groups for a prefix and data part.
///
/// Public because the checksum is one of the three parts this module promises
/// to show, and a caller building a string field by field should not have to
/// encode and re-decode to see it — the same reason
/// [`base58::checksum`](crate::encoding::base58::checksum) is public.
///
/// Values of 32 or more are masked into range rather than rejected; [`encode`]
/// is where they are refused, and this function has no error to return.
#[must_use]
pub fn checksum(hrp: &str, data: &[u8], variant: Variant) -> [u8; CHECKSUM_LEN] {
    let mut values = expand_hrp(&hrp.to_ascii_lowercase());
    values.extend(data.iter().map(|&v| v & 0x1f));
    values.extend_from_slice(&[0u8; CHECKSUM_LEN]);
    let residue = polymod(&values) ^ variant.constant();

    let mut out = [0u8; CHECKSUM_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        // Six five-bit groups, most significant first.
        let shift = 5 * (CHECKSUM_LEN - 1 - i);
        // The mask keeps this below 32, so the cast cannot lose anything.
        *slot = ((residue >> shift) & 0x1f) as u8;
    }
    out
}

/// Decode a bech32 or bech32m string into its three parts.
///
/// Surrounding whitespace is trimmed, and an all-uppercase string is accepted
/// and lowercased — mixed case is not, because it is what the checksum's
/// case-insensitivity cannot survive.
///
/// # Errors
///
/// Any [`Bech32Error`] except [`Bech32Error::InvalidDataValue`], which only
/// [`encode`] can produce.
///
/// ```
/// use bitcoin_tools_core::encoding::bech32::{self, Variant};
///
/// let decoded = bech32::decode("BC1SW50QGDZ25J")?;
/// assert_eq!(decoded.hrp, "bc");
/// assert_eq!(decoded.variant, Variant::Bech32m);
/// // Uppercase in, lowercase out — the same string either way.
/// assert_eq!(bech32::decode("bc1sw50qgdz25j")?, decoded);
/// # Ok::<_, bitcoin_tools_core::encoding::bech32::Bech32Error>(())
/// ```
pub fn decode(s: &str) -> Result<Decoded, Bech32Error> {
    let trimmed = s.trim();
    // Bech32 is defined over ASCII, and the check has to come first. Unicode
    // case folding is not the identity outside ASCII — U+212A KELVIN SIGN
    // lowercases to a plain `k` — so folding before this would let one witness
    // program have unboundedly many spellings, each with a valid checksum, and
    // none of them a string any other implementation accepts. It would also
    // make every `offset` below an offset into a string the caller never
    // supplied.
    if let Some(offset) = trimmed.bytes().position(|b| !b.is_ascii()) {
        return Err(Bech32Error::NotAscii { offset });
    }
    if trimmed.len() > MAX_LENGTH {
        return Err(Bech32Error::TooLong {
            len: trimmed.len(),
            max: MAX_LENGTH,
        });
    }
    let has_lower = trimmed.bytes().any(|b| b.is_ascii_lowercase());
    let has_upper = trimmed.bytes().any(|b| b.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err(Bech32Error::MixedCase);
    }
    let lowered = trimmed.to_ascii_lowercase();

    // The last separator, because `1` is legal inside a prefix.
    let split = lowered
        .rfind(SEPARATOR)
        .ok_or(Bech32Error::MissingSeparator)?;
    let (hrp, rest) = lowered.split_at(split);
    let payload = &rest[SEPARATOR.len_utf8()..];
    check_hrp(hrp)?;

    if payload.len() < CHECKSUM_LEN {
        return Err(Bech32Error::DataTooShort { len: payload.len() });
    }

    let mut values = Vec::with_capacity(payload.len());
    for (i, byte) in payload.bytes().enumerate() {
        let value = VALUES.get(usize::from(byte)).copied().unwrap_or(0xff);
        if value == 0xff {
            // Offsets are into the original string, so they point at the
            // character the caller can see.
            return Err(Bech32Error::InvalidChar {
                offset: split + 1 + i,
            });
        }
        values.push(value);
    }

    let mut combined = expand_hrp(hrp);
    combined.extend_from_slice(&values);
    let variant = Variant::from_residue(polymod(&combined)).ok_or(Bech32Error::BadChecksum)?;

    let (data, tail) = values.split_at(values.len() - CHECKSUM_LEN);
    let mut checksum = [0u8; CHECKSUM_LEN];
    checksum.copy_from_slice(tail);
    Ok(Decoded {
        hrp: hrp.to_owned(),
        data: data.to_vec(),
        checksum,
        variant,
    })
}

/// Regroup bytes into the five-bit groups a data part is made of, padding the
/// last group with zeros.
///
/// 8 and 5 share no factor, so this is not a reshape: a 20-byte program is 32
/// groups with four bits of padding, and a 32-byte one is 52 groups with two.
/// The loop itself is [`bytes::pack_bits`], shared
/// with BIP39's eleven-bit words — this supplies the two widths and the byte
/// types.
#[must_use]
pub fn bytes_to_groups(bytes: &[u8]) -> Vec<u8> {
    bytes::pack_bits(bytes.iter().copied().map(u16::from), 8, 5)
        .into_iter()
        // Every value is masked to five bits by `pack_bits`, so the narrowing
        // cannot lose anything.
        .map(|group| (group & 0x1f) as u8)
        .collect()
}

/// Regroup five-bit groups back into bytes, rejecting anything left over.
///
/// # Returns
///
/// `None` if a group does not fit five bits, if the leftover run is five bits
/// or longer — a whole group that produced no byte — or if the leftover bits
/// are not zero. See [`bytes::unpack_bits`], which
/// is where all three checks live.
#[must_use]
pub fn groups_to_bytes(groups: &[u8]) -> Option<Vec<u8>> {
    let widened: Vec<u16> = groups.iter().copied().map(u16::from).collect();
    Some(
        bytes::unpack_bits(&widened, 5, 8)?
            .into_iter()
            .map(|byte| (byte & 0xff) as u8)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP173's and BIP350's valid strings. Each is a boundary: an
    /// 83-character prefix, a prefix that is itself the separator character,
    /// an empty data part, a prefix of `?`.
    #[test]
    fn accepts_the_published_valid_strings() {
        for (s, variant) in [
            ("A12UEL5L", Variant::Bech32),
            ("a12uel5l", Variant::Bech32),
            (
                "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
                Variant::Bech32,
            ),
            (
                "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
                Variant::Bech32,
            ),
            (
                "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
                Variant::Bech32,
            ),
            (
                "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
                Variant::Bech32,
            ),
            ("?1ezyfcl", Variant::Bech32),
            ("A1LQFN3A", Variant::Bech32m),
            ("a1lqfn3a", Variant::Bech32m),
            (
                "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
                Variant::Bech32m,
            ),
            (
                "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
                Variant::Bech32m,
            ),
            (
                "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
                Variant::Bech32m,
            ),
            (
                "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
                Variant::Bech32m,
            ),
            ("?1v759aa", Variant::Bech32m),
        ] {
            let decoded = decode(s).unwrap_or_else(|e| panic!("{s} failed: {e}"));
            assert_eq!(decoded.variant, variant, "{s}");
            assert_eq!(
                encode(&decoded.hrp, &decoded.data, decoded.variant).unwrap(),
                s.to_lowercase(),
                "{s} did not round-trip"
            );
            // No string is valid under both constants — that is what BIP350
            // bought, and it is why `decode` can report which one it found.
            let other = match variant {
                Variant::Bech32 => Variant::Bech32m,
                Variant::Bech32m => Variant::Bech32,
            };
            assert_ne!(
                encode(&decoded.hrp, &decoded.data, other).unwrap(),
                s.to_lowercase()
            );
        }
    }

    /// The published invalid strings, each with the reason the BIP gives.
    /// This is the half that matters — a decoder that accepts everything
    /// passes the vectors above.
    ///
    /// Three of the listed vectors are prefixed with a raw `0x80` or `0xff`
    /// byte and one with `0x20`. The first two cannot be written as a `&str`
    /// at all, and the third is stripped by the same `trim` every text parser
    /// in this crate applies, so a leading space is "nothing" here rather than
    /// an out-of-range prefix character. `0x7f` covers the same branch without
    /// either problem.
    #[test]
    fn rejects_the_published_invalid_strings() {
        for (s, expected) in [
            (
                "\u{7f}1axkwrx",
                Bech32Error::InvalidHrpChar {
                    offset: 0,
                    byte: 0x7f,
                },
            ),
            (
                "\u{7f}1g6xzxy",
                Bech32Error::InvalidHrpChar {
                    offset: 0,
                    byte: 0x7f,
                },
            ),
            ("pzry9x0s0muk", Bech32Error::MissingSeparator),
            ("qyrz8wqd2c9m", Bech32Error::MissingSeparator),
            ("1pzry9x0s0muk", Bech32Error::EmptyHrp),
            ("1qyrz8wqd2c9m", Bech32Error::EmptyHrp),
            ("10a06t8", Bech32Error::EmptyHrp),
            ("1qzzfhee", Bech32Error::EmptyHrp),
            ("16plkw9", Bech32Error::EmptyHrp),
            ("1p2gdwpf", Bech32Error::EmptyHrp),
            ("x1b4n0q5v", Bech32Error::InvalidChar { offset: 2 }),
            ("y1b0jsk6g", Bech32Error::InvalidChar { offset: 2 }),
            ("lt1igcx5c0", Bech32Error::InvalidChar { offset: 3 }),
            ("mm1crxm3i", Bech32Error::InvalidChar { offset: 8 }),
            ("au1s5cgom", Bech32Error::InvalidChar { offset: 7 }),
            ("li1dgmt3", Bech32Error::DataTooShort { len: 5 }),
            ("in1muywd", Bech32Error::DataTooShort { len: 5 }),
            ("A1G7SGD8", Bech32Error::BadChecksum),
            ("M1VUXWEZ", Bech32Error::BadChecksum),
        ] {
            assert_eq!(decode(s), Err(expected), "decoding {s:?}");
        }

        // Overall max length exceeded — 91 characters, from both BIPs.
        for s in [
            "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
            "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        ] {
            assert_eq!(
                decode(s),
                Err(Bech32Error::TooLong {
                    len: 91,
                    max: MAX_LENGTH
                })
            );
        }
    }

    /// Unicode case folding is not the identity, and bech32 is ASCII.
    ///
    /// `U+212A KELVIN SIGN` lowercases to a plain `k`, and it is not
    /// `is_ascii_uppercase`, so a fold-then-check decoder accepts it, accepts
    /// its checksum, and hands back an address the caller never typed. Every
    /// non-ASCII character that folds into the alphabet is another spelling of
    /// the same witness program — which is precisely what the checksum and the
    /// mixed-case rule exist to prevent.
    #[test]
    fn a_character_that_folds_into_the_alphabet_is_not_in_the_alphabet() {
        let good = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert!(decode(good).is_ok());

        // The premise, stated rather than assumed.
        assert_eq!("\u{212a}".to_lowercase(), "k");
        let smuggled = good.replacen('k', "\u{212a}", 1);
        assert_ne!(smuggled, good);
        assert!(
            matches!(decode(&smuggled), Err(Bech32Error::NotAscii { .. })),
            "{smuggled:?} was accepted as bech32"
        );
        // The same character in the prefix, where it would otherwise pass the
        // printable-ASCII check by having been folded first.
        assert!(matches!(
            decode(&good.replacen("bc", "b\u{212a}", 1)),
            Err(Bech32Error::NotAscii { offset: 1 })
        ));
        // The offset points into the string the caller supplied, which it
        // could not if the check came after folding.
        assert_eq!(
            decode("\u{212a}1qqqqqq"),
            Err(Bech32Error::NotAscii { offset: 0 })
        );
        // …and the length limit is checked after, so it counts bytes of a
        // string that is now known to be one byte per character.
        assert!(matches!(
            decode(&"\u{e9}".repeat(50)),
            Err(Bech32Error::NotAscii { offset: 0 })
        ));
    }

    /// Mixed case is rejected because case-insensitivity is what the checksum
    /// is computed over — one lowercase character in an uppercase address is
    /// a different string to the checksum, not a cosmetic difference.
    #[test]
    fn rejects_mixed_case() {
        let good = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7";
        assert!(decode(good).is_ok());
        assert!(decode(&good.to_uppercase()).is_ok());
        assert_eq!(
            decode(&good.replace("sl5k7", "sL5k7")),
            Err(Bech32Error::MixedCase)
        );
    }

    /// A prefix longer than 83 characters cannot reach [`decode`] at all —
    /// 84 + 1 + 6 is already past [`MAX_LENGTH`], so the length check fires
    /// first. The branch is real on the encoding side, where there is no
    /// string to have been too long yet.
    #[test]
    fn a_prefix_can_only_be_too_long_on_the_way_out() {
        assert_eq!(
            encode(&"a".repeat(MAX_HRP_LENGTH + 1), &[], Variant::Bech32),
            Err(Bech32Error::HrpTooLong {
                len: MAX_HRP_LENGTH + 1
            })
        );
        assert!(encode(&"a".repeat(MAX_HRP_LENGTH), &[], Variant::Bech32).is_ok());
        assert_eq!(encode("", &[], Variant::Bech32), Err(Bech32Error::EmptyHrp));
    }

    /// Past ninety characters the error-detection guarantee no longer holds,
    /// so the string is refused rather than half-checked.
    #[test]
    fn rejects_a_string_past_the_length_the_guarantee_covers() {
        assert_eq!(
            encode("bc", &[0u8; 90], Variant::Bech32),
            Err(Bech32Error::TooLong {
                len: 99,
                max: MAX_LENGTH
            })
        );
        let over = "a".repeat(MAX_LENGTH + 1);
        assert_eq!(
            decode(&over),
            Err(Bech32Error::TooLong {
                len: MAX_LENGTH + 1,
                max: MAX_LENGTH
            })
        );
        // Exactly ninety is legal, and still round-trips.
        let at = encode("bc", &[0u8; 81], Variant::Bech32).unwrap();
        assert_eq!(at.len(), MAX_LENGTH);
        assert_eq!(decode(&at).unwrap().data, vec![0u8; 81]);
    }

    #[test]
    fn the_variant_follows_the_witness_version() {
        assert_eq!(Variant::for_witness_version(0), Variant::Bech32);
        for version in 1..=16 {
            assert_eq!(Variant::for_witness_version(version), Variant::Bech32m);
        }
        assert_eq!(Variant::Bech32.to_string(), "bech32");
        assert_eq!(Variant::Bech32m.to_string(), "bech32m");
    }

    /// Every single-character substitution has to be caught. That guarantee is
    /// the whole reason for the alphabet's odd ordering, and it is cheap to
    /// check exhaustively over one address.
    #[test]
    fn every_single_character_substitution_is_detected() {
        let good = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let chars: Vec<char> = good.chars().collect();
        let mut checked = 0;

        for position in 3..chars.len() {
            for &replacement in CHARSET {
                let replacement = char::from(replacement);
                if chars[position] == replacement {
                    continue;
                }
                let mut candidate = chars.clone();
                candidate[position] = replacement;
                let candidate: String = candidate.into_iter().collect();
                assert_eq!(
                    decode(&candidate),
                    Err(Bech32Error::BadChecksum),
                    "a one-character change at {position} went undetected"
                );
                checked += 1;
            }
        }
        assert!(checked > 1000, "only {checked} substitutions were tried");
    }

    #[test]
    fn the_checksum_is_the_last_six_characters() {
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let decoded = decode(address).unwrap();
        assert_eq!(decoded.checksum.len(), CHECKSUM_LEN);
        assert_eq!(
            decoded.checksum_chars(),
            address[address.len() - CHECKSUM_LEN..]
        );
        // The standalone function agrees with what the string carried…
        assert_eq!(
            checksum(&decoded.hrp, &decoded.data, decoded.variant),
            decoded.checksum
        );
        // …and `data` excludes it, so re-encoding has to put it back.
        assert_eq!(
            decoded.data.len(),
            address.len() - "bc1".len() - CHECKSUM_LEN
        );
        assert_eq!(
            encode(&decoded.hrp, &decoded.data, decoded.variant).unwrap(),
            address
        );
    }

    #[test]
    fn rejects_data_that_does_not_fit_five_bits() {
        assert_eq!(
            encode("bc", &[0, 31, 32], Variant::Bech32),
            Err(Bech32Error::InvalidDataValue {
                index: 2,
                value: 32
            })
        );
        assert!(encode("bc", &[0, 31], Variant::Bech32).is_ok());
    }

    /// 8 and 5 share no factor, so the regrouping has a remainder at almost
    /// every length — and the remainder is where the bugs are.
    #[test]
    fn regroups_bytes_into_five_bit_groups_and_back() {
        for len in 0..=64usize {
            let bytes: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i).unwrap_or(0).wrapping_mul(37))
                .collect();
            let groups = bytes_to_groups(&bytes);
            assert!(groups.iter().all(|&g| g < 32));
            assert_eq!(groups.len(), (len * 8).div_ceil(5), "{len} bytes");
            assert_eq!(
                groups_to_bytes(&groups).as_deref(),
                Some(&bytes[..]),
                "{len} bytes did not survive the round trip"
            );
        }
    }

    /// Padding bits that are not zero mean the string carries information no
    /// byte accounts for, which BIP173 requires be rejected — it is how one
    /// witness program would otherwise have several spellings.
    #[test]
    fn refuses_to_drop_non_zero_padding() {
        // Five leftover bits are a whole group that produced nothing, so the
        // string carried a character the bytes do not account for — rejected
        // whether or not those bits happen to be zero.
        assert_eq!(groups_to_bytes(&[1]), None);
        assert_eq!(groups_to_bytes(&[0]), None);
        // Ten bits is one byte and two bits of padding. Zero padding is what
        // the encoder wrote…
        assert_eq!(groups_to_bytes(&[0, 0]), Some(vec![0]));
        assert_eq!(groups_to_bytes(&[1, 0]), Some(vec![8]));
        // …and non-zero padding is the case BIP173 names.
        assert_eq!(groups_to_bytes(&[0, 1]), None);
        // A group that does not fit five bits is not a group.
        assert_eq!(groups_to_bytes(&[32]), None);
        // Nothing in, nothing out — and no leftover to complain about.
        assert_eq!(groups_to_bytes(&[]), Some(vec![]));
    }
}
