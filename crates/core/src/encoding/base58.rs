//! Base58 and Base58Check.
//!
//! Base58 is base 58 — the arithmetic is [`Number`]'s, shared with the number
//! converter rather than written again here. What is specific to Base58 is the
//! alphabet (no `0`, `O`, `I` or `l`, so a written address survives being read
//! aloud) and one rule that is *not* arithmetic: a leading zero **byte** is not
//! a leading zero **digit**. Zero bytes carry no value, so a numeric
//! conversion drops them; Bitcoin needs them back, because the version byte of
//! a mainnet address is `0x00` and losing it would shorten every address that
//! starts with a `1`. They are counted off the front and re-emitted as `1`s.
//!
//! Base58Check adds four bytes of checksum — the first four of
//! [`hash256`] over the payload — which is what makes
//! a mistyped address get rejected instead of sending money nowhere.

use crate::general::Number;
use crate::hashes::hash256;

/// The Bitcoin alphabet. Index is the digit value.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse of [`ALPHABET`]: character to digit value, `0xff` for anything
/// outside it. Built once at compile time so decoding indexes rather than
/// scanning fifty-eight entries per character.
const DIGITS: [u8; 128] = {
    let mut table = [0xffu8; 128];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Bytes of checksum appended by [`encode_check`].
pub const CHECKSUM_LEN: usize = 4;

/// Longest Base58 string [`decode`] will accept.
///
/// Decoding is quadratic in the length, because base conversion is. Every real
/// Base58 string in Bitcoin is far shorter than this — an address is 34
/// characters, a WIF key 52, a BIP32 extended key 111 — so this is not a limit
/// on anything legitimate. It exists so that a pasted file is rejected instead
/// of chewed on: at 50 000 characters decoding takes about a second, and it
/// gets worse from there.
pub const MAX_LEN: usize = 256;

/// Why a Base58 string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Base58Error {
    /// A character outside the alphabet. The offset is a byte offset into the
    /// trimmed string, as everywhere else in this crate.
    ///
    /// `0`, `O`, `I` and `l` are the interesting cases: they are excluded on
    /// purpose because they are easy to confuse with `O`, `0`, `l` and `I`.
    InvalidChar {
        /// Byte offset into the trimmed string.
        offset: usize,
    },
    /// Longer than [`MAX_LEN`]. Decoding is quadratic, so this is a guard
    /// against a pasted file, not a statement about how long a Base58 string
    /// may be.
    TooLong {
        /// Characters supplied.
        len: usize,
        /// The limit, [`MAX_LEN`].
        max: usize,
    },
    /// Decoded to fewer than [`CHECKSUM_LEN`] bytes, so there is no room for a
    /// checksum, let alone a payload.
    TooShort {
        /// Bytes decoded, fewer than a checksum needs.
        len: usize,
    },
    /// The four trailing bytes are not what the payload hashes to. Both are
    /// reported: a decoder should be able to show what it expected.
    BadChecksum {
        /// The four bytes the string carried.
        found: [u8; CHECKSUM_LEN],
        /// The four bytes its payload hashes to.
        expected: [u8; CHECKSUM_LEN],
    },
}

impl std::fmt::Display for Base58Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Base58Error::InvalidChar { offset } => {
                write!(f, "not a base58 character at byte {offset}")
            }
            Base58Error::TooLong { len, max } => {
                write!(f, "{len} characters is past the {max} this decoder accepts")
            }
            Base58Error::TooShort { len } => write!(
                f,
                "{len} bytes is too short to carry a {CHECKSUM_LEN}-byte checksum"
            ),
            Base58Error::BadChecksum { found, expected } => write!(
                f,
                "checksum is {} but the payload hashes to {}",
                crate::hex::encode(found),
                crate::hex::encode(expected)
            ),
        }
    }
}

impl std::error::Error for Base58Error {}

/// Encode as Base58, with no checksum.
///
/// **Unbounded, and quadratic in the length.** There is no cap here because
/// the caller already holds the bytes and knows how many there are, exactly as
/// [`Number::from_be_bytes`] is unbounded while [`decode`] is not. Be aware of
/// the shape of the cost before feeding it something large: 200 KiB takes
/// about a minute and a half.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|&&b| b == 0).count();
    let mut out = String::with_capacity(bytes.len() * 2);
    // Each leading zero byte is one `1`, outside the numeric conversion.
    for _ in 0..zeros {
        out.push('1');
    }
    let rest = &bytes[zeros..];
    if !rest.is_empty() {
        for digit in Number::from_be_bytes(rest).to_digits(58) {
            out.push(char::from(ALPHABET[digit as usize]));
        }
    }
    out
}

/// Decode Base58, with no checksum to verify.
///
/// Surrounding whitespace is trimmed. Length is capped at [`MAX_LEN`] — this
/// is the door on the quadratic work, and every parser in this crate that
/// takes Base58 text goes through here.
///
/// # Errors
///
/// [`Base58Error::InvalidChar`] for anything outside the alphabet, or
/// [`Base58Error::TooLong`] past [`MAX_LEN`].
pub fn decode(s: &str) -> Result<Vec<u8>, Base58Error> {
    let trimmed = s.trim();
    // Checked before any work, on the trimmed string, so the answer does not
    // depend on how much whitespace came with it.
    if trimmed.len() > MAX_LEN {
        return Err(Base58Error::TooLong {
            len: trimmed.len(),
            max: MAX_LEN,
        });
    }
    let zeros = trimmed.bytes().take_while(|&b| b == b'1').count();
    let rest = &trimmed.as_bytes()[zeros..];

    let mut digits = Vec::with_capacity(rest.len());
    for (i, &c) in rest.iter().enumerate() {
        // Non-ASCII bytes are past the end of the table, and are not base58.
        let value = DIGITS.get(usize::from(c)).copied().unwrap_or(0xff);
        if value == 0xff {
            return Err(Base58Error::InvalidChar { offset: zeros + i });
        }
        digits.push(value);
    }

    let mut out = vec![0u8; zeros];
    if !digits.is_empty() {
        // `rest` cannot start with `1`, so the value is non-zero and its
        // minimal form has no leading zero byte to confuse with the count
        // above.
        out.extend_from_slice(Number::from_digits(&digits, 58).as_be_bytes());
    }
    Ok(out)
}

/// The four checksum bytes for `payload`: the first four of
/// [`hash256`] over it.
///
/// Public because callers that build a Base58Check payload themselves — an
/// address showing its parts, a WIF key — need the checksum without going
/// through a full encode-then-decode round trip to get it back.
#[must_use]
pub fn checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let digest = hash256(payload);
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&digest[..CHECKSUM_LEN]);
    out
}

/// Encode as Base58Check: `payload` followed by four bytes of checksum.
///
/// ```
/// use bitcoin_tools_core::encoding::base58;
/// use bitcoin_tools_core::hex;
///
/// // A version byte and a public key hash make a P2PKH address.
/// let payload = hex::decode("00010966776006953d5567439e5e39f86a0d273bee")?;
/// assert_eq!(base58::encode_check(&payload), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
/// # Ok::<_, bitcoin_tools_core::hex::HexError>(())
/// ```
///
/// The payload is whatever the format prepends its version byte to — this
/// function does not know or care which format that is, which is why one
/// implementation serves WIF keys, P2PKH and P2SH addresses, and BIP32
/// extended keys alike.
#[must_use]
pub fn encode_check(payload: &[u8]) -> String {
    let mut buf = Vec::with_capacity(payload.len() + CHECKSUM_LEN);
    buf.extend_from_slice(payload);
    buf.extend_from_slice(&checksum(payload));
    encode(&buf)
}

/// A Base58Check string taken apart, *without* requiring the checksum to be
/// right.
///
/// This is the shape a tools library needs. Refusing to say anything about a
/// string whose checksum fails is exactly wrong when the question being asked
/// is "why is this address rejected" — [`Parts::is_valid`] answers that, and
/// the fields show the working.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Parts {
    /// Everything before the checksum. For an address or a WIF key, the
    /// version byte is `payload[0]`.
    pub payload: Vec<u8>,
    /// The four bytes the string actually carries.
    pub checksum: [u8; CHECKSUM_LEN],
    /// The four bytes `payload` hashes to. Equal to `checksum` when the string
    /// is intact.
    pub expected: [u8; CHECKSUM_LEN],
}

impl Parts {
    /// True when the string carries the checksum its payload implies.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.checksum == self.expected
    }
}

/// Decode Base58Check into its parts, reporting a bad checksum rather than
/// refusing on one.
///
/// # Errors
///
/// [`Base58Error::InvalidChar`], [`Base58Error::TooLong`] or
/// [`Base58Error::TooShort`]. A checksum mismatch is *not* an error here — see
/// [`Parts`].
pub fn decode_check_parts(s: &str) -> Result<Parts, Base58Error> {
    let bytes = decode(s)?;
    if bytes.len() < CHECKSUM_LEN {
        return Err(Base58Error::TooShort { len: bytes.len() });
    }
    let split = bytes.len() - CHECKSUM_LEN;
    let payload = bytes[..split].to_vec();
    let mut found = [0u8; CHECKSUM_LEN];
    found.copy_from_slice(&bytes[split..]);
    let expected = checksum(&payload);
    Ok(Parts {
        payload,
        checksum: found,
        expected,
    })
}

/// Decode Base58Check and return the payload, requiring the checksum.
///
/// # Errors
///
/// [`Base58Error::InvalidChar`], [`Base58Error::TooLong`],
/// [`Base58Error::TooShort`], or [`Base58Error::BadChecksum`] with both
/// values.
pub fn decode_check(s: &str) -> Result<Vec<u8>, Base58Error> {
    let parts = decode_check_parts(s)?;
    if !parts.is_valid() {
        return Err(Base58Error::BadChecksum {
            found: parts.checksum,
            expected: parts.expected,
        });
    }
    Ok(parts.payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn the_alphabet_omits_the_confusable_characters() {
        assert_eq!(ALPHABET.len(), 58);
        // Zero, capital O, capital I, lowercase L -- the four base58 leaves out
        // because they are read wrong when a human copies an address.
        for c in *b"0OIl" {
            assert!(
                !ALPHABET.contains(&c),
                "{} must not be in the alphabet",
                char::from(c)
            );
        }
        // …and every character it does have is distinct.
        let mut seen = ALPHABET.to_vec();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(seen.len(), 58, "the alphabet repeats a character");
    }

    #[test]
    fn encodes_the_published_vectors() {
        for (bytes, encoded) in [
            ("", ""),
            ("61", "2g"),
            ("626262", "a3gV"),
            ("636363", "aPEr"),
            (
                "73696d706c792061206c6f6e6720737472696e67",
                "2cFupjhnEsSn59qHXstmK2ffpLv2",
            ),
        ] {
            let raw = hex::decode(bytes).unwrap();
            assert_eq!(encode(&raw), encoded, "encoding {bytes}");
            assert_eq!(decode(encoded).unwrap(), raw, "decoding {encoded}");
        }
    }

    /// The rule that is not arithmetic: a zero byte carries no value, so only
    /// explicit bookkeeping keeps it.
    #[test]
    fn leading_zero_bytes_become_leading_ones() {
        assert_eq!(encode(&[0]), "1");
        assert_eq!(encode(&[0, 0]), "11");
        assert_eq!(encode(&[0, 0, 1]), "112");
        assert_eq!(decode("1").unwrap(), vec![0]);
        assert_eq!(decode("11").unwrap(), vec![0, 0]);
        assert_eq!(decode("112").unwrap(), vec![0, 0, 1]);
        // A mainnet address is a `0x00` version byte, which is why they all
        // start with `1`. Dropping it would shorten every one of them.
        assert_eq!(encode(&[0x00, 0xff]), "15Q");
        assert_eq!(decode("15Q").unwrap(), vec![0x00, 0xff]);
    }

    #[test]
    fn round_trips_at_every_width() {
        for len in 0..40usize {
            for seed in [0x00u8, 0x01, 0x7f, 0xff] {
                let bytes: Vec<u8> = (0..len)
                    .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
                    .collect();
                assert_eq!(
                    decode(&encode(&bytes)).unwrap(),
                    bytes,
                    "{len} bytes seeded {seed:#04x}"
                );
            }
        }
    }

    #[test]
    fn rejects_characters_outside_the_alphabet() {
        // The four excluded characters are the ones worth naming.
        for (s, offset) in [("0", 0), ("O", 0), ("I", 0), ("l", 0), ("1x0", 2)] {
            assert_eq!(
                decode(s),
                Err(Base58Error::InvalidChar { offset }),
                "decoding {s}"
            );
        }
    }

    /// The canonical worked example: hash160 of a public key, version 0x00,
    /// Base58Check — the address form published alongside it.
    #[test]
    fn produces_the_published_address() {
        let payload = hex::decode("00010966776006953d5567439e5e39f86a0d273bee").unwrap();
        assert_eq!(encode_check(&payload), "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM");
        assert_eq!(
            decode_check("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM").unwrap(),
            payload
        );
    }

    /// The most published Base58Check string there is.
    #[test]
    fn produces_the_genesis_address() {
        let payload = hex::decode("0062e907b15cbf27d5425399ebf6f0fb50ebb88f18").unwrap();
        assert_eq!(encode_check(&payload), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    #[test]
    fn a_wrong_checksum_is_shown_rather_than_hidden() {
        // Same address with one character changed in the checksum region.
        let good = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
        let bad = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN";

        let parts = decode_check_parts(bad).expect("still decodes as base58");
        assert!(!parts.is_valid());
        assert_ne!(parts.checksum, parts.expected);
        // The payload is still visible, which is the point.
        assert_eq!(
            hex::encode(&parts.payload),
            "00010966776006953d5567439e5e39f86a0d273bee"
        );

        // …while the checked form refuses, and says what it wanted.
        assert!(matches!(
            decode_check(bad),
            Err(Base58Error::BadChecksum { .. })
        ));
        assert!(decode_check_parts(good).unwrap().is_valid());
    }

    #[test]
    fn a_string_too_short_to_hold_a_checksum_is_rejected() {
        // Three bytes of payload-plus-checksum cannot be split.
        let short = encode(&[1, 2, 3]);
        assert_eq!(
            decode_check_parts(&short),
            Err(Base58Error::TooShort { len: 3 })
        );
        assert_eq!(
            decode_check_parts(""),
            Err(Base58Error::TooShort { len: 0 })
        );
        // Exactly four bytes is an empty payload, which is short but legal.
        let empty_payload = encode_check(&[]);
        assert_eq!(decode_check(&empty_payload).unwrap(), Vec::<u8>::new());
    }

    /// The door on the quadratic work. Without it, `Address::from_str` and
    /// `PrivateKey::from_wif` — both public, both taking a `&str` a consumer
    /// hands straight from a request — inherit an unbounded cost.
    #[test]
    fn a_string_too_long_to_chew_on_is_rejected() {
        let huge = "z".repeat(MAX_LEN + 1);
        assert_eq!(
            decode(&huge),
            Err(Base58Error::TooLong {
                len: MAX_LEN + 1,
                max: MAX_LEN
            })
        );
        // The check is on the trimmed string, so whitespace cannot smuggle a
        // string past it or push a legal one over.
        assert_eq!(
            decode(&format!("  {huge}  ")),
            Err(Base58Error::TooLong {
                len: MAX_LEN + 1,
                max: MAX_LEN
            })
        );
        // Exactly at the limit still decodes, and every real string is far
        // shorter: an address is 34 characters, a WIF 52.
        assert!(decode(&"z".repeat(MAX_LEN)).is_ok());
        const { assert!(MAX_LEN > 111, "a BIP32 extended key must still fit") };
    }

    #[test]
    fn tolerates_surrounding_whitespace() {
        assert_eq!(
            decode_check("  16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM \n").unwrap(),
            hex::decode("00010966776006953d5567439e5e39f86a0d273bee").unwrap()
        );
    }
}
