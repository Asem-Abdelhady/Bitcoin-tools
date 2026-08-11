//! Hex encoding and decoding.
//!
//! Bitcoin's interchange format for anything binary — raw transactions,
//! scripts, hashes, keys — so this sits at the root of `core` rather than
//! under any one of them.
//!
//! # What counts as hex a person may have typed
//!
//! [`decode`] is strict: it takes exactly the characters it is given. Every
//! `from_hex`-style entry point in this crate — [`Script::from_hex`],
//! [`Tx::from_hex`], [`Txid::from_str`], [`general::reverse_hex`] — therefore
//! decodes `normalize(s)` rather than `s`, so the `0x` and the whitespace
//! people paste in are accepted at the crate's edge and nowhere deeper. A new
//! entry point taking a `&str` from a caller is expected to do the same. The
//! composition stays visible at each site because the two halves are used
//! apart as well: a size cap has to be applied to the *normalized* string,
//! before decoding allocates for it.
//!
//! [`Script::from_hex`]: crate::transactions::script::Script::from_hex
//! [`Tx::from_hex`]: crate::transactions::tx::Tx::from_hex
//! [`Txid::from_str`]: crate::transactions::tx::Txid
//! [`general::reverse_hex`]: crate::general::reverse_hex

use std::fmt;

/// Why a hex string could not be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HexError {
    /// Hex needs two characters per byte.
    OddLength { len: usize },
    /// Byte offset into the input string of the offending character.
    InvalidChar { offset: usize },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::OddLength { len } => write!(f, "hex string has odd length {len}"),
            HexError::InvalidChar { offset } => write!(f, "invalid hex at byte {offset}"),
        }
    }
}

impl std::error::Error for HexError {}

/// Lowercase hex.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    // Infallible: `String`'s `fmt::Write` never errors.
    let _ = write(&mut out, bytes);
    out
}

/// Write `bytes` as lowercase hex directly into a formatter, without
/// allocating.
///
/// This is what every `Display` in the crate should call. Hashes, scripts,
/// keys and address parts all render as hex, and each one hand-rolling
/// `for b in .. { write!(f, "{b:02x}") }` is how a codec ends up defined in
/// seven places.
pub fn write(f: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    for &b in bytes {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// Write `bytes` as lowercase hex in **reverse** order — Bitcoin's display
/// order for hashes.
///
/// Txids, block hashes and merkle roots are computed and serialized in one
/// order and shown to humans in the other. Naming the flip here means a new
/// hash type states which one it wants, instead of remembering a `.rev()`.
pub fn write_rev(f: &mut impl fmt::Write, bytes: &[u8]) -> fmt::Result {
    for &b in bytes.iter().rev() {
        write!(f, "{b:02x}")?;
    }
    Ok(())
}

/// Lowercase hex in **reverse** byte order.
///
/// The allocating counterpart of [`write_rev`], as [`encode`] is of
/// [`write()`]. Anything holding bytes that need showing in Bitcoin's display
/// order wants this: a reversed `Display` calls `write_rev`, and everything
/// else — a `to_string`-style method, a JSON field, [`general::reverse`] —
/// would otherwise reach for `format!` or reverse a `Vec` first.
///
/// [`general::reverse`]: crate::general::reverse
#[must_use]
pub fn encode_rev(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    // Infallible: `String`'s `fmt::Write` never errors.
    let _ = write_rev(&mut out, bytes);
    out
}

const fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode hex, accepting either case. Does not trim — see [`normalize`].
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let raw = s.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(HexError::OddLength { len: raw.len() });
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for (i, pair) in raw.chunks_exact(2).enumerate() {
        let (Some(hi), Some(lo)) = (nibble(pair[0]), nibble(pair[1])) else {
            let offset = if nibble(pair[0]).is_none() {
                i * 2
            } else {
                i * 2 + 1
            };
            return Err(HexError::InvalidChar { offset });
        };
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

/// Decode hex in **reverse** byte order — the inverse of [`encode_rev`].
///
/// This is what parsing a *displayed* hash into wire order needs, and it is
/// the reading half of a flip that previously existed only for writing:
/// [`Txid::from_str`](crate::transactions::tx::Txid) hand-rolled decode →
/// `reverse` → `copy_from_slice`, and every hash type after it (`BlockHash`,
/// a merkle root, the planned `Hash<N>`) wants the identical three lines.
/// Byte order is a decision each of those types makes once; it should not be
/// re-implemented once per type.
pub fn decode_rev(s: &str) -> Result<Vec<u8>, HexError> {
    let mut bytes = decode(s)?;
    bytes.reverse();
    Ok(bytes)
}

/// Strip surrounding whitespace and one optional `0x` prefix — the two things
/// people paste in without meaning to.
///
/// Exactly one prefix: `"0x0xab"` is not a hex string anybody meant to write,
/// and normalizing it into a successful decode would hide a typo rather than
/// report it.
///
/// An offset in a [`HexError`] from a later [`decode`] is relative to the
/// string returned here, not to the one passed in. A caller that underlines
/// the offending character in what the user actually typed has to add back
/// what this stripped — two for a `0x`, plus any leading whitespace.
#[must_use]
pub fn normalize(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix("0x").unwrap_or(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for case in [
            vec![],
            vec![0x00],
            vec![0xff, 0x00, 0xab],
            (0..=255).collect(),
        ] {
            assert_eq!(decode(&encode(&case)).unwrap(), case);
        }
    }

    #[test]
    fn encodes_lowercase_and_zero_padded() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn encode_rev_is_encode_backwards_by_whole_bytes() {
        // Nibbles travel together: 0xde 0xad becomes 0xad 0xde, never "daed".
        assert_eq!(encode_rev(&[0xde, 0xad]), "adde");
        assert_eq!(encode_rev(&[0x00, 0x0f, 0xa0]), "a00f00");
        assert_eq!(encode_rev(&[]), "");
        // Agrees with the non-allocating form it wraps.
        let bytes: Vec<u8> = (0..=255).collect();
        let mut s = String::new();
        write_rev(&mut s, &bytes).unwrap();
        assert_eq!(encode_rev(&bytes), s);
    }

    #[test]
    fn decode_rev_undoes_encode_rev() {
        assert_eq!(decode_rev("adde").unwrap(), vec![0xde, 0xad]);
        assert_eq!(decode_rev("").unwrap(), Vec::<u8>::new());
        for case in [vec![], vec![0x00], vec![0xff, 0x00, 0xab]] {
            assert_eq!(decode_rev(&encode_rev(&case)).unwrap(), case);
        }
        // Strict about the same things `decode` is — it is the same scan.
        assert_eq!(decode_rev("abc"), Err(HexError::OddLength { len: 3 }));
        assert_eq!(decode_rev("zz"), Err(HexError::InvalidChar { offset: 0 }));
    }

    #[test]
    fn decodes_either_case() {
        assert_eq!(decode("DEADbeef").unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn reports_where_the_problem_is() {
        assert_eq!(decode("abc"), Err(HexError::OddLength { len: 3 }));
        assert_eq!(decode("zz"), Err(HexError::InvalidChar { offset: 0 }));
        assert_eq!(decode("az"), Err(HexError::InvalidChar { offset: 1 }));
        assert_eq!(decode("00zz"), Err(HexError::InvalidChar { offset: 2 }));
        // Offsets are byte offsets, so a 2-byte 'é' occupies a whole pair.
        assert_eq!(decode("00é00"), Err(HexError::InvalidChar { offset: 2 }));
        // …and an odd *byte* length is caught first, even if it looks even.
        assert_eq!(decode("00é0"), Err(HexError::OddLength { len: 5 }));
    }

    #[test]
    fn normalize_strips_noise() {
        assert_eq!(normalize("  0xdeadbeef \n"), "deadbeef");
        assert_eq!(normalize("deadbeef"), "deadbeef");
        assert_eq!(normalize("0x"), "");
    }
}
