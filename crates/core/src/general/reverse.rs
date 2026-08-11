//! 1.1 — Reverse Bytes: wire order ⇄ display order.
//!
//! Bitcoin writes hashes into blocks and transactions in one byte order and
//! shows them to people in the other. A txid copied from an explorer never
//! appears verbatim in the raw transaction that produced it, and this is the
//! operation relating the two.
//!
//! Reversal is an involution — applying it twice is the identity — so one
//! function covers both directions. A `ByteOrder` argument would decorate the
//! signature without changing what it computes.
//!
//! # This module is the wrapper, not the flip
//!
//! The flip itself is [`hex::encode_rev`] at L0; why it lives there rather
//! than here is argued once, in [the module docs above](super).
//!
//! What this module adds is what a *string a person typed* needs and a
//! `&[u8]` does not: accepting the `0x` and whitespace people paste in, and
//! reporting where the hex went wrong. A caller that already holds decoded
//! bytes — the web server, which decodes through its own input policy before
//! any domain code runs — wants [`hex::encode_rev`] directly instead of
//! re-encoding a `Vec` just to parse it again.

use crate::hex::{self, HexError};

/// Reverse the byte order of a hex string.
///
/// Whitespace and one `0x` prefix are accepted, per [`hex`]'s input policy.
/// An empty string reverses to an empty string:
/// whether the caller should have sent something is the caller's policy, not
/// a property of reversal.
///
/// # Errors
///
/// [`HexError`] if the input is not a whole number of bytes of hex. Reversal
/// is defined on bytes, so a lone nibble has no answer — reversing `"abc"` as
/// text gives `"cba"`, which is a different value rather than the same value
/// the other way round.
///
/// # Examples
///
/// A txid as it occupies bytes inside a raw transaction, and as an explorer
/// prints it:
///
/// ```
/// use bitcoin_tools_core::general::reverse_hex;
///
/// let wire = "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7";
/// let shown = "b7a2e93a958ff96729c6f0f6dc250b3d3c36b0064d057f8d2bea6df68fbb0085";
///
/// assert_eq!(reverse_hex(wire)?, shown);
/// assert_eq!(reverse_hex(shown)?, wire);
/// # Ok::<_, bitcoin_tools_core::hex::HexError>(())
/// ```
pub fn reverse_hex(s: &str) -> Result<String, HexError> {
    hex::decode(hex::normalize(s)).map(|bytes| hex::encode_rev(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverses_bytes_rather_than_characters() {
        assert_eq!(reverse_hex("dead").unwrap(), "adde");
        assert_eq!(reverse_hex("0102030405").unwrap(), "0504030201");
    }

    #[test]
    fn is_its_own_inverse() {
        for case in ["", "ab", "dead", "0102030405", "ff00ff00"] {
            let there = reverse_hex(case).unwrap();
            assert_eq!(reverse_hex(&there).unwrap(), case, "round trip for {case}");
        }
    }

    #[test]
    fn one_byte_and_no_bytes_are_unchanged() {
        assert_eq!(reverse_hex("ab").unwrap(), "ab");
        assert_eq!(reverse_hex("").unwrap(), "");
    }

    #[test]
    fn output_is_lowercase_whatever_went_in() {
        assert_eq!(reverse_hex("DEADBEEF").unwrap(), "efbeadde");
    }

    #[test]
    fn accepts_the_noise_people_paste() {
        assert_eq!(reverse_hex("  0xdeadbeef \n").unwrap(), "efbeadde");
        // `0x` and nothing else normalises to empty, which is not an error
        // here — the empty-input decision belongs to the caller.
        assert_eq!(reverse_hex(" 0x ").unwrap(), "");
    }

    #[test]
    fn rejects_anything_that_is_not_whole_bytes() {
        assert_eq!(reverse_hex("abc"), Err(HexError::OddLength { len: 3 }));
        assert_eq!(reverse_hex("zz"), Err(HexError::InvalidChar { offset: 0 }));
        // Offsets refer to the normalised string, as everywhere else in the
        // crate — `0x` is not part of the hex it reports on.
        assert_eq!(
            reverse_hex("0x00zz"),
            Err(HexError::InvalidChar { offset: 2 })
        );
    }
}
