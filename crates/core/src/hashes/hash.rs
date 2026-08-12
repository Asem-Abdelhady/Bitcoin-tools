//! A fixed-size digest, and the byte-order handling every hash type needs.

use std::fmt;
use std::str::FromStr;

use crate::hex::{self, HexError};

/// Why a string was not a hash of the expected width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashParseError {
    /// Not hex, or an odd number of digits.
    Hex(HexError),
    /// Hex, but the wrong number of bytes. A hash has exactly one width, so
    /// this is not a value that can be padded into place.
    WrongLength {
        /// Bytes decoded.
        got: usize,
        /// Bytes this hash width requires.
        expected: usize,
    },
}

impl fmt::Display for HashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashParseError::Hex(e) => write!(f, "{e}"),
            HashParseError::WrongLength { got, expected } => {
                write!(f, "expected a {expected}-byte hash, got {got} bytes")
            }
        }
    }
}

impl std::error::Error for HashParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HashParseError::Hex(e) => Some(e),
            HashParseError::WrongLength { .. } => None,
        }
    }
}

impl From<HexError> for HashParseError {
    fn from(e: HexError) -> Self {
        HashParseError::Hex(e)
    }
}

/// `N` bytes of digest, in the order they appear on the wire.
///
/// # Byte order is not part of this type
///
/// The plan this replaced said `Hash<N>` would supply a reversed `Display`,
/// "Bitcoin's convention". That turned out to be wrong, and the counter-example
/// is not exotic: a merkle root and a P2WSH script commitment are both thirty-two
/// bytes, and only the first is shown reversed. Width does not predict order.
///
/// So order belongs to the *semantic* type, not to the width, and this one
/// stores wire order and offers both renderings by name —
/// [`Hash::to_hex`] and [`Hash::to_hex_reversed`], [`Hash::from_hex`] and
/// [`Hash::from_hex_reversed`]. [`Display`](fmt::Display) is the forward one,
/// because a type that wants the reversal has to say so:
/// [`Txid`](crate::transactions::tx::Txid) is one line of `Display` over
/// [`hex::write_rev`], and that line is the whole declaration of its
/// convention.
///
/// What this type does supply is everything that is *not* the order — the
/// storage, the width check, the hex codec, and the equality — so a new hash
/// type is a newtype and a `Display`, rather than seventy lines that can each
/// be got subtly wrong.
///
/// ```
/// use bitcoin_tools_core::hashes::{Hash, hash160};
///
/// let digest: Hash<20> = Hash::from_bytes(hash160(b"abc"));
/// assert_eq!(digest.to_hex().len(), 40);
///
/// // Wire order in, wire order out; the reversal is always asked for.
/// assert_eq!(Hash::<20>::from_hex(&digest.to_hex())?, digest);
/// assert_eq!(Hash::<20>::from_hex_reversed(&digest.to_hex_reversed())?, digest);
/// # Ok::<_, bitcoin_tools_core::hashes::HashParseError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash<const N: usize>([u8; N]);

impl<const N: usize> Hash<N> {
    /// Width in bytes, which is the type parameter under a readable name.
    pub const SIZE: usize = N;

    /// Wrap bytes that are already in wire order.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; N]) -> Self {
        Hash(bytes)
    }

    /// The bytes, in wire order.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; N] {
        self.0
    }

    /// The bytes, in wire order, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }

    /// Read `N` bytes of hex in wire order.
    ///
    /// # Errors
    ///
    /// [`HashParseError`] for bad hex or the wrong width.
    pub fn from_hex(s: &str) -> Result<Self, HashParseError> {
        Self::from_slice(&hex::decode(hex::normalize(s))?)
    }

    /// Read `N` bytes of hex written in *display* order, undoing the reversal.
    ///
    /// This is the one that closes the trap: hex-decoding an explorer txid
    /// straight into [`Hash::from_bytes`] yields a byte-reversed value that
    /// nothing downstream can detect.
    ///
    /// # Errors
    ///
    /// [`HashParseError`] for bad hex or the wrong width.
    pub fn from_hex_reversed(s: &str) -> Result<Self, HashParseError> {
        Self::from_slice(&hex::decode_rev(hex::normalize(s))?)
    }

    /// Wrap a slice that is already in wire order.
    ///
    /// The width check, in one place. Without it every caller holding a slice
    /// — a bech32 witness program, a header field read into a `Vec` — writes
    /// the same `try_into` and the same error arm, and spells `N` itself.
    ///
    /// # Errors
    ///
    /// [`HashParseError::WrongLength`] unless the slice is exactly `N` bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, HashParseError> {
        <[u8; N]>::try_from(bytes)
            .map(Hash)
            .map_err(|_| HashParseError::WrongLength {
                got: bytes.len(),
                expected: N,
            })
    }

    /// Lowercase hex in wire order.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Lowercase hex reversed — the order explorers and RPC print.
    #[must_use]
    pub fn to_hex_reversed(&self) -> String {
        hex::encode_rev(&self.0)
    }
}

/// Wire order. A type displayed reversed says so itself.
impl<const N: usize> fmt::Display for Hash<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

impl<const N: usize> FromStr for Hash<N> {
    type Err = HashParseError;

    /// Wire order, matching [`Display`](fmt::Display). For the displayed form
    /// of a txid or block hash, use [`Hash::from_hex_reversed`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_hex(s)
    }
}

impl<const N: usize> AsRef<[u8]> for Hash<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> From<[u8; N]> for Hash<N> {
    fn from(bytes: [u8; N]) -> Self {
        Hash(bytes)
    }
}

impl<const N: usize> TryFrom<&[u8]> for Hash<N> {
    type Error = HashParseError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Hash::from_slice(bytes)
    }
}

#[cfg(feature = "serde")]
impl<const N: usize> serde::Serialize for Hash<N> {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WIRE: &str = "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7";
    const SHOWN: &str = "b7a2e93a958ff96729c6f0f6dc250b3d3c36b0064d057f8d2bea6df68fbb0085";

    #[test]
    fn both_orders_are_available_and_neither_is_implicit() {
        let hash = Hash::<32>::from_hex(WIRE).unwrap();
        assert_eq!(hash.to_hex(), WIRE);
        assert_eq!(hash.to_hex_reversed(), SHOWN);
        assert_eq!(hash.to_string(), WIRE, "Display is wire order");

        // Reading the displayed form gives the same value as reading the wire
        // form — which is the whole point of naming the two parsers.
        assert_eq!(Hash::<32>::from_hex_reversed(SHOWN).unwrap(), hash);
        assert_ne!(Hash::<32>::from_hex(SHOWN).unwrap(), hash);
    }

    #[test]
    fn round_trips_in_both_directions() {
        let hash = Hash::<20>::from_hex("010966776006953d5567439e5e39f86a0d273bee").unwrap();
        assert_eq!(Hash::<20>::from_hex(&hash.to_hex()).unwrap(), hash);
        assert_eq!(
            Hash::<20>::from_hex_reversed(&hash.to_hex_reversed()).unwrap(),
            hash
        );
        assert_eq!(hash.to_string().parse::<Hash<20>>().unwrap(), hash);
    }

    #[test]
    fn the_width_is_checked_and_named() {
        assert_eq!(
            Hash::<32>::from_hex("aabb"),
            Err(HashParseError::WrongLength {
                got: 2,
                expected: 32
            })
        );
        assert_eq!(
            Hash::<20>::from_hex(&"00".repeat(21)),
            Err(HashParseError::WrongLength {
                got: 21,
                expected: 20
            })
        );
        // The reversed parser checks the same width, for the same reason.
        assert_eq!(
            Hash::<32>::from_hex_reversed(""),
            Err(HashParseError::WrongLength {
                got: 0,
                expected: 32
            })
        );
        assert!(matches!(
            Hash::<32>::from_hex("zz"),
            Err(HashParseError::Hex(_))
        ));
        // `0x` and whitespace, as everywhere else in the crate.
        assert!(Hash::<32>::from_hex(&format!("  0x{WIRE}\n")).is_ok());
    }

    #[test]
    fn size_names_the_width() {
        assert_eq!(Hash::<20>::SIZE, 20);
        assert_eq!(Hash::<32>::SIZE, 32);
        assert_eq!(Hash::<32>::from_hex(WIRE).unwrap().as_bytes().len(), 32);
    }
}
