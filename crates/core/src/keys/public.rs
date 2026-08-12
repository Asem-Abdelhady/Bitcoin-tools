//! § 3.2 — Public keys.

use std::fmt;
use std::str::FromStr;

use crate::crypto::secp::{COMPRESSED_SIZE, Point, PointError, SCALAR_SIZE, UNCOMPRESSED_SIZE};
use crate::hashes::hash160;
use crate::hex::{self, HexError};
use crate::keys::address::Address;
use crate::keys::address::AddressHash;
use crate::network::Network;

/// A point on the curve, together with how it is being serialized.
///
/// The compression flag is not part of the point — the same key has both
/// forms — but it decides which bytes get hashed, and therefore which address
/// the key has. One key with two encodings is two addresses, and every
/// "where did my coins go" story about early wallets is that fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKey {
    point: Point,
    /// Whether [`PublicKey::to_bytes`] gives the 33-byte or the 65-byte form.
    pub compressed: bool,
}

/// Why bytes are not a public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PublicKeyError {
    /// Not hex, or an odd number of digits.
    Hex(HexError),
    /// Not a point on the curve — see [`PointError`].
    Point(PointError),
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyError::Hex(e) => write!(f, "{e}"),
            PublicKeyError::Point(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PublicKeyError::Hex(e) => Some(e),
            PublicKeyError::Point(e) => Some(e),
        }
    }
}

impl From<HexError> for PublicKeyError {
    fn from(e: HexError) -> Self {
        PublicKeyError::Hex(e)
    }
}

impl From<PointError> for PublicKeyError {
    fn from(e: PointError) -> Self {
        PublicKeyError::Point(e)
    }
}

impl PublicKey {
    /// Wrap a curve point with a chosen serialization.
    #[must_use]
    pub const fn new(point: Point, compressed: bool) -> Self {
        PublicKey { point, compressed }
    }

    /// Read a key from its SEC1 bytes, taking the compression flag from the
    /// encoding rather than from the caller — 33 bytes is compressed, 65 is
    /// not, and the prefix byte says which.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Point`] if the bytes are not a point on the curve.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, PublicKeyError> {
        let point = Point::from_sec1(bytes)?;
        Ok(PublicKey {
            point,
            compressed: bytes.len() == COMPRESSED_SIZE,
        })
    }

    /// Read a key written in hex.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError`] for bad hex or a point that is not on the curve.
    ///
    /// ```
    /// use bitcoin_tools_core::keys::PublicKey;
    /// use bitcoin_tools_core::network::Network;
    ///
    /// // The worked example every Bitcoin tutorial uses.
    /// let key = PublicKey::from_hex(
    ///     "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352\
    ///      2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",
    /// )?;
    ///
    /// assert_eq!(
    ///     key.p2pkh_address(Network::Mainnet).to_string(),
    ///     "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
    /// );
    /// # Ok::<_, bitcoin_tools_core::keys::PublicKeyError>(())
    /// ```
    pub fn from_hex(s: &str) -> Result<Self, PublicKeyError> {
        let bytes = hex::decode(hex::normalize(s))?;
        PublicKey::from_sec1(&bytes)
    }

    /// The underlying point, for anything that is about the curve rather than
    /// about Bitcoin.
    #[must_use]
    pub const fn point(&self) -> Point {
        self.point
    }

    /// The `(x, y)` coordinates, 32 bytes each.
    #[must_use]
    pub fn coordinates(&self) -> ([u8; SCALAR_SIZE], [u8; SCALAR_SIZE]) {
        self.point.coordinates()
    }

    /// 33 bytes: `02` or `03` by the parity of `y`, then `x`.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; COMPRESSED_SIZE] {
        self.point.to_compressed()
    }

    /// 65 bytes: `04`, then `x`, then `y`.
    #[must_use]
    pub fn to_uncompressed(&self) -> [u8; UNCOMPRESSED_SIZE] {
        self.point.to_uncompressed()
    }

    /// 32 bytes: `x` alone, BIP340's form for taproot.
    #[must_use]
    pub fn to_x_only(&self) -> [u8; SCALAR_SIZE] {
        self.point.to_x_only()
    }

    /// The serialization this key is actually using — the bytes that get
    /// hashed, and so the bytes that decide the address.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.compressed {
            self.to_compressed().to_vec()
        } else {
            self.to_uncompressed().to_vec()
        }
    }

    /// `HASH160` of [`PublicKey::to_bytes`] — the twenty bytes a P2PKH or
    /// P2WPKH output commits to.
    ///
    /// Wire order, and shown that way: unlike a txid, a pubkey hash is never
    /// printed reversed. That is why
    /// [`Hash`](crate::hashes::Hash) does not decide the order and this type
    /// does not have to override anything.
    #[must_use]
    pub fn pubkey_hash(&self) -> AddressHash {
        AddressHash::from_bytes(hash160(&self.to_bytes()))
    }

    /// The P2PKH address for this key on `network`.
    #[must_use]
    pub fn p2pkh_address(&self, network: Network) -> Address {
        Address::p2pkh(self.pubkey_hash(), network)
    }
}

/// Hex of whichever serialization this key uses.
impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.to_bytes())
    }
}

impl FromStr for PublicKey {
    type Err = PublicKeyError;

    /// The inverse of [`Display`](fmt::Display): hex of a SEC1 encoding, which
    /// is the form a public key is written in everywhere.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PublicKey::from_hex(s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::private::PrivateKey;

    /// The generator, which is `1 * G` and the most published point there is.
    const G_COMPRESSED: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const G_Y: &str = "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    fn generator(compressed: bool) -> PublicKey {
        let mut one = [0u8; SCALAR_SIZE];
        one[31] = 1;
        PrivateKey::from_be_bytes(&one, Network::Mainnet, compressed)
            .unwrap()
            .public_key()
    }

    #[test]
    fn shows_every_encoding_of_one_point() {
        let key = generator(true);
        assert_eq!(hex::encode(&key.to_compressed()), G_COMPRESSED);
        assert_eq!(hex::encode(&key.to_x_only()), G_X);
        let (x, y) = key.coordinates();
        assert_eq!(hex::encode(&x), G_X);
        assert_eq!(hex::encode(&y), G_Y);
        assert_eq!(hex::encode(&key.to_uncompressed()), format!("04{G_X}{G_Y}"));
    }

    /// The compression flag decides which bytes are hashed, so the same key
    /// has two different pubkey hashes and two different addresses.
    #[test]
    fn one_key_two_encodings_two_addresses() {
        let compressed = generator(true);
        let uncompressed = generator(false);

        assert_eq!(compressed.point(), uncompressed.point(), "same point");
        assert_eq!(compressed.to_bytes().len(), 33);
        assert_eq!(uncompressed.to_bytes().len(), 65);
        assert_ne!(compressed.pubkey_hash(), uncompressed.pubkey_hash());
        assert_ne!(
            compressed.p2pkh_address(Network::Mainnet).to_string(),
            uncompressed.p2pkh_address(Network::Mainnet).to_string()
        );
    }

    #[test]
    fn reads_back_from_both_serializations() {
        for compressed in [true, false] {
            let key = generator(compressed);
            let parsed = PublicKey::from_hex(&key.to_string()).unwrap();
            assert_eq!(parsed.point(), key.point());
            assert_eq!(
                parsed.compressed, compressed,
                "the encoding says which form it is; the caller does not"
            );
        }
    }

    #[test]
    fn rejects_what_is_not_a_key() {
        assert!(matches!(
            PublicKey::from_hex("zz"),
            Err(PublicKeyError::Hex(_))
        ));
        assert!(matches!(
            PublicKey::from_hex(&"ff".repeat(33)),
            Err(PublicKeyError::Point(_))
        ));
        // A compressed key with its x tampered with is no longer on the curve.
        let mut bad = generator(true).to_compressed();
        bad[32] ^= 0xff;
        assert!(matches!(
            PublicKey::from_sec1(&bad),
            Err(PublicKeyError::Point(_))
        ));
    }

    /// The end-to-end path the wiki publishes: an uncompressed key, its
    /// HASH160, and the address that hash produces.
    #[test]
    fn reproduces_the_published_key_to_address_path() {
        let key = PublicKey::from_hex(
            "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352\
             2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",
        )
        .unwrap();
        assert!(!key.compressed, "65 bytes is the uncompressed form");
        assert_eq!(
            key.pubkey_hash().to_hex(),
            "010966776006953d5567439e5e39f86a0d273bee"
        );
        assert_eq!(
            key.p2pkh_address(Network::Mainnet).to_string(),
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
        );
    }
}
