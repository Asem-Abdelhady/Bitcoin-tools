//! Public keys.

use crate::parse::display_serialize;
use std::fmt;
use std::str::FromStr;

use crate::crypto::ecdsa::{self, Signature};
use crate::crypto::secp::{
    COMPRESSED_SIZE, Point, PointError, SCALAR_SIZE, TweakError, UNCOMPRESSED_SIZE,
};
use crate::hashes::{hash160, tagged_sha256};
use crate::hex::{self, HexError};
use crate::keys::address::{Address, AddressHash};
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
    /// An operation that requires a compressed key was asked of an
    /// uncompressed one. Every segwit output type does: BIP143 makes an
    /// uncompressed key in a v0 witness invalid, and taproot keys are x-only.
    Uncompressed,
    /// A curve tweak failed — see [`TweakError`]. Unreachable in practice;
    /// present because it is not unreachable by construction.
    Tweak(TweakError),
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicKeyError::Hex(e) => write!(f, "{e}"),
            PublicKeyError::Point(e) => write!(f, "{e}"),
            PublicKeyError::Uncompressed => {
                f.write_str("this address type requires a compressed public key")
            }
            PublicKeyError::Tweak(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for PublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PublicKeyError::Hex(e) => Some(e),
            PublicKeyError::Point(e) => Some(e),
            PublicKeyError::Tweak(e) => Some(e),
            PublicKeyError::Uncompressed => None,
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

impl From<TweakError> for PublicKeyError {
    fn from(e: TweakError) -> Self {
        PublicKeyError::Tweak(e)
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
        let bytes = hex::decode_lenient(s)?;
        PublicKey::from_sec1(&bytes)
    }

    /// The underlying point, for anything that is about the curve rather than
    /// about Bitcoin.
    #[must_use]
    pub const fn point(&self) -> Point {
        self.point
    }

    /// Does `signature` verify against this key and this hash?
    ///
    /// A forward to [`ecdsa::verify`], which documents what the answer means —
    /// in particular that it is the arithmetic question, and that
    /// [`Signature::is_low_s`] is the separate policy one.
    ///
    /// The compression flag plays no part: `02…`, `03…` and `04…` spellings of
    /// the same point verify the same signatures. It changes the *address*,
    /// which is why this type keeps it, and never the arithmetic.
    #[must_use]
    pub fn verify(&self, message_hash: &[u8; ecdsa::MESSAGE_SIZE], signature: &Signature) -> bool {
        ecdsa::verify(message_hash, signature, &self.point)
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

    /// The native segwit v0 address — BIP84's output type.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Uncompressed`] for an uncompressed key. BIP143 makes
    /// an uncompressed key in a v0 witness invalid outright, so there is no
    /// such address to return; compressing it silently would hand back an
    /// address for a key the caller does not think they have, and a different
    /// one from the P2PKH address the same value produces.
    pub fn p2wpkh_address(&self, network: Network) -> Result<Address, PublicKeyError> {
        if !self.compressed {
            return Err(PublicKeyError::Uncompressed);
        }
        Ok(Address::p2wpkh(self.pubkey_hash(), network))
    }

    /// The redeem script BIP49 wraps in P2SH: `OP_0 <20-byte pubkey hash>`.
    ///
    /// Exposed rather than kept inside [`PublicKey::p2sh_p2wpkh_address`]
    /// because it is what the spending input's `scriptSig` has to push, and a
    /// tool showing a BIP49 account should be able to show it.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Uncompressed`], as for
    /// [`PublicKey::p2wpkh_address`] — a nested witness program is still a
    /// witness program.
    pub fn p2wpkh_redeem_script(&self) -> Result<Vec<u8>, PublicKeyError> {
        if !self.compressed {
            return Err(PublicKeyError::Uncompressed);
        }
        let mut script = vec![0x00, 0x14];
        script.extend_from_slice(self.pubkey_hash().as_bytes());
        Ok(script)
    }

    /// The P2SH-wrapped segwit address — BIP49's output type.
    ///
    /// From outside it is an ordinary P2SH address starting with `3`: the
    /// witness program is the *redeem script*, so what the output commits to
    /// is `HASH160` of that script rather than of the key.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Uncompressed`].
    pub fn p2sh_p2wpkh_address(&self, network: Network) -> Result<Address, PublicKeyError> {
        let redeem = self.p2wpkh_redeem_script()?;
        Ok(Address::p2sh(
            AddressHash::from_bytes(hash160(&redeem)),
            network,
        ))
    }

    /// The taproot output key for this key used as an internal key with no
    /// script tree — BIP86's rule.
    ///
    /// `Q = P + int(tagged_hash("TapTweak", x(P))) * G`. The tweak is not
    /// decoration: an output that committed to `P` directly would be spendable
    /// by anyone who could produce a script path, and the tweak with an empty
    /// tree is what proves there is no script path.
    ///
    /// The internal key is *not* the output key, and neither is the address.
    /// Three different 32-byte values that all look alike is exactly why this
    /// is named after what it returns.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Tweak`] if the tweak is not a scalar or the result is
    /// not a point — each around 2⁻¹²⁷, and neither reachable by any input a
    /// test could supply.
    pub fn taproot_output_key(&self) -> Result<[u8; SCALAR_SIZE], PublicKeyError> {
        let tweak = tagged_sha256("TapTweak", &self.to_x_only());
        Ok(self.point.add_tweak_x_only(&tweak)?)
    }

    /// The taproot address for this key as a BIP86 internal key.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Tweak`] — see [`PublicKey::taproot_output_key`].
    pub fn p2tr_address(&self, network: Network) -> Result<Address, PublicKeyError> {
        Ok(Address::p2tr(self.taproot_output_key()?, network))
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

display_serialize!(PublicKey);

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
