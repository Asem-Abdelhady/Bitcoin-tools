//! § 3.1 — Private keys and WIF.

use std::fmt;
use std::str::FromStr;

use crate::crypto::secp::{SCALAR_SIZE, ScalarError, SecretScalar};
use crate::encoding::base58::{self, Base58Error};
use crate::general::Number;
use crate::hex::{self, HexError};
use crate::keys::public::PublicKey;
use crate::network::Network;

/// A secret key, with the two things WIF records alongside it: which network
/// it belongs to, and whether its public key is used compressed.
///
/// The compression flag is not a property of the secret — the same scalar
/// works either way — but it changes the address, so a key that forgets it
/// derives the wrong one. WIF stores it, and so does this.
///
/// # What this type deliberately does not have
///
/// No `Display`, no `Serialize`, and a [`Debug`](fmt::Debug) that redacts the
/// scalar. That is not an oversight to be fixed by a later patch: a secret
/// that is one `{}` away from a log line is a secret that eventually reaches
/// one. Getting the bytes out is possible — [`PrivateKey::to_be_bytes`],
/// [`PrivateKey::to_wif`] — but it has to be asked for by name.
///
/// [`FromStr`] *is* implemented, reading WIF. Parsing a secret is not a leak,
/// and the asymmetry with the redacted `Debug` is the point being made.
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey {
    scalar: SecretScalar,
    /// Which network's WIF and address version bytes apply.
    pub network: Network,
    /// Whether the public key derived from this is used in compressed form.
    /// Everything since 2012 says yes; keys from before it often say no, and
    /// they hash to a different address.
    pub compressed: bool,
}

/// Why a string or byte string is not a private key.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivateKeyError {
    /// Not hex, or an odd number of digits.
    Hex(HexError),
    /// Hex, but not 32 bytes.
    WrongLength {
        /// Bytes decoded, where 32 were needed.
        got: usize,
    },
    /// Thirty-two bytes that are not a usable scalar — zero, or at or above
    /// the group order.
    Scalar(ScalarError),
    /// The WIF string is not valid Base58Check.
    Base58(Base58Error),
    /// The payload was empty, so there is not even a version byte.
    MissingVersion,
    /// A WIF payload whose version byte belongs to no known network.
    UnknownVersion {
        /// The version byte found.
        version: u8,
    },
    /// A WIF payload of the wrong size. 33 bytes means uncompressed, 34 means
    /// compressed with a trailing `0x01`; nothing else is a key.
    WifLength {
        /// Bytes after the version byte.
        got: usize,
    },
    /// A 34-byte WIF payload whose final byte is not `0x01`. That byte has
    /// exactly one meaning, and a decoder that ignored it would report a
    /// compression flag the sender never set.
    WifCompressionFlag {
        /// The byte found where `0x01` was required.
        got: u8,
    },
}

impl fmt::Display for PrivateKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivateKeyError::Hex(e) => write!(f, "{e}"),
            PrivateKeyError::WrongLength { got } => {
                write!(f, "a private key is 32 bytes, got {got}")
            }
            PrivateKeyError::Scalar(e) => write!(f, "{e}"),
            PrivateKeyError::Base58(e) => write!(f, "{e}"),
            PrivateKeyError::MissingVersion => f.write_str("a WIF payload has no version byte"),
            PrivateKeyError::UnknownVersion { version } => {
                write!(f, "no network uses WIF version byte {version:#04x}")
            }
            PrivateKeyError::WifLength { got } => write!(
                f,
                "a WIF payload is 33 or 34 bytes after the version, got {got}"
            ),
            PrivateKeyError::WifCompressionFlag { got } => {
                write!(f, "a 34-byte WIF payload must end in 0x01, got {got:#04x}")
            }
        }
    }
}

impl std::error::Error for PrivateKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PrivateKeyError::Hex(e) => Some(e),
            PrivateKeyError::Scalar(e) => Some(e),
            PrivateKeyError::Base58(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HexError> for PrivateKeyError {
    fn from(e: HexError) -> Self {
        PrivateKeyError::Hex(e)
    }
}

impl From<ScalarError> for PrivateKeyError {
    fn from(e: ScalarError) -> Self {
        PrivateKeyError::Scalar(e)
    }
}

impl From<Base58Error> for PrivateKeyError {
    fn from(e: Base58Error) -> Self {
        PrivateKeyError::Base58(e)
    }
}

/// The WIF version byte for a network.
const fn wif_version(network: Network) -> u8 {
    // Mainnet's is the P2PKH version plus 0x80; the test networks share one,
    // which is why a testnet WIF does not say *which* test network it is.
    if network.is_mainnet() { 0x80 } else { 0xef }
}

/// Which network a WIF version byte names, if any.
const fn network_for_wif(version: u8) -> Option<Network> {
    match version {
        0x80 => Some(Network::Mainnet),
        // Testnet, signet and regtest are indistinguishable here — the byte
        // does not carry the difference, so reporting testnet is the honest
        // answer rather than a guess between three.
        0xef => Some(Network::Testnet),
        _ => None,
    }
}

impl PrivateKey {
    /// Wrap 32 big-endian bytes.
    ///
    /// # Errors
    ///
    /// [`PrivateKeyError::Scalar`] if the value is zero or at or above the
    /// group order. "Is it 32 bytes" does not answer this.
    pub fn from_be_bytes(
        bytes: &[u8; SCALAR_SIZE],
        network: Network,
        compressed: bool,
    ) -> Result<Self, PrivateKeyError> {
        Ok(PrivateKey {
            scalar: SecretScalar::from_be_bytes(bytes)?,
            network,
            compressed,
        })
    }

    /// Wrap a scalar that has already been validated.
    ///
    /// The way [`Xpriv`](crate::hd::Xpriv) hands over: it holds a
    /// [`SecretScalar`] the curve layer already accepted, and without this it
    /// would have to go out through 32 bytes and back in through
    /// [`PrivateKey::from_be_bytes`] — a copy of the secret and a
    /// re-validation, to reach a value that is already in hand.
    #[must_use]
    pub const fn from_scalar(scalar: SecretScalar, network: Network, compressed: bool) -> Self {
        PrivateKey {
            scalar,
            network,
            compressed,
        }
    }

    /// Read a key written as 64 hex digits.
    ///
    /// # Errors
    ///
    /// [`PrivateKeyError`] for bad hex, a length other than 32 bytes, or a
    /// value outside `1..n`.
    pub fn from_hex(s: &str, network: Network, compressed: bool) -> Result<Self, PrivateKeyError> {
        let bytes = hex::decode(hex::normalize(s))?;
        let array: [u8; SCALAR_SIZE] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| PrivateKeyError::WrongLength { got: bytes.len() })?;
        PrivateKey::from_be_bytes(&array, network, compressed)
    }

    /// Generate a key from the operating system's randomness.
    ///
    /// Behind the `rand` feature: inspecting an existing key has no reason to
    /// link an RNG, and a tool that only decodes should not be able to mint a
    /// secret by accident.
    ///
    /// Rejected draws are retried. The chance of one is about 2⁻¹²⁸ — the
    /// invalid range above the group order is that thin — so this is a loop
    /// that has never run twice, not a rejection sampler with a real cost.
    #[cfg(feature = "rand")]
    #[must_use]
    pub fn generate(network: Network, compressed: bool) -> Self {
        use rand::RngCore;
        let mut rng = rand::rng();
        let mut bytes = [0u8; SCALAR_SIZE];
        loop {
            rng.fill_bytes(&mut bytes);
            if let Ok(key) = PrivateKey::from_be_bytes(&bytes, network, compressed) {
                return key;
            }
        }
    }

    /// The raw scalar, 32 big-endian bytes.
    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.scalar.to_be_bytes()
    }

    /// The key as a number, for rendering in binary, decimal or hex.
    ///
    /// A private key *is* a 256-bit integer, and 3.1 asks to see it as one.
    /// Note that this drops leading zero bytes, as any numeric view does — use
    /// [`Number::to_be_bytes_padded`] to get the 32-byte field back.
    #[must_use]
    pub fn to_number(&self) -> Number {
        Number::from_be_bytes(&self.to_be_bytes())
    }

    /// The scalar itself, for the layer below.
    ///
    /// [`crypto`](crate::crypto) is L2 and cannot name this type, so signing
    /// takes a [`SecretScalar`]. Without this accessor a caller holding a
    /// WIF-parsed key would have to go out through
    /// [`PrivateKey::to_be_bytes`] and back in through
    /// [`SecretScalar::from_be_bytes`] — a copy of the secret and a
    /// re-validation, to reach a value that is already here.
    #[must_use]
    pub const fn scalar(&self) -> &SecretScalar {
        &self.scalar
    }

    /// The public key this derives.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey::new(self.scalar.public_point(), self.compressed)
    }

    /// Wallet Import Format: Base58Check over the version byte, the key, and a
    /// trailing `0x01` when the public key is compressed.
    ///
    /// That trailing byte is the whole reason a compressed-key WIF starts with
    /// `K` or `L` and an uncompressed one with `5` — it makes the payload one
    /// byte longer, which changes the leading digit.
    #[must_use]
    pub fn to_wif(&self) -> String {
        let mut payload = Vec::with_capacity(2 + SCALAR_SIZE);
        payload.push(wif_version(self.network));
        payload.extend_from_slice(&self.to_be_bytes());
        if self.compressed {
            payload.push(0x01);
        }
        base58::encode_check(&payload)
    }

    /// Read a Wallet Import Format key.
    ///
    /// The network and the compression flag both come from the string, so
    /// unlike [`PrivateKey::from_hex`] there is nothing for the caller to say.
    ///
    /// # Errors
    ///
    /// [`PrivateKeyError`] for a bad checksum, an unknown version byte, a
    /// payload of the wrong length, a compression flag that is not `0x01`, or
    /// a scalar outside `1..n`.
    ///
    /// ```
    /// use bitcoin_tools_core::keys::PrivateKey;
    /// use bitcoin_tools_core::network::Network;
    ///
    /// let key = PrivateKey::from_wif("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ")?;
    /// assert_eq!(key.network, Network::Mainnet);
    /// assert!(!key.compressed, "a WIF starting with 5 is uncompressed");
    ///
    /// // …and the key's own address falls out of it.
    /// let address = key.public_key().p2pkh_address(Network::Mainnet);
    /// assert!(address.to_string().starts_with('1'));
    /// # Ok::<_, bitcoin_tools_core::keys::PrivateKeyError>(())
    /// ```
    pub fn from_wif(s: &str) -> Result<Self, PrivateKeyError> {
        let payload = base58::decode_check(s)?;
        let (&version, rest) = payload
            .split_first()
            .ok_or(PrivateKeyError::MissingVersion)?;
        let network =
            network_for_wif(version).ok_or(PrivateKeyError::UnknownVersion { version })?;

        // Split the fixed-size key off the front, so the length check and the
        // array conversion are the same step and there is no unreachable
        // "wrong length" arm left over afterwards.
        let (key, tail) = rest
            .split_first_chunk::<SCALAR_SIZE>()
            .ok_or(PrivateKeyError::WifLength { got: rest.len() })?;
        let compressed = match tail {
            [] => false,
            // The 33rd byte says compressed, and `0x01` is the only thing it
            // is allowed to say.
            [0x01] => true,
            [flag] => return Err(PrivateKeyError::WifCompressionFlag { got: *flag }),
            _ => {
                return Err(PrivateKeyError::WifLength { got: rest.len() });
            }
        };
        PrivateKey::from_be_bytes(key, network, compressed)
    }
}

impl FromStr for PrivateKey {
    type Err = PrivateKeyError;

    /// Reads WIF, which carries its own network and compression flag — see
    /// [`PrivateKey::from_wif`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        PrivateKey::from_wif(s)
    }
}

/// Redacted, like the scalar underneath. The network and compression flag are
/// safe to show and are the fields you actually want when debugging.
impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("scalar", &self.scalar)
            .field("network", &self.network)
            .field("compressed", &self.compressed)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::general::Base;

    /// The canonical WIF worked example, uncompressed and on mainnet.
    const KEY_HEX: &str = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
    const WIF_UNCOMPRESSED: &str = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ";

    fn key(compressed: bool) -> PrivateKey {
        PrivateKey::from_hex(KEY_HEX, Network::Mainnet, compressed).expect("a valid key")
    }

    #[test]
    fn produces_the_published_wif() {
        assert_eq!(key(false).to_wif(), WIF_UNCOMPRESSED);
    }

    #[test]
    fn wif_round_trips_and_carries_its_own_metadata() {
        for network in [Network::Mainnet, Network::Testnet] {
            for compressed in [false, true] {
                let original = PrivateKey::from_hex(KEY_HEX, network, compressed).unwrap();
                let parsed = PrivateKey::from_wif(&original.to_wif()).unwrap();
                assert_eq!(parsed.to_be_bytes(), original.to_be_bytes());
                assert_eq!(parsed.network, network, "network survives the trip");
                assert_eq!(parsed.compressed, compressed, "so does compression");
            }
        }
    }

    /// The trailing `0x01` lengthens the payload, which is why the first
    /// character differs — the single most visible fact about WIF.
    #[test]
    fn compression_changes_the_leading_character() {
        assert!(WIF_UNCOMPRESSED.starts_with('5'));
        let compressed = key(true).to_wif();
        assert!(
            compressed.starts_with('K') || compressed.starts_with('L'),
            "a compressed mainnet WIF starts with K or L, got {compressed}"
        );
        // Testnet uses a different version byte, hence a different prefix.
        let testnet = PrivateKey::from_hex(KEY_HEX, Network::Testnet, false)
            .unwrap()
            .to_wif();
        assert!(testnet.starts_with('9'), "got {testnet}");
    }

    #[test]
    fn rejects_the_scalars_that_are_not_keys() {
        assert_eq!(
            PrivateKey::from_hex(&"00".repeat(32), Network::Mainnet, true),
            Err(PrivateKeyError::Scalar(ScalarError::Zero))
        );
        assert_eq!(
            PrivateKey::from_hex(
                "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                Network::Mainnet,
                true
            ),
            Err(PrivateKeyError::Scalar(ScalarError::NotBelowGroupOrder))
        );
    }

    #[test]
    fn rejects_hex_that_is_not_a_key() {
        assert_eq!(
            PrivateKey::from_hex("00", Network::Mainnet, true),
            Err(PrivateKeyError::WrongLength { got: 1 })
        );
        assert_eq!(
            PrivateKey::from_hex(&"00".repeat(33), Network::Mainnet, true),
            Err(PrivateKeyError::WrongLength { got: 33 })
        );
        assert!(matches!(
            PrivateKey::from_hex("zz", Network::Mainnet, true),
            Err(PrivateKeyError::Hex(_))
        ));
        // `0x` and whitespace are accepted, as everywhere else.
        assert!(PrivateKey::from_hex(&format!("  0x{KEY_HEX}\n"), Network::Mainnet, true).is_ok());
    }

    #[test]
    fn rejects_malformed_wif() {
        // A flipped character breaks the checksum.
        let mut broken: Vec<char> = WIF_UNCOMPRESSED.chars().collect();
        broken[10] = if broken[10] == 'a' { 'b' } else { 'a' };
        let broken: String = broken.into_iter().collect();
        assert!(matches!(
            PrivateKey::from_wif(&broken),
            Err(PrivateKeyError::Base58(_))
        ));

        // A valid Base58Check string with a version byte nobody uses.
        let mut payload = vec![0x99];
        payload.extend_from_slice(&hex::decode(KEY_HEX).unwrap());
        assert_eq!(
            PrivateKey::from_wif(&base58::encode_check(&payload)),
            Err(PrivateKeyError::UnknownVersion { version: 0x99 })
        );

        // The right version, but the payload is too short to be a key.
        let short = base58::encode_check(&[0x80, 0x01, 0x02]);
        assert_eq!(
            PrivateKey::from_wif(&short),
            Err(PrivateKeyError::WifLength { got: 2 })
        );

        // Thirty-four bytes whose flag byte is not 0x01.
        let mut wrong_flag = vec![0x80];
        wrong_flag.extend_from_slice(&hex::decode(KEY_HEX).unwrap());
        wrong_flag.push(0x02);
        assert_eq!(
            PrivateKey::from_wif(&base58::encode_check(&wrong_flag)),
            Err(PrivateKeyError::WifCompressionFlag { got: 0x02 })
        );
    }

    /// 3.1 asks for the key in binary, decimal and hex — which is exactly
    /// what `Number` already does, so the key only has to hand it over.
    #[test]
    fn renders_as_a_number_in_every_base() {
        let n = key(true).to_number();
        // Hex is the spelling the key was given in, minus the leading zero
        // nibble that a *value* does not carry.
        assert_eq!(
            n.to_base(Base::Hexadecimal),
            KEY_HEX.trim_start_matches('0')
        );
        assert_eq!(n.bits(), 252, "this key's top nibble is 0x0");
        // Binary and decimal are checked by round-tripping rather than by a
        // restated literal: each must read back as the same number.
        for base in [Base::Binary, Base::Decimal, Base::Hexadecimal] {
            let text = n.to_base(base);
            assert_eq!(Number::parse(&text, base).unwrap(), n, "{base}");
        }
        assert_eq!(n.to_binary().len(), 252);
        // The numeric view drops leading zero bytes; the field is still 32.
        assert_eq!(n.to_be_bytes_padded(32).unwrap().len(), 32);
        assert_eq!(
            hex::encode(&n.to_be_bytes_padded(32).unwrap()),
            KEY_HEX,
            "padding restores the 32-byte field"
        );
    }

    /// Generation is only compiled with the `rand` feature, so this test is
    /// too — otherwise a default `cargo test` would silently not cover it.
    #[cfg(feature = "rand")]
    #[test]
    fn generated_keys_are_valid_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let key = PrivateKey::generate(Network::Mainnet, true);
            // In range by construction — `from_be_bytes` is the only way in.
            assert!(PrivateKey::from_be_bytes(&key.to_be_bytes(), Network::Mainnet, true).is_ok());
            assert!(
                seen.insert(key.to_be_bytes()),
                "generated the same key twice"
            );
            // …and it round-trips as a WIF like any other key.
            assert_eq!(
                PrivateKey::from_wif(&key.to_wif()).unwrap().to_be_bytes(),
                key.to_be_bytes()
            );
        }
    }

    #[test]
    fn debug_does_not_leak_the_key() {
        let shown = format!("{:?}", key(true));
        assert!(!shown.contains("0c28"), "Debug leaked the key: {shown}");
        assert!(shown.contains("redacted"));
        assert!(
            shown.contains("Mainnet"),
            "the safe fields are still useful"
        );
    }
}
