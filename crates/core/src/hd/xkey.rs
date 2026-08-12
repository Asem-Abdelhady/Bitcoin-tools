//! § 4.2 — BIP32 extended keys.
//!
//! An extended key is a key plus a chain code: 256 extra bits that are mixed
//! into every child derivation. Without them, knowing a parent key and a child
//! index would be enough to compute the child — the chain code is what makes a
//! subtree unguessable from outside.
//!
//! The two types here are the same eight fields with one difference, and that
//! difference is the whole of what BIP32 is for: [`Xpriv`] can derive hardened
//! children and [`Xpub`] cannot, so an xpub can be handed to a watch-only
//! wallet that generates addresses forever and learns nothing.

use std::fmt;
use std::str::FromStr;

use crate::crypto::secp::{
    COMPRESSED_SIZE, Point, PointError, SCALAR_SIZE, ScalarError, SecretScalar, TweakError,
};
use crate::encoding::base58::{self, Base58Error};
use crate::hashes::hmac_sha512;
use crate::hd::path::{ChildNumber, DerivationPath, MAX_DEPTH};
use crate::hex::{self, HexError};
use crate::keys::{AddressHash, PrivateKey, PublicKey};
use crate::network::Network;

/// Bytes in a chain code.
pub const CHAIN_CODE_SIZE: usize = 32;

/// Bytes in a key's fingerprint — the first four of its identifier.
pub const FINGERPRINT_SIZE: usize = 4;

/// Bytes in the serialized form, before Base58Check.
///
/// Four of version, one of depth, four of parent fingerprint, four of child
/// number, thirty-two of chain code and thirty-three of key.
pub const SERIALIZED_SIZE: usize =
    VERSION_SIZE + 1 + FINGERPRINT_SIZE + CHILD_NUMBER_SIZE + CHAIN_CODE_SIZE + COMPRESSED_SIZE;

/// Bytes of version prefix.
pub const VERSION_SIZE: usize = 4;

/// Bytes of child number — a big-endian `u32`.
pub const CHILD_NUMBER_SIZE: usize = 4;

/// Bytes hashed at each derivation step: a 33-byte key and a child number.
const DERIVATION_INPUT_SIZE: usize = COMPRESSED_SIZE + CHILD_NUMBER_SIZE;

/// Shortest seed BIP32 accepts: 128 bits.
pub const MIN_SEED_SIZE: usize = 16;

/// Longest seed BIP32 accepts: 512 bits, which is what BIP39 produces.
pub const MAX_SEED_SIZE: usize = 64;

/// The HMAC key for master generation.
///
/// A fixed string, and the reason a Bitcoin master key and a master key for
/// some other chain differ even from the same seed. It is the domain
/// separation for the whole tree.
pub const MASTER_KEY: &[u8] = b"Bitcoin seed";

/// `xprv` on mainnet.
const VERSION_PRIVATE_MAIN: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
/// `xpub` on mainnet.
const VERSION_PUBLIC_MAIN: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
/// `tprv` on the test networks.
const VERSION_PRIVATE_TEST: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
/// `tpub` on the test networks.
const VERSION_PUBLIC_TEST: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];

/// The 256 bits mixed into every derivation below a key.
///
/// Not a [`Hash`](crate::hashes::Hash): it is not a digest of anything — it is
/// half of an HMAC output being used as a key. Giving it its own type keeps it
/// from being passed where a hash is wanted, which is the mistake worth making
/// impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainCode([u8; CHAIN_CODE_SIZE]);

impl ChainCode {
    /// Wrap 32 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; CHAIN_CODE_SIZE]) -> Self {
        ChainCode(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; CHAIN_CODE_SIZE] {
        self.0
    }

    /// The bytes, borrowed.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CHAIN_CODE_SIZE] {
        &self.0
    }

    /// Read 32 bytes of hex.
    ///
    /// # Errors
    ///
    /// [`Bip32Error::Hex`] for bad hex, [`Bip32Error::WrongLength`] for any
    /// length but 32.
    pub fn from_hex(s: &str) -> Result<Self, Bip32Error> {
        let bytes = hex::decode(hex::normalize(s))?;
        let array: [u8; CHAIN_CODE_SIZE] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Bip32Error::WrongLength { got: bytes.len() })?;
        Ok(ChainCode(array))
    }
}

impl fmt::Display for ChainCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

/// Hex, as [`Display`](fmt::Display) gives it. A chain code belonging to an
/// *xpub* is not a secret — it is already inside the string — and rendering it
/// is what a tool showing an extended key's fields does.
#[cfg(feature = "serde")]
impl serde::Serialize for ChainCode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// The first four bytes of a key's identifier, used to point at its parent.
///
/// Four bytes collide, and BIP32 says so: this is a hint for finding a parent
/// among keys you already have, never a proof that you found the right one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; FINGERPRINT_SIZE]);

impl Fingerprint {
    /// The master key's parent fingerprint: four zero bytes, because it has no
    /// parent.
    pub const MASTER: Fingerprint = Fingerprint([0; FINGERPRINT_SIZE]);

    /// Wrap four bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; FINGERPRINT_SIZE]) -> Self {
        Fingerprint(bytes)
    }

    /// The bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; FINGERPRINT_SIZE] {
        self.0
    }

    /// The first four bytes of an identifier.
    #[must_use]
    pub fn from_identifier(identifier: AddressHash) -> Self {
        let mut bytes = [0u8; FINGERPRINT_SIZE];
        bytes.copy_from_slice(&identifier.as_bytes()[..FINGERPRINT_SIZE]);
        Fingerprint(bytes)
    }

    /// Whether this is [`Fingerprint::MASTER`].
    #[must_use]
    pub fn is_master(self) -> bool {
        self == Fingerprint::MASTER
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

/// Hex, as [`Display`](fmt::Display) gives it.
#[cfg(feature = "serde")]
impl serde::Serialize for Fingerprint {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// Why an extended key could not be built, derived or read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Bip32Error {
    /// A seed outside 16 to 64 bytes. The floor is a security limit, not an
    /// encoding one: a shorter seed makes the whole tree brute-forceable.
    SeedLength {
        /// Bytes supplied.
        got: usize,
    },
    /// Not hex, or an odd number of digits.
    Hex(HexError),
    /// The string is not valid Base58Check.
    Base58(Base58Error),
    /// A payload that is not [`SERIALIZED_SIZE`] bytes.
    WrongLength {
        /// Bytes decoded.
        got: usize,
    },
    /// Four version bytes belonging to no network and neither key type.
    ///
    /// SLIP-132's `ypub`/`zpub` land here on purpose — see
    /// [`hd`](crate::hd) for why this crate does not read them.
    UnknownVersion {
        /// The four bytes found.
        version: [u8; 4],
    },
    /// The version bytes name the other kind of key: an `xpub` handed to
    /// [`Xpriv::parse`], or the reverse.
    ///
    /// Distinct from the two prefix errors below, which are about byte 45.
    /// BIP32's invalid-key list has vectors for both, and collapsing them
    /// produces the message "a private extended key must begin 0x00, got
    /// 0x00" for a payload that begins with exactly that.
    WrongKeyType {
        /// The version this parser required.
        expected: [u8; 4],
        /// The version the string carried.
        found: [u8; 4],
    },
    /// A private key's 33 bytes must begin with `0x00`. Anything else is
    /// either a public key wearing a private version, or corruption.
    PrivatePrefix {
        /// The byte found.
        found: u8,
    },
    /// A public key's 33 bytes must begin with `0x02` or `0x03`. `0x04` is a
    /// real SEC1 prefix but introduces 65 bytes, which do not fit here.
    PublicPrefix {
        /// The byte found.
        found: u8,
    },
    /// A key at depth 0 carrying a parent fingerprint. It has no parent.
    RootWithParent {
        /// The fingerprint found where zeros were required.
        fingerprint: Fingerprint,
    },
    /// A key at depth 0 carrying a child number. It is not a child.
    RootWithIndex {
        /// The child number found where zero was required.
        child: ChildNumber,
    },
    /// The scalar in a private key is zero or at or above the group order.
    Scalar(ScalarError),
    /// The 33 bytes of a public key are not a point on the curve.
    Point(PointError),
    /// A hardened child was asked of a public key. That is not a limitation of
    /// this implementation — it is the property hardening exists to have.
    HardenedFromPublic {
        /// The child that cannot be derived.
        child: ChildNumber,
    },
    /// The derived child is not a valid key.
    ///
    /// BIP32's answer is to move to the next index, and that is the caller's
    /// decision rather than this function's: silently returning child `i + 1`
    /// under the name `i` would put a key at a path it does not belong to.
    /// The chance is about 2⁻¹²⁷.
    InvalidChild {
        /// The child that could not be derived.
        child: ChildNumber,
        /// What the arithmetic said.
        reason: TweakError,
    },
    /// Deriving past depth 255, which has no serialization.
    TooDeep,
}

impl fmt::Display for Bip32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bip32Error::SeedLength { got } => write!(
                f,
                "a seed is {MIN_SEED_SIZE} to {MAX_SEED_SIZE} bytes, got {got}"
            ),
            Bip32Error::Hex(e) => write!(f, "{e}"),
            Bip32Error::Base58(e) => write!(f, "{e}"),
            Bip32Error::WrongLength { got } => {
                write!(f, "an extended key is {SERIALIZED_SIZE} bytes, got {got}")
            }
            Bip32Error::UnknownVersion { version } => write!(
                f,
                "no network uses the extended key version {}",
                hex::encode(version)
            ),
            Bip32Error::WrongKeyType { expected, found } => write!(
                f,
                "these are {} version bytes, not the {} this reads",
                hex::encode(found),
                hex::encode(expected)
            ),
            Bip32Error::PrivatePrefix { found } => write!(
                f,
                "a private extended key must begin 0x00, got {found:#04x}"
            ),
            Bip32Error::PublicPrefix { found } => write!(
                f,
                "a public extended key must begin 0x02 or 0x03, got {found:#04x}"
            ),
            Bip32Error::RootWithParent { fingerprint } => write!(
                f,
                "a key at depth 0 has no parent, but carries the fingerprint {fingerprint}"
            ),
            Bip32Error::RootWithIndex { child } => write!(
                f,
                "a key at depth 0 is not a child, but carries the index {child}"
            ),
            Bip32Error::Scalar(e) => write!(f, "{e}"),
            Bip32Error::Point(e) => write!(f, "{e}"),
            Bip32Error::HardenedFromPublic { child } => write!(
                f,
                "{child} is hardened, so only a private key can derive it"
            ),
            Bip32Error::InvalidChild { child, reason } => {
                write!(f, "child {child} is not a valid key: {reason}")
            }
            Bip32Error::TooDeep => {
                write!(f, "a key deeper than {MAX_DEPTH} has no serialization")
            }
        }
    }
}

impl std::error::Error for Bip32Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Bip32Error::Hex(e) => Some(e),
            Bip32Error::Base58(e) => Some(e),
            Bip32Error::Scalar(e) => Some(e),
            Bip32Error::Point(e) => Some(e),
            Bip32Error::InvalidChild { reason, .. } => Some(reason),
            _ => None,
        }
    }
}

impl From<HexError> for Bip32Error {
    fn from(e: HexError) -> Self {
        Bip32Error::Hex(e)
    }
}

impl From<Base58Error> for Bip32Error {
    fn from(e: Base58Error) -> Self {
        Bip32Error::Base58(e)
    }
}

impl From<ScalarError> for Bip32Error {
    fn from(e: ScalarError) -> Self {
        Bip32Error::Scalar(e)
    }
}

impl From<PointError> for Bip32Error {
    fn from(e: PointError) -> Self {
        Bip32Error::Point(e)
    }
}

/// Everything a serialized key carries except the key itself.
///
/// Both types have these four fields and both serialize them the same way, so
/// they are named once. It is private: a caller wants
/// [`Xpriv::depth`] and friends, not a bag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Header {
    network: Network,
    depth: u8,
    parent_fingerprint: Fingerprint,
    child_number: ChildNumber,
    chain_code: ChainCode,
}

impl Header {
    /// The header of a master key: depth 0, no parent, no index.
    const fn master(network: Network, chain_code: ChainCode) -> Self {
        Header {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint::MASTER,
            child_number: ChildNumber::from_u32(0),
            chain_code,
        }
    }

    /// The header a child of `parent` gets.
    ///
    /// # Errors
    ///
    /// [`Bip32Error::TooDeep`] past depth 255.
    fn child(
        &self,
        parent_fingerprint: Fingerprint,
        child_number: ChildNumber,
        chain_code: ChainCode,
    ) -> Result<Self, Bip32Error> {
        Ok(Header {
            network: self.network,
            depth: self.depth.checked_add(1).ok_or(Bip32Error::TooDeep)?,
            parent_fingerprint,
            child_number,
            chain_code,
        })
    }

    /// The 78 bytes, given the version and the 33 key bytes.
    fn serialize(
        &self,
        version: [u8; VERSION_SIZE],
        key: &[u8; COMPRESSED_SIZE],
    ) -> [u8; SERIALIZED_SIZE] {
        let mut out = [0u8; SERIALIZED_SIZE];
        out[..4].copy_from_slice(&version);
        out[4] = self.depth;
        out[5..9].copy_from_slice(&self.parent_fingerprint.0);
        out[9..13].copy_from_slice(&self.child_number.to_u32().to_be_bytes());
        out[13..45].copy_from_slice(&self.chain_code.0);
        out[45..].copy_from_slice(key);
        out
    }

    /// Split a Base58Check payload into a header, its version and its key
    /// bytes, checking everything that does not depend on which type it is.
    fn parse(
        payload: &[u8],
    ) -> Result<([u8; VERSION_SIZE], Header, [u8; COMPRESSED_SIZE]), Bip32Error> {
        let payload: &[u8; SERIALIZED_SIZE] = payload
            .try_into()
            .map_err(|_| Bip32Error::WrongLength { got: payload.len() })?;

        let mut version = [0u8; 4];
        version.copy_from_slice(&payload[..4]);
        let depth = payload[4];

        let mut fingerprint = [0u8; FINGERPRINT_SIZE];
        fingerprint.copy_from_slice(&payload[5..9]);
        let parent_fingerprint = Fingerprint(fingerprint);

        let mut index = [0u8; 4];
        index.copy_from_slice(&payload[9..13]);
        let child_number = ChildNumber::from_u32(u32::from_be_bytes(index));

        let mut chain_code = [0u8; CHAIN_CODE_SIZE];
        chain_code.copy_from_slice(&payload[13..45]);

        let mut key = [0u8; COMPRESSED_SIZE];
        key.copy_from_slice(&payload[45..]);

        // A depth of zero means a master key, and a master key has no parent
        // and no index. A string claiming otherwise is not a key with odd
        // metadata — it is a key whose path cannot be true, and BIP32's own
        // invalid-vector list names both spellings of it.
        if depth == 0 {
            if !parent_fingerprint.is_master() {
                return Err(Bip32Error::RootWithParent {
                    fingerprint: parent_fingerprint,
                });
            }
            if child_number.to_u32() != 0 {
                return Err(Bip32Error::RootWithIndex {
                    child: child_number,
                });
            }
        }

        let network = network_for_version(version).ok_or(Bip32Error::UnknownVersion { version })?;

        Ok((
            version,
            Header {
                network,
                depth,
                parent_fingerprint,
                child_number,
                chain_code: ChainCode(chain_code),
            },
            key,
        ))
    }
}

/// Which network a version belongs to, if this crate knows it.
const fn network_for_version(version: [u8; 4]) -> Option<Network> {
    match version {
        VERSION_PRIVATE_MAIN | VERSION_PUBLIC_MAIN => Some(Network::Mainnet),
        // The test networks share one pair, so a `tprv` cannot say which of
        // the three it is — the same collapse as WIF and the address version
        // bytes.
        VERSION_PRIVATE_TEST | VERSION_PUBLIC_TEST => Some(Network::Testnet),
        _ => None,
    }
}

/// An extended private key.
///
/// # It is a secret, and is treated like one
///
/// No [`Display`](fmt::Display), a redacting [`Debug`](fmt::Debug), no
/// `Serialize`. Getting the string out means naming
/// [`Xpriv::to_base58`]. That is exactly the shape
/// [`PrivateKey`] has, for exactly the same reason — and an xprv is worse than
/// a private key, because it is *every* private key below it.
///
/// ```
/// use bitcoin_tools_core::hd::{DerivationPath, Xpriv};
/// use bitcoin_tools_core::network::Network;
///
/// // BIP32's first test vector.
/// let seed = bitcoin_tools_core::hex::decode("000102030405060708090a0b0c0d0e0f")?;
/// let master = Xpriv::new_master(&seed, Network::Mainnet)?;
/// assert_eq!(master.depth(), 0);
///
/// let child = master.derive_path(&"m/0'/1".parse::<DerivationPath>()?)?;
/// assert_eq!(child.depth(), 2);
/// assert_eq!(
///     child.to_xpub().to_string(),
///     "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Xpriv {
    header: Header,
    scalar: SecretScalar,
}

/// An extended public key.
///
/// Derives every non-hardened descendant of itself and no hardened one, which
/// is what makes it safe to hand to a watch-only wallet.
///
/// ```
/// use bitcoin_tools_core::hd::{DerivationPath, Xpub};
///
/// // An account xpub, as a wallet would export it.
/// let account: Xpub = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ".parse()?;
/// assert_eq!(account.depth(), 2);
///
/// // It generates addresses forever…
/// let receiving = account.derive_child("0".parse()?)?;
/// assert!(receiving.public_key().p2wpkh_address(account.network())?.is_segwit());
///
/// // …and cannot reach a hardened index, which is the whole point of handing
/// // one out.
/// assert!(account.derive_child("0'".parse()?).is_err());
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Xpub {
    header: Header,
    point: Point,
}

impl Xpriv {
    /// The master key for a seed.
    ///
    /// `HMAC-SHA512("Bitcoin seed", seed)`, split in half: the left half is
    /// the key and the right half is the chain code. This is where a wallet
    /// begins, and where BIP39 hands over.
    ///
    /// # Errors
    ///
    /// [`Bip32Error::SeedLength`] outside 16 to 64 bytes, or
    /// [`Bip32Error::Scalar`] in the case BIP32 calls "the master key is
    /// invalid" — a left half that is zero or past the group order, with
    /// probability about 2⁻¹²⁷.
    pub fn new_master(seed: &[u8], network: Network) -> Result<Self, Bip32Error> {
        if !(MIN_SEED_SIZE..=MAX_SEED_SIZE).contains(&seed.len()) {
            return Err(Bip32Error::SeedLength { got: seed.len() });
        }
        let (scalar, chain_code) = split(&hmac_sha512(MASTER_KEY, seed))?;
        Ok(Xpriv {
            header: Header::master(network, chain_code),
            scalar,
        })
    }

    /// The network this key's version bytes name.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.header.network
    }

    /// How many derivations from the master this key is.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.header.depth
    }

    /// The first four bytes of the parent's identifier, or zeros at the root.
    #[must_use]
    pub const fn parent_fingerprint(&self) -> Fingerprint {
        self.header.parent_fingerprint
    }

    /// The index this key was derived at, or zero at the root.
    #[must_use]
    pub const fn child_number(&self) -> ChildNumber {
        self.header.child_number
    }

    /// The chain code.
    #[must_use]
    pub const fn chain_code(&self) -> ChainCode {
        self.header.chain_code
    }

    /// The scalar, for the layer below.
    #[must_use]
    pub const fn scalar(&self) -> &SecretScalar {
        &self.scalar
    }

    /// This key as an ordinary private key.
    ///
    /// Always compressed: BIP32 serializes public keys in 33 bytes and has no
    /// way to say otherwise, so every key in an HD tree is a compressed key.
    #[must_use]
    pub fn private_key(&self) -> PrivateKey {
        PrivateKey::from_scalar(self.scalar.clone(), self.header.network, true)
    }

    /// The matching extended public key.
    #[must_use]
    pub fn to_xpub(&self) -> Xpub {
        Xpub {
            header: self.header,
            point: self.scalar.public_point(),
        }
    }

    /// `HASH160` of the public key — what a fingerprint is the front of.
    #[must_use]
    pub fn identifier(&self) -> AddressHash {
        self.to_xpub().identifier()
    }

    /// The first four bytes of [`Xpriv::identifier`].
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_identifier(self.identifier())
    }

    /// Derive one child.
    ///
    /// Hardened children hash the *private* key and normal ones hash the
    /// public key — which is the entire difference, and why only this type can
    /// do both.
    ///
    /// # Errors
    ///
    /// [`Bip32Error::TooDeep`] past depth 255, or
    /// [`Bip32Error::InvalidChild`] in the vanishing case where the
    /// arithmetic lands outside the valid range.
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Bip32Error> {
        let mut data = [0u8; DERIVATION_INPUT_SIZE];
        if child.is_hardened() {
            // A leading zero byte pads the 32-byte secret to the 33 bytes a
            // public key would have occupied, so the two cases hash inputs of
            // the same length.
            data[1..COMPRESSED_SIZE].copy_from_slice(&self.scalar.to_be_bytes());
        } else {
            data[..COMPRESSED_SIZE].copy_from_slice(&self.scalar.public_point().to_compressed());
        }
        data[COMPRESSED_SIZE..].copy_from_slice(&child.to_u32().to_be_bytes());

        let digest = hmac_sha512(self.header.chain_code.as_bytes(), &data);
        let (tweak, chain_code) = split_halves(&digest);
        let scalar = self
            .scalar
            .add_tweak(&tweak)
            .map_err(|reason| Bip32Error::InvalidChild { child, reason })?;

        Ok(Xpriv {
            header: self.header.child(self.fingerprint(), child, chain_code)?,
            scalar,
        })
    }

    /// Derive every step of a path in order.
    ///
    /// # Errors
    ///
    /// Whatever [`Xpriv::derive_child`] returns, at the first step that fails.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Bip32Error> {
        let mut key = self.clone();
        for &child in path {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }

    /// The 78 bytes before Base58Check.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SERIALIZED_SIZE] {
        let mut key = [0u8; COMPRESSED_SIZE];
        key[1..].copy_from_slice(&self.scalar.to_be_bytes());
        self.header.serialize(private_version(self.network()), &key)
    }

    /// The `xprv…` string.
    ///
    /// Named rather than a [`Display`](fmt::Display) impl, so that printing
    /// the whole of a wallet has to be asked for — see the type's own note.
    #[must_use]
    pub fn to_base58(&self) -> String {
        base58::encode_check(&self.to_bytes())
    }

    /// Read an `xprv…` or `tprv…` string.
    ///
    /// # Errors
    ///
    /// Any [`Bip32Error`] that describes a malformed string: a bad checksum, a
    /// wrong length, an unknown version, a public version, a key byte that is
    /// not `0x00`, a scalar out of range, or metadata a root key cannot have.
    pub fn parse(s: &str) -> Result<Self, Bip32Error> {
        let (version, header, key) = Header::parse(&base58::decode_check(s)?)?;
        let expected = private_version(header.network);
        if version != expected {
            return Err(Bip32Error::WrongKeyType {
                expected,
                found: version,
            });
        }
        if key[0] != 0x00 {
            return Err(Bip32Error::PrivatePrefix { found: key[0] });
        }
        let mut scalar_bytes = [0u8; SCALAR_SIZE];
        scalar_bytes.copy_from_slice(&key[1..]);
        Ok(Xpriv {
            header,
            scalar: SecretScalar::from_be_bytes(&scalar_bytes)?,
        })
    }
}

impl Xpub {
    /// The network this key's version bytes name.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.header.network
    }

    /// How many derivations from the master this key is.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.header.depth
    }

    /// The first four bytes of the parent's identifier, or zeros at the root.
    #[must_use]
    pub const fn parent_fingerprint(&self) -> Fingerprint {
        self.header.parent_fingerprint
    }

    /// The index this key was derived at, or zero at the root.
    #[must_use]
    pub const fn child_number(&self) -> ChildNumber {
        self.header.child_number
    }

    /// The chain code.
    #[must_use]
    pub const fn chain_code(&self) -> ChainCode {
        self.header.chain_code
    }

    /// This key as an ordinary public key, compressed.
    #[must_use]
    pub const fn public_key(&self) -> PublicKey {
        PublicKey::new(self.point, true)
    }

    /// `HASH160` of the compressed public key.
    ///
    /// Asked of [`PublicKey`] rather than computed here: a key's identifier
    /// and its pubkey hash are the same twenty bytes under two names, and
    /// [`PublicKey::pubkey_hash`] already decides which serialization gets
    /// hashed. Two definitions of that would be two chances to hash the
    /// uncompressed form.
    #[must_use]
    pub fn identifier(&self) -> AddressHash {
        self.public_key().pubkey_hash()
    }

    /// The first four bytes of [`Xpub::identifier`].
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::from_identifier(self.identifier())
    }

    /// Derive one non-hardened child.
    ///
    /// # Errors
    ///
    /// [`Bip32Error::HardenedFromPublic`] for a hardened index — which is not
    /// a missing feature but the reason hardening exists —
    /// [`Bip32Error::TooDeep`] past depth 255, or
    /// [`Bip32Error::InvalidChild`].
    pub fn derive_child(&self, child: ChildNumber) -> Result<Self, Bip32Error> {
        if child.is_hardened() {
            return Err(Bip32Error::HardenedFromPublic { child });
        }
        let mut data = [0u8; DERIVATION_INPUT_SIZE];
        data[..COMPRESSED_SIZE].copy_from_slice(&self.point.to_compressed());
        data[COMPRESSED_SIZE..].copy_from_slice(&child.to_u32().to_be_bytes());

        let digest = hmac_sha512(self.header.chain_code.as_bytes(), &data);
        let (tweak, chain_code) = split_halves(&digest);
        let point = self
            .point
            .add_tweak(&tweak)
            .map_err(|reason| Bip32Error::InvalidChild { child, reason })?;

        Ok(Xpub {
            header: self.header.child(self.fingerprint(), child, chain_code)?,
            point,
        })
    }

    /// Derive every step of a path in order.
    ///
    /// # Errors
    ///
    /// Whatever [`Xpub::derive_child`] returns, at the first step that fails —
    /// including the first hardened step, if the path has one.
    pub fn derive_path(&self, path: &DerivationPath) -> Result<Self, Bip32Error> {
        let mut key = *self;
        for &child in path {
            key = key.derive_child(child)?;
        }
        Ok(key)
    }

    /// The 78 bytes before Base58Check.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SERIALIZED_SIZE] {
        self.header
            .serialize(public_version(self.network()), &self.point.to_compressed())
    }

    /// The `xpub…` string. Also this type's [`Display`](fmt::Display).
    #[must_use]
    pub fn to_base58(&self) -> String {
        base58::encode_check(&self.to_bytes())
    }

    /// Read an `xpub…` or `tpub…` string.
    ///
    /// # Errors
    ///
    /// Any [`Bip32Error`] that describes a malformed string — see
    /// [`Xpriv::parse`], with the key byte required to be `0x02` or `0x03`
    /// instead.
    pub fn parse(s: &str) -> Result<Self, Bip32Error> {
        let (version, header, key) = Header::parse(&base58::decode_check(s)?)?;
        let expected = public_version(header.network);
        if version != expected {
            return Err(Bip32Error::WrongKeyType {
                expected,
                found: version,
            });
        }
        if key[0] != 0x02 && key[0] != 0x03 {
            return Err(Bip32Error::PublicPrefix { found: key[0] });
        }
        Ok(Xpub {
            header,
            point: Point::from_sec1(&key)?,
        })
    }
}

/// The private version bytes for a network.
const fn private_version(network: Network) -> [u8; 4] {
    if network.is_mainnet() {
        VERSION_PRIVATE_MAIN
    } else {
        VERSION_PRIVATE_TEST
    }
}

/// The public version bytes for a network.
const fn public_version(network: Network) -> [u8; 4] {
    if network.is_mainnet() {
        VERSION_PUBLIC_MAIN
    } else {
        VERSION_PUBLIC_TEST
    }
}

/// Split an HMAC output into the two halves BIP32 uses: a tweak and a chain
/// code.
fn split_halves(digest: &[u8; 64]) -> ([u8; SCALAR_SIZE], ChainCode) {
    let mut left = [0u8; SCALAR_SIZE];
    let mut right = [0u8; CHAIN_CODE_SIZE];
    left.copy_from_slice(&digest[..SCALAR_SIZE]);
    right.copy_from_slice(&digest[SCALAR_SIZE..]);
    (left, ChainCode(right))
}

/// The same split, with the left half validated as a key — which is what
/// master generation needs and derivation does not, since derivation adds the
/// left half to the parent instead of using it directly.
fn split(digest: &[u8; 64]) -> Result<(SecretScalar, ChainCode), Bip32Error> {
    let (left, chain_code) = split_halves(digest);
    Ok((SecretScalar::from_be_bytes(&left)?, chain_code))
}

/// Redacted, like [`PrivateKey`]. The path metadata is safe and is what you
/// want when something is wrong.
impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("network", &self.header.network)
            .field("depth", &self.header.depth)
            .field("parent_fingerprint", &self.header.parent_fingerprint)
            .field("child_number", &self.header.child_number)
            .field("chain_code", &"<redacted>")
            .field("scalar", &"<redacted>")
            .finish()
    }
}

impl FromStr for Xpriv {
    type Err = Bip32Error;

    /// See [`Xpriv::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Xpriv::parse(s)
    }
}

impl fmt::Display for Xpub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.to_base58())
    }
}

impl FromStr for Xpub {
    type Err = Bip32Error;

    /// See [`Xpub::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Xpub::parse(s)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Xpub {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP32's first test vector seed.
    const SEED: &str = "000102030405060708090a0b0c0d0e0f";

    fn master() -> Xpriv {
        let seed = hex::decode(SEED).expect("valid hex");
        Xpriv::new_master(&seed, Network::Mainnet).expect("a valid master key")
    }

    /// The headline vector, checked in both directions at the root. The whole
    /// of the published set is in `tests/hd_vectors.rs`.
    #[test]
    fn reproduces_the_published_master_key() {
        let master = master();
        assert_eq!(
            master.to_base58(),
            "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
        );
        assert_eq!(
            master.to_xpub().to_string(),
            "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
        );
        assert_eq!(master.depth(), 0);
        assert!(master.parent_fingerprint().is_master());
        assert_eq!(master.child_number().to_u32(), 0);
    }

    /// The property BIP32 exists for: a public parent derives the same
    /// non-hardened child a private parent does.
    #[test]
    fn a_public_parent_derives_the_same_child_as_a_private_one() {
        let parent = master();
        let parent_pub = parent.to_xpub();

        for index in [0u32, 1, 2, 1_000_000_000, crate::hd::path::MAX_INDEX] {
            let child = ChildNumber::normal(index).expect("a normal index");
            let from_private = parent.derive_child(child).unwrap().to_xpub();
            let from_public = parent_pub.derive_child(child).unwrap();
            assert_eq!(from_private, from_public, "index {index}");
            assert_eq!(from_private.to_base58(), from_public.to_base58());
        }
    }

    /// …and cannot derive a hardened one. That is the point of hardening, not
    /// a gap in this implementation.
    #[test]
    fn a_public_parent_cannot_derive_a_hardened_child() {
        let child = ChildNumber::hardened(0).expect("a hardened index");
        assert_eq!(
            master().to_xpub().derive_child(child),
            Err(Bip32Error::HardenedFromPublic { child })
        );
        // …while a path containing one fails at that step and no earlier.
        let path: DerivationPath = "m/0/1/2'/3".parse().unwrap();
        assert!(matches!(
            master().to_xpub().derive_path(&path),
            Err(Bip32Error::HardenedFromPublic { .. })
        ));
        assert!(master().derive_path(&path).is_ok());
    }

    #[test]
    fn a_child_records_where_it_came_from() {
        let parent = master();
        let child_number = ChildNumber::hardened(44).unwrap();
        let child = parent.derive_child(child_number).unwrap();

        assert_eq!(child.depth(), 1);
        assert_eq!(child.child_number(), child_number);
        assert_eq!(child.parent_fingerprint(), parent.fingerprint());
        assert_ne!(child.chain_code(), parent.chain_code());
        // The fingerprint is the front of the identifier, which is HASH160 of
        // the public key.
        assert_eq!(
            parent.fingerprint().to_bytes(),
            parent.identifier().as_bytes()[..FINGERPRINT_SIZE]
        );
        assert_eq!(parent.identifier(), parent.to_xpub().identifier());
    }

    #[test]
    fn keys_round_trip_through_their_string_forms() {
        let path: DerivationPath = "m/44'/0'/0'/0/0".parse().unwrap();
        for network in [Network::Mainnet, Network::Testnet] {
            let seed = hex::decode(SEED).unwrap();
            let key = Xpriv::new_master(&seed, network)
                .unwrap()
                .derive_path(&path)
                .unwrap();

            let text = key.to_base58();
            assert_eq!(Xpriv::parse(&text).unwrap(), key);
            assert_eq!(text.parse::<Xpriv>().unwrap(), key);

            let xpub = key.to_xpub();
            assert_eq!(Xpub::parse(&xpub.to_string()).unwrap(), xpub);
            assert_eq!(key.to_bytes().len(), SERIALIZED_SIZE);

            // The prefixes everyone recognises, which follow from the version
            // bytes and the fixed 78-byte length.
            let (private_prefix, public_prefix) = if network.is_mainnet() {
                ("xprv", "xpub")
            } else {
                ("tprv", "tpub")
            };
            assert!(text.starts_with(private_prefix), "{text}");
            assert!(xpub.to_string().starts_with(public_prefix));
            assert_eq!(text.len(), 111, "an extended key is 111 characters");
        }
    }

    /// A seed is 128 to 512 bits. The floor is a security limit rather than an
    /// encoding one: a shorter seed makes the entire tree brute-forceable.
    #[test]
    fn rejects_a_seed_of_the_wrong_size() {
        for length in [0usize, 15, 65, 128] {
            assert_eq!(
                Xpriv::new_master(&vec![7; length], Network::Mainnet),
                Err(Bip32Error::SeedLength { got: length })
            );
        }
        for length in [MIN_SEED_SIZE, 32, MAX_SEED_SIZE] {
            assert!(Xpriv::new_master(&vec![7; length], Network::Mainnet).is_ok());
        }
    }

    /// Depth is one byte, so the 256th derivation has no serialization.
    #[test]
    fn refuses_to_derive_past_the_depth_a_byte_holds() {
        let mut key = master();
        let step = ChildNumber::normal(0).unwrap();
        for _ in 0..MAX_DEPTH {
            key = key.derive_child(step).expect("within a byte");
        }
        assert_eq!(key.depth(), 255);
        assert_eq!(key.derive_child(step), Err(Bip32Error::TooDeep));
        assert_eq!(key.to_xpub().derive_child(step), Err(Bip32Error::TooDeep));
    }

    /// The two types are the same eight fields, so reading one as the other
    /// has to fail on the version rather than on the bytes happening to fit.
    #[test]
    fn a_private_key_is_not_a_public_one() {
        let key = master();
        assert!(matches!(
            Xpub::parse(&key.to_base58()),
            Err(Bip32Error::WrongKeyType { .. })
        ));
        assert!(matches!(
            Xpriv::parse(&key.to_xpub().to_string()),
            Err(Bip32Error::WrongKeyType { .. })
        ));
        // …and the prefix errors stay about byte 45, where a payload carries
        // the right version and the wrong key byte.
        let mut payload = key.to_bytes();
        payload[45] = 0x01;
        assert_eq!(
            Xpriv::parse(&base58::encode_check(&payload)),
            Err(Bip32Error::PrivatePrefix { found: 0x01 })
        );
    }

    #[test]
    fn debug_does_not_leak_the_key() {
        let shown = format!("{:?}", master());
        assert!(!shown.contains("redacted\": false"));
        assert_eq!(shown.matches("<redacted>").count(), 2);
        assert!(
            shown.contains("Mainnet"),
            "the safe fields are still useful"
        );
        assert!(shown.contains("depth"));
    }

    /// A chain code is not a hash and does not print like one being reversed;
    /// it is 32 bytes shown forward.
    #[test]
    fn chain_codes_read_and_write_as_hex() {
        let code = master().chain_code();
        assert_eq!(code.to_string().len(), 64);
        assert_eq!(ChainCode::from_hex(&code.to_string()).unwrap(), code);
        assert!(matches!(
            ChainCode::from_hex("aabb"),
            Err(Bip32Error::WrongLength { got: 2 })
        ));
        assert!(matches!(ChainCode::from_hex("zz"), Err(Bip32Error::Hex(_))));
    }
}
