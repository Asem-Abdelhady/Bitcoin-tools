//! § 3.2 — Base58Check addresses, and the parts they are made of.
//!
//! Only the Base58 address types live here: P2PKH, which commits to a public
//! key, and P2SH, which commits to a script. The witness types (P2WPKH, P2WSH,
//! P2TR) are Bech32 and land with `encoding/bech32.rs`.

use std::fmt;
use std::str::FromStr;

use crate::encoding::base58::{self, Base58Error, CHECKSUM_LEN};
use crate::hashes::Hash;
use crate::network::Network;

/// The digest a Base58 address commits to: twenty bytes of `HASH160`, either
/// of a public key or of a redeem script.
///
/// A named alias rather than a `HASH_SIZE` constant beside it — the width was
/// a second spelling of something `hash160` already implies, and this way the
/// type carries it.
pub type AddressHash = Hash<20>;

/// Which kind of thing an address commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum AddressKind {
    /// Pay to public key hash — `HASH160` of a public key.
    P2pkh,
    /// Pay to script hash — `HASH160` of a redeem script.
    P2sh,
}

impl AddressKind {
    /// The version byte this kind uses on `network`.
    ///
    /// These four numbers are why a mainnet P2PKH address starts with `1` and
    /// a P2SH one with `3`: Base58 has no fixed-width leading digit, so the
    /// version byte's value shows through as the first character.
    #[must_use]
    pub const fn version(self, network: Network) -> u8 {
        match (self, network.is_mainnet()) {
            (AddressKind::P2pkh, true) => 0x00,
            (AddressKind::P2pkh, false) => 0x6f,
            (AddressKind::P2sh, true) => 0x05,
            (AddressKind::P2sh, false) => 0xc4,
        }
    }

    /// The kind and network a version byte names, if any.
    #[must_use]
    pub const fn from_version(version: u8) -> Option<(AddressKind, Network)> {
        match version {
            0x00 => Some((AddressKind::P2pkh, Network::Mainnet)),
            0x05 => Some((AddressKind::P2sh, Network::Mainnet)),
            // The three test networks share their version bytes, so the byte
            // cannot say which one it is. Testnet is the honest answer rather
            // than a guess between three.
            0x6f => Some((AddressKind::P2pkh, Network::Testnet)),
            0xc4 => Some((AddressKind::P2sh, Network::Testnet)),
            _ => None,
        }
    }
}

/// A Base58Check address.
///
/// ```
/// use bitcoin_tools_core::keys::{Address, AddressKind};
/// use bitcoin_tools_core::{hex, network::Network};
///
/// let address: Address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse()?;
/// assert_eq!(address.kind(), AddressKind::P2pkh);
/// assert_eq!(address.network(), Network::Mainnet);
///
/// // The three fields the string is made of, which is the point of the tool.
/// let parts = address.parts();
/// assert_eq!(parts.version, 0x00);
/// assert_eq!(parts.hash.to_hex(), "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
/// # Ok::<_, bitcoin_tools_core::keys::AddressError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Address {
    kind: AddressKind,
    hash: AddressHash,
    network: Network,
}

/// An address taken apart: the three fields a decoder should show.
///
/// This is what 3.2 means by "split into prefix, hash, and checksum" — the
/// point of the tool is that an address is not an opaque string, and the
/// checksum in particular is only interesting when you can see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AddressParts {
    /// The version byte, which names the kind and the network at once.
    pub version: u8,
    /// The twenty bytes being committed to.
    pub hash: AddressHash,
    /// The four checksum bytes the string carries.
    pub checksum: [u8; CHECKSUM_LEN],
}

/// Why a string is not an address.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    /// Not valid Base58Check — bad character, too short, or a failed checksum.
    Base58(Base58Error),
    /// A version byte belonging to no address kind this crate knows. Witness
    /// addresses land here today because they are Bech32, not Base58.
    UnknownVersion {
        /// The version byte found.
        version: u8,
    },
    /// A payload of the wrong size. Every Base58 address is a version byte and
    /// exactly twenty hash bytes.
    WrongLength {
        /// Bytes after the version byte, where 20 were needed.
        got: usize,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Base58(e) => write!(f, "{e}"),
            AddressError::UnknownVersion { version } => {
                write!(f, "no base58 address kind uses version byte {version:#04x}")
            }
            AddressError::WrongLength { got } => write!(
                f,
                "an address payload is {} bytes after the version, got {got}",
                AddressHash::SIZE
            ),
        }
    }
}

impl std::error::Error for AddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AddressError::Base58(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Base58Error> for AddressError {
    fn from(e: Base58Error) -> Self {
        AddressError::Base58(e)
    }
}

impl Address {
    /// An address paying to a public key hash.
    #[must_use]
    pub const fn p2pkh(hash: AddressHash, network: Network) -> Self {
        Address {
            kind: AddressKind::P2pkh,
            hash,
            network,
        }
    }

    /// An address paying to a script hash.
    #[must_use]
    pub const fn p2sh(hash: AddressHash, network: Network) -> Self {
        Address {
            kind: AddressKind::P2sh,
            hash,
            network,
        }
    }

    /// Whether this pays to a key hash or a script hash.
    #[must_use]
    pub const fn kind(&self) -> AddressKind {
        self.kind
    }

    /// The network its version byte names. Always [`Network::Testnet`] for a
    /// parsed test-network address — the byte does not distinguish the three.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// The twenty bytes this address commits to.
    #[must_use]
    pub const fn hash(&self) -> AddressHash {
        self.hash
    }

    /// The version byte this address encodes with.
    #[must_use]
    pub const fn version(&self) -> u8 {
        self.kind.version(self.network)
    }

    /// The bytes Base58Check runs over: the version byte, then the hash.
    /// Shared with [`Display`](fmt::Display) so the layout is written once.
    fn payload(&self) -> Vec<u8> {
        let mut payload = Vec::with_capacity(1 + AddressHash::SIZE);
        payload.push(self.version());
        payload.extend_from_slice(self.hash.as_bytes());
        payload
    }

    /// The address broken into version, hash and checksum.
    ///
    /// Computed rather than remembered from a parse, so an address built in
    /// code shows the same three fields as one that was read in — and taken
    /// from the checksum function directly rather than by encoding and
    /// re-decoding, so there is no error path here to invent a value for.
    #[must_use]
    pub fn parts(&self) -> AddressParts {
        AddressParts {
            version: self.version(),
            hash: self.hash,
            checksum: base58::checksum(&self.payload()),
        }
    }
}

/// The Base58Check string.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&base58::encode_check(&self.payload()))
    }
}

impl FromStr for Address {
    type Err = AddressError;

    /// Reads a Base58Check address, taking the kind and the network from the
    /// version byte — neither is something the caller has to supply, and
    /// neither is something they could override if they wanted to.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let payload = base58::decode_check(s)?;
        let (&version, hash) = payload
            .split_first()
            .ok_or(AddressError::WrongLength { got: 0 })?;
        let (kind, network) =
            AddressKind::from_version(version).ok_or(AddressError::UnknownVersion { version })?;
        let hash = AddressHash::from_slice(hash)
            .map_err(|_| AddressError::WrongLength { got: hash.len() })?;
        Ok(Address {
            kind,
            hash,
            network,
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Address {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_of(hex_str: &str) -> AddressHash {
        AddressHash::from_hex(hex_str).expect("a 20-byte hash in hex")
    }

    /// The most published address there is: the genesis coinbase output's key,
    /// hashed and encoded.
    #[test]
    fn produces_the_genesis_address() {
        let address = Address::p2pkh(
            hash_of("62e907b15cbf27d5425399ebf6f0fb50ebb88f18"),
            Network::Mainnet,
        );
        assert_eq!(address.to_string(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    }

    /// The version byte shows through as the leading character, which is the
    /// one thing everybody knows about Bitcoin addresses.
    #[test]
    fn the_version_byte_decides_the_leading_character() {
        let hash = hash_of("62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
        for (kind, network, first) in [
            (AddressKind::P2pkh, Network::Mainnet, '1'),
            (AddressKind::P2sh, Network::Mainnet, '3'),
            (AddressKind::P2pkh, Network::Testnet, 'm'),
            (AddressKind::P2sh, Network::Testnet, '2'),
        ] {
            let address = match kind {
                AddressKind::P2pkh => Address::p2pkh(hash, network),
                AddressKind::P2sh => Address::p2sh(hash, network),
            };
            let text = address.to_string();
            let got = text.chars().next().unwrap();
            // Testnet P2PKH is the one that varies: `m` or `n`, because the
            // 0x6f version leaves the first character not quite pinned.
            let ok =
                got == first || (kind == AddressKind::P2pkh && !network.is_mainnet() && got == 'n');
            assert!(
                ok,
                "{kind:?} on {network} started with {got}, wanted {first}"
            );
        }
    }

    #[test]
    fn round_trips_through_its_string_form() {
        let hash = hash_of("010966776006953d5567439e5e39f86a0d273bee");
        for network in [Network::Mainnet, Network::Testnet] {
            for address in [Address::p2pkh(hash, network), Address::p2sh(hash, network)] {
                let parsed: Address = address.to_string().parse().unwrap();
                assert_eq!(parsed, address);
                assert_eq!(parsed.kind(), address.kind());
                assert_eq!(parsed.network(), address.network());
                assert_eq!(parsed.hash(), address.hash());
            }
        }
    }

    #[test]
    fn splits_into_version_hash_and_checksum() {
        let address: Address = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM".parse().unwrap();
        let parts = address.parts();
        assert_eq!(parts.version, 0x00);
        assert_eq!(
            parts.hash.to_hex(),
            "010966776006953d5567439e5e39f86a0d273bee"
        );
        // The checksum is the first four bytes of hash256 over version||hash,
        // which the base58 layer computed — this asserts they agree.
        let mut payload = vec![parts.version];
        payload.extend_from_slice(parts.hash.as_bytes());
        assert_eq!(parts.checksum, base58::checksum(&payload));
        // …and that is the same value the encoder puts in the string.
        let encoded = base58::decode_check_parts(&base58::encode_check(&payload)).unwrap();
        assert_eq!(parts.checksum, encoded.checksum);
        assert!(encoded.is_valid());
    }

    #[test]
    fn rejects_what_is_not_an_address() {
        // A bad checksum.
        assert!(matches!(
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN".parse::<Address>(),
            Err(AddressError::Base58(Base58Error::BadChecksum { .. }))
        ));
        // A version byte no base58 address kind uses.
        let mut payload = vec![0x99];
        payload.extend_from_slice(hash_of("010966776006953d5567439e5e39f86a0d273bee").as_bytes());
        assert_eq!(
            base58::encode_check(&payload).parse::<Address>(),
            Err(AddressError::UnknownVersion { version: 0x99 })
        );
        // The right version, the wrong payload size.
        let short = base58::encode_check(&[0x00, 0x01, 0x02]);
        assert_eq!(
            short.parse::<Address>(),
            Err(AddressError::WrongLength { got: 2 })
        );
    }

    #[test]
    fn every_version_byte_maps_back_to_the_kind_that_made_it() {
        for kind in [AddressKind::P2pkh, AddressKind::P2sh] {
            for network in [Network::Mainnet, Network::Testnet] {
                let version = kind.version(network);
                assert_eq!(
                    AddressKind::from_version(version),
                    Some((kind, network)),
                    "{kind:?} on {network}"
                );
            }
        }
        assert_eq!(AddressKind::from_version(0x99), None);
    }

    /// The test networks share version bytes, so a parsed testnet address
    /// cannot claim to know which of the three it came from.
    #[test]
    fn the_test_networks_are_indistinguishable_by_version() {
        let hash = hash_of("010966776006953d5567439e5e39f86a0d273bee");
        let signet = Address::p2pkh(hash, Network::Signet).to_string();
        let regtest = Address::p2pkh(hash, Network::Regtest).to_string();
        assert_eq!(signet, regtest, "the byte does not carry the difference");
        assert_eq!(
            signet.parse::<Address>().unwrap().network(),
            Network::Testnet,
            "so parsing reports testnet rather than guessing"
        );
    }

    #[test]
    fn display_honours_width() {
        let address = Address::p2pkh(hash_of(&"00".repeat(20)), Network::Mainnet);
        let text = address.to_string();
        assert_eq!(format!("{address:>40}"), format!("{:>40}", text));
    }
}
