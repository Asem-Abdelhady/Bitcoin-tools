//! Base58Check addresses, and the parts they are made of.
//!
//! P2PKH, which commits to a public key, and P2SH, which commits to a script.
//! Both are twenty bytes behind a version byte, which is why they share a type
//! — and why the witness addresses in [`segwit`](super::segwit) do not.
//!
//! `base58` here is [`encoding::base58`](crate::encoding::base58), the codec.
//! This module supplies the version bytes and the meaning; the codec supplies
//! the arithmetic and the checksum, and knows nothing about addresses.

use std::fmt;
use std::str::FromStr;

use crate::encoding::base58::{self, CHECKSUM_LEN};
use crate::hashes::Hash;
use crate::keys::address::AddressError;
use crate::network::Network;
use crate::parse::{display_serialize, name_table};

/// The digest a Base58 address commits to: twenty bytes of `HASH160`, either
/// of a public key or of a redeem script.
///
/// A named alias rather than a `HASH_SIZE` constant beside it — the width was
/// a second spelling of something `hash160` already implies, and this way the
/// type carries it.
pub type AddressHash = Hash<20>;

/// Which kind of thing a Base58 address commits to.
///
/// Two variants and no more: this enum's whole content is a version-byte
/// table, and a witness address has no version byte to put in it. That is what
/// [`AddressKind`](super::AddressKind) is for, one level up, where the answer
/// is allowed to be "a witness program of a version nobody has defined yet".
///
/// Deliberately *not* `#[non_exhaustive]`, for the same reason: an enum that
/// cannot grow should not make every caller's `match` carry a dead arm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Base58Kind {
    /// Pay to public key hash — `HASH160` of a public key.
    P2pkh,
    /// Pay to script hash — `HASH160` of a redeem script.
    P2sh,
}

name_table! {
    spelling Base58Kind {
        P2pkh => "p2pkh";
        P2sh => "p2sh";
    }
}

impl Base58Kind {
    /// The version byte this kind uses on `network`.
    ///
    /// These four numbers are why a mainnet P2PKH address starts with `1` and
    /// a P2SH one with `3`: Base58 has no fixed-width leading digit, so the
    /// version byte's value shows through as the first character.
    #[must_use]
    pub const fn version(self, network: Network) -> u8 {
        match (self, network.is_mainnet()) {
            (Base58Kind::P2pkh, true) => 0x00,
            (Base58Kind::P2pkh, false) => 0x6f,
            (Base58Kind::P2sh, true) => 0x05,
            (Base58Kind::P2sh, false) => 0xc4,
        }
    }

    /// The kind and network a version byte names, if any.
    #[must_use]
    pub const fn from_version(version: u8) -> Option<(Base58Kind, Network)> {
        match version {
            0x00 => Some((Base58Kind::P2pkh, Network::Mainnet)),
            0x05 => Some((Base58Kind::P2sh, Network::Mainnet)),
            // The three test networks share their version bytes, so the byte
            // cannot say which one it is. Testnet is the honest answer rather
            // than a guess between three.
            0x6f => Some((Base58Kind::P2pkh, Network::Testnet)),
            0xc4 => Some((Base58Kind::P2sh, Network::Testnet)),
            _ => None,
        }
    }
}

/// A Base58Check address: a version byte and twenty bytes of hash.
///
/// ```
/// use bitcoin_tools_core::keys::{Address, Base58Kind};
/// use bitcoin_tools_core::network::Network;
///
/// let address: Address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse()?;
/// let base58 = address.as_base58().expect("a 1… address is base58");
/// assert_eq!(base58.kind(), Base58Kind::P2pkh);
/// assert_eq!(address.network(), Network::Mainnet);
///
/// // The three fields the string is made of, which is the point of the tool.
/// let parts = base58.parts();
/// assert_eq!(parts.version, 0x00);
/// assert_eq!(parts.hash.to_hex(), "62e907b15cbf27d5425399ebf6f0fb50ebb88f18");
/// # Ok::<_, bitcoin_tools_core::keys::AddressError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Base58Address {
    kind: Base58Kind,
    hash: AddressHash,
    network: Network,
}

/// A Base58 address taken apart: the three fields a decoder should show.
///
/// This is what "split into prefix, hash, and checksum" means — the
/// point of the tool is that an address is not an opaque string, and the
/// checksum in particular is only interesting when you can see it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Base58Parts {
    /// The version byte, which names the kind and the network at once.
    pub version: u8,
    /// The twenty bytes being committed to.
    pub hash: AddressHash,
    /// The four checksum bytes the string carries.
    pub checksum: [u8; CHECKSUM_LEN],
}

impl Base58Address {
    /// An address paying to a public key hash.
    #[must_use]
    pub const fn p2pkh(hash: AddressHash, network: Network) -> Self {
        Base58Address {
            kind: Base58Kind::P2pkh,
            hash,
            network,
        }
    }

    /// An address paying to a script hash.
    #[must_use]
    pub const fn p2sh(hash: AddressHash, network: Network) -> Self {
        Base58Address {
            kind: Base58Kind::P2sh,
            hash,
            network,
        }
    }

    /// Whether this pays to a key hash or a script hash.
    #[must_use]
    pub const fn kind(&self) -> Base58Kind {
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
    pub fn parts(&self) -> Base58Parts {
        Base58Parts {
            version: self.version(),
            hash: self.hash,
            checksum: base58::checksum(&self.payload()),
        }
    }

    /// The `scriptPubKey` this address is a way of writing.
    ///
    /// `OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG` for P2PKH, and
    /// `OP_HASH160 <20> OP_EQUAL` for P2SH — the two templates
    /// [`ScriptKind`](crate::transactions::ScriptKind) recognises, written
    /// from the other end.
    #[must_use]
    pub fn script_pubkey(&self) -> Vec<u8> {
        let hash = self.hash.as_bytes();
        match self.kind {
            Base58Kind::P2pkh => {
                let mut script = vec![0x76, 0xa9, 0x14];
                script.extend_from_slice(hash);
                script.extend_from_slice(&[0x88, 0xac]);
                script
            }
            Base58Kind::P2sh => {
                let mut script = vec![0xa9, 0x14];
                script.extend_from_slice(hash);
                script.push(0x87);
                script
            }
        }
    }

    /// Read a Base58Check address, taking the kind and the network from the
    /// version byte.
    ///
    /// # Errors
    ///
    /// [`AddressError::Base58`] for a bad checksum or a stray character,
    /// [`AddressError::UnknownVersion`] for a version byte no kind uses, or
    /// [`AddressError::WrongLength`] for a payload that is not twenty bytes
    /// after the version.
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let payload = base58::decode_check(s)?;
        let (&version, hash) = payload
            .split_first()
            .ok_or(AddressError::WrongLength { got: 0 })?;
        let (kind, network) =
            Base58Kind::from_version(version).ok_or(AddressError::UnknownVersion { version })?;
        let hash = AddressHash::from_slice(hash)
            .map_err(|_| AddressError::WrongLength { got: hash.len() })?;
        Ok(Base58Address {
            kind,
            hash,
            network,
        })
    }
}

/// The Base58Check string.
impl fmt::Display for Base58Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&base58::encode_check(&self.payload()))
    }
}

impl FromStr for Base58Address {
    type Err = AddressError;

    /// See [`Base58Address::parse`]. Neither the kind nor the network is
    /// something the caller supplies, and neither is something they could
    /// override if they wanted to.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Base58Address::parse(s)
    }
}

display_serialize!(Base58Address);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base58::Base58Error;
    use crate::hex;

    fn hash_of(hex_str: &str) -> AddressHash {
        AddressHash::from_hex(hex_str).expect("a 20-byte hash in hex")
    }

    /// The most published address there is: the genesis coinbase output's key,
    /// hashed and encoded.
    #[test]
    fn produces_the_genesis_address() {
        let address = Base58Address::p2pkh(
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
            (Base58Kind::P2pkh, Network::Mainnet, '1'),
            (Base58Kind::P2sh, Network::Mainnet, '3'),
            (Base58Kind::P2pkh, Network::Testnet, 'm'),
            (Base58Kind::P2sh, Network::Testnet, '2'),
        ] {
            let address = match kind {
                Base58Kind::P2pkh => Base58Address::p2pkh(hash, network),
                Base58Kind::P2sh => Base58Address::p2sh(hash, network),
            };
            let text = address.to_string();
            let got = text.chars().next().unwrap();
            // Testnet P2PKH is the one that varies: `m` or `n`, because the
            // 0x6f version leaves the first character not quite pinned.
            let ok =
                got == first || (kind == Base58Kind::P2pkh && !network.is_mainnet() && got == 'n');
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
            for address in [
                Base58Address::p2pkh(hash, network),
                Base58Address::p2sh(hash, network),
            ] {
                let parsed: Base58Address = address.to_string().parse().unwrap();
                assert_eq!(parsed, address);
                assert_eq!(parsed.kind(), address.kind());
                assert_eq!(parsed.network(), address.network());
                assert_eq!(parsed.hash(), address.hash());
            }
        }
    }

    #[test]
    fn splits_into_version_hash_and_checksum() {
        let address = Base58Address::parse("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM").unwrap();
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

    /// An address is a way of writing a `scriptPubKey`, so it has to produce
    /// the template a decoder would classify it from.
    #[test]
    fn writes_the_script_it_stands_for() {
        let hash = hash_of("65ed366110a6fe3132cc1f63d73d3bb5a658797f");
        assert_eq!(
            hex::encode(&Base58Address::p2pkh(hash, Network::Mainnet).script_pubkey()),
            "76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac"
        );
        assert_eq!(
            hex::encode(&Base58Address::p2sh(hash, Network::Mainnet).script_pubkey()),
            "a91465ed366110a6fe3132cc1f63d73d3bb5a658797f87"
        );
        // The network changes the string, never the script.
        assert_eq!(
            Base58Address::p2pkh(hash, Network::Testnet).script_pubkey(),
            Base58Address::p2pkh(hash, Network::Mainnet).script_pubkey()
        );
    }

    #[test]
    fn rejects_what_is_not_an_address() {
        // A bad checksum.
        assert!(matches!(
            Base58Address::parse("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvN"),
            Err(AddressError::Base58(Base58Error::BadChecksum { .. }))
        ));
        // A version byte no base58 address kind uses.
        let mut payload = vec![0x99];
        payload.extend_from_slice(hash_of("010966776006953d5567439e5e39f86a0d273bee").as_bytes());
        assert_eq!(
            Base58Address::parse(&base58::encode_check(&payload)),
            Err(AddressError::UnknownVersion { version: 0x99 })
        );
        // The right version, the wrong payload size.
        let short = base58::encode_check(&[0x00, 0x01, 0x02]);
        assert_eq!(
            Base58Address::parse(&short),
            Err(AddressError::WrongLength { got: 2 })
        );
    }

    #[test]
    fn every_version_byte_maps_back_to_the_kind_that_made_it() {
        for kind in [Base58Kind::P2pkh, Base58Kind::P2sh] {
            for network in [Network::Mainnet, Network::Testnet] {
                let version = kind.version(network);
                assert_eq!(
                    Base58Kind::from_version(version),
                    Some((kind, network)),
                    "{kind:?} on {network}"
                );
            }
        }
        assert_eq!(Base58Kind::from_version(0x99), None);
    }

    /// The test networks share version bytes, so a parsed testnet address
    /// cannot claim to know which of the three it came from.
    #[test]
    fn the_test_networks_are_indistinguishable_by_version() {
        let hash = hash_of("010966776006953d5567439e5e39f86a0d273bee");
        let signet = Base58Address::p2pkh(hash, Network::Signet).to_string();
        let regtest = Base58Address::p2pkh(hash, Network::Regtest).to_string();
        assert_eq!(signet, regtest, "the byte does not carry the difference");
        assert_eq!(
            Base58Address::parse(&signet).unwrap().network(),
            Network::Testnet,
            "so parsing reports testnet rather than guessing"
        );
    }

    #[test]
    fn display_honours_width() {
        let address = Base58Address::p2pkh(hash_of(&"00".repeat(20)), Network::Mainnet);
        let text = address.to_string();
        assert_eq!(format!("{address:>40}"), format!("{:>40}", text));
    }
}
