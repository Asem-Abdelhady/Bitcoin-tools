//! § 3.2 — Addresses.
//!
//! An address is a way of writing a `scriptPubKey` so a person can copy it.
//! Bitcoin has two ways of doing that and they have nothing in common: one is
//! a version byte and twenty bytes of hash in Base58Check, the other is a
//! witness version and a two-to-forty byte program in Bech32. So [`Address`]
//! is an enum over the two, and each arm keeps its own fields, its own parse
//! errors, and its own idea of what "the parts" are.
//!
//! ## This replaced a struct, on purpose
//!
//! [`keys`](crate::keys) recorded this break before writing it: the old
//! `Address` was a struct holding an [`AddressHash`] and a version byte, which
//! is exactly a Base58 address and nothing like a witness one. A 32-byte P2WSH
//! or P2TR program does not fit twenty bytes, and `version()` has no answer
//! for a bech32 address. Widening the struct would have meant a hash field
//! that is sometimes the wrong width and a version byte that is sometimes a
//! lie, so the struct became this enum and `version()`/`hash()` moved onto
//! [`Base58Address`], where they are always true.
//!
//! ## What is *not* here
//!
//! Neither arm knows how to build itself from a key — [`PublicKey`] does that,
//! because which hash goes in the program is a property of the key's
//! serialization rather than of the address format. And neither arm executes
//! or classifies a script: [`script_pubkey`](Address::script_pubkey) writes
//! the four templates an address stands for, and reading scripts back is
//! [`transactions::script`](crate::transactions::script) at L4.
//!
//! ## The `Parts` structs are not `Serialize`
//!
//! [`Base58Parts`] and [`SegwitParts`] carry raw bytes — a version byte, a
//! checksum, a witness program — and how those are rendered is a *transport*
//! decision, not a domain one. Deriving `Serialize` here would put an array of
//! numbers on the wire where every consumer wants hex, and the fix would then
//! live in this crate rather than in the caller that chose the format. The
//! value types a caller renders whole — [`Address`], [`AddressHash`],
//! [`AddressKind`] — do have it, because for those there is one right answer
//! and it is the string.
//!
//! [`PublicKey`]: crate::keys::PublicKey

pub mod base58;
pub mod segwit;

use std::fmt;
use std::str::FromStr;

use crate::encoding::base58::Base58Error;
use crate::encoding::bech32::{Bech32Error, SEPARATOR, Variant};
use crate::hashes::Hash;
use crate::network::Network;
use crate::parse::name_table;

pub use base58::{AddressHash, Base58Address, Base58Kind, Base58Parts};
pub use segwit::{SegwitAddress, SegwitParts, WitnessVersion};

/// A Bitcoin address, in either of the two formats.
///
/// ```
/// use bitcoin_tools_core::keys::{Address, AddressKind};
/// use bitcoin_tools_core::network::Network;
///
/// // The two formats parse through the same entry point, and each says what
/// // it is rather than being asked.
/// let legacy: Address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa".parse()?;
/// let witness: Address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".parse()?;
///
/// assert_eq!(legacy.kind(), Some(AddressKind::P2pkh));
/// assert_eq!(witness.kind(), Some(AddressKind::P2wpkh));
/// assert_eq!(witness.network(), Network::Mainnet);
/// assert!(!legacy.is_segwit() && witness.is_segwit());
/// # Ok::<_, bitcoin_tools_core::keys::AddressError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Address {
    /// P2PKH or P2SH, written in Base58Check.
    Base58(Base58Address),
    /// A witness program, written in Bech32 or Bech32m.
    Segwit(SegwitAddress),
}

/// What an address pays to, when that is something Bitcoin has defined.
///
/// [`Address::kind`] returns an `Option` of this, and `None` is not an error:
/// a witness program at a version nobody has assigned a meaning to is a valid
/// address that this enum has no name for, and BIP350 is explicit that such an
/// address must still be payable. Naming it would mean inventing a meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum AddressKind {
    /// Pay to public key hash.
    P2pkh,
    /// Pay to script hash — including the P2SH-wrapped witness programs BIP49
    /// uses, which are P2SH addresses and nothing else from outside.
    P2sh,
    /// Pay to witness public key hash: version 0, twenty bytes.
    P2wpkh,
    /// Pay to witness script hash: version 0, thirty-two bytes.
    P2wsh,
    /// Pay to taproot: version 1, thirty-two bytes.
    P2tr,
}

name_table! {
    spelling AddressKind {
        P2pkh => "p2pkh";
        P2sh => "p2sh";
        P2wpkh => "p2wpkh";
        P2wsh => "p2wsh";
        P2tr => "p2tr";
    }
}

/// Why a string is not an address.
///
/// One error type across both formats. They fail in different ways and the
/// variants say which, but a caller parsing "an address" should not have to
/// know which format they were handed in order to know what went wrong.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressError {
    /// Not valid Base58Check — bad character, too short, or a failed checksum.
    Base58(Base58Error),
    /// Not valid Bech32 — see [`Bech32Error`].
    Bech32(Bech32Error),
    /// A Base58 version byte belonging to no address kind.
    UnknownVersion {
        /// The version byte found.
        version: u8,
    },
    /// A Base58 payload of the wrong size. Every Base58 address is a version
    /// byte and exactly twenty hash bytes.
    WrongLength {
        /// Bytes after the version byte, where 20 were needed.
        got: usize,
    },
    /// A well-formed Bech32 string whose prefix names no network this crate
    /// knows. `tc1…` is the published example: its checksum is valid *for that
    /// prefix*, which is what makes this a different failure from a corrupt
    /// address.
    UnknownHrp {
        /// The prefix found.
        hrp: String,
    },
    /// A Bech32 string with a checksum and nothing else — no version group, so
    /// no program.
    EmptyProgram,
    /// A witness version above 16. The version is pushed by a single opcode
    /// and there is no seventeenth.
    InvalidWitnessVersion {
        /// The five-bit group found where a version was expected.
        value: u8,
    },
    /// A data part whose bits do not regroup into whole bytes: either a
    /// leftover run long enough to have been a group of its own, or padding
    /// bits that are not zero. Both mean the string carries information no
    /// byte accounts for, which would give one program several spellings.
    ProgramEncoding,
    /// The witness version and the checksum constant disagree. Version 0 is
    /// Bech32 and everything above it is Bech32m; a string that gets this
    /// backwards is invalid rather than merely unusual, which is the whole
    /// point of BIP350.
    VariantMismatch {
        /// The witness version the string claims.
        version: u8,
        /// The variant its checksum verified against.
        found: Variant,
        /// The variant that version requires.
        expected: Variant,
    },
    /// A witness program of an impossible length: outside 2 to 40 bytes, or
    /// not 20 or 32 at version 0.
    ProgramLength {
        /// The witness version.
        version: u8,
        /// The program length found.
        got: usize,
    },
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Base58(e) => write!(f, "{e}"),
            AddressError::Bech32(e) => write!(f, "{e}"),
            AddressError::UnknownVersion { version } => {
                write!(f, "no base58 address kind uses version byte {version:#04x}")
            }
            AddressError::WrongLength { got } => write!(
                f,
                "an address payload is {} bytes after the version, got {got}",
                AddressHash::SIZE
            ),
            AddressError::UnknownHrp { hrp } => {
                write!(f, "no network uses the bech32 prefix {hrp:?}")
            }
            AddressError::EmptyProgram => {
                f.write_str("a segwit address needs a witness version and a program")
            }
            AddressError::InvalidWitnessVersion { value } => {
                write!(f, "{value} is not a witness version: they run 0 to 16")
            }
            AddressError::ProgramEncoding => {
                f.write_str("the data part does not regroup into whole bytes")
            }
            AddressError::VariantMismatch {
                version,
                found,
                expected,
            } => write!(
                f,
                "witness version {version} must use {expected}, but the checksum is {found}"
            ),
            AddressError::ProgramLength { version, got } => {
                write!(
                    f,
                    "{got} bytes is not a witness program at version {version}"
                )
            }
        }
    }
}

impl std::error::Error for AddressError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AddressError::Base58(e) => Some(e),
            AddressError::Bech32(e) => Some(e),
            _ => None,
        }
    }
}

impl From<Base58Error> for AddressError {
    fn from(e: Base58Error) -> Self {
        AddressError::Base58(e)
    }
}

impl From<Bech32Error> for AddressError {
    fn from(e: Bech32Error) -> Self {
        AddressError::Bech32(e)
    }
}

impl Address {
    /// An address paying to a public key hash.
    #[must_use]
    pub const fn p2pkh(hash: AddressHash, network: Network) -> Self {
        Address::Base58(Base58Address::p2pkh(hash, network))
    }

    /// An address paying to a script hash.
    #[must_use]
    pub const fn p2sh(hash: AddressHash, network: Network) -> Self {
        Address::Base58(Base58Address::p2sh(hash, network))
    }

    /// A version 0 address paying to a public key hash — the same twenty bytes
    /// as [`Address::p2pkh`], written as a witness program instead.
    #[must_use]
    pub fn p2wpkh(hash: AddressHash, network: Network) -> Self {
        Address::Segwit(SegwitAddress::p2wpkh(hash, network))
    }

    /// A version 0 address paying to a script hash.
    ///
    /// Thirty-two bytes, and a single `SHA256` of the witness script rather
    /// than the `HASH160` P2SH uses — which is why this takes a different type
    /// from [`Address::p2sh`] rather than the same one at a different width.
    #[must_use]
    pub fn p2wsh(script_hash: Hash<32>, network: Network) -> Self {
        Address::Segwit(SegwitAddress::p2wsh(script_hash, network))
    }

    /// A taproot address, from an already-tweaked x-only output key.
    ///
    /// The tweak is not applied here: what goes in a v1 program is the *output*
    /// key, and computing it from an internal key is
    /// [`PublicKey::taproot_output_key`](crate::keys::PublicKey::taproot_output_key)'s
    /// job because it is curve arithmetic. Handing this the internal key by
    /// mistake produces a valid address for a key nobody holds — so the two
    /// have different names and neither is called "the key".
    #[must_use]
    pub fn p2tr(output_key: [u8; 32], network: Network) -> Self {
        Address::Segwit(SegwitAddress::p2tr(output_key, network))
    }

    /// A segwit address at any version, with the program checked.
    ///
    /// # Errors
    ///
    /// [`AddressError::ProgramLength`] — see [`SegwitAddress::new`].
    pub fn segwit(
        version: WitnessVersion,
        program: &[u8],
        network: Network,
    ) -> Result<Self, AddressError> {
        SegwitAddress::new(version, program, network).map(Address::Segwit)
    }

    /// The network this address belongs to.
    ///
    /// Always [`Network::Testnet`] for a parsed test-network address, in both
    /// formats: neither a `0x6f` version byte nor a `tb` prefix distinguishes
    /// testnet from signet.
    #[must_use]
    pub const fn network(&self) -> Network {
        match self {
            Address::Base58(a) => a.network(),
            Address::Segwit(a) => a.network(),
        }
    }

    /// What this address pays to, or `None` for a witness version and length
    /// pair that has no defined meaning yet.
    #[must_use]
    pub fn kind(&self) -> Option<AddressKind> {
        match self {
            Address::Base58(a) => Some(match a.kind() {
                Base58Kind::P2pkh => AddressKind::P2pkh,
                Base58Kind::P2sh => AddressKind::P2sh,
            }),
            Address::Segwit(a) => match (a.version().to_u8(), a.program().len()) {
                (0, 20) => Some(AddressKind::P2wpkh),
                (0, 32) => Some(AddressKind::P2wsh),
                (1, 32) => Some(AddressKind::P2tr),
                _ => None,
            },
        }
    }

    /// Whether this is a witness address.
    #[must_use]
    pub const fn is_segwit(&self) -> bool {
        matches!(self, Address::Segwit(_))
    }

    /// The Base58 arm, if this is one.
    #[must_use]
    pub const fn as_base58(&self) -> Option<&Base58Address> {
        match self {
            Address::Base58(a) => Some(a),
            Address::Segwit(_) => None,
        }
    }

    /// The segwit arm, if this is one.
    #[must_use]
    pub const fn as_segwit(&self) -> Option<&SegwitAddress> {
        match self {
            Address::Segwit(a) => Some(a),
            Address::Base58(_) => None,
        }
    }

    /// The `scriptPubKey` this address is a way of writing.
    #[must_use]
    pub fn script_pubkey(&self) -> Vec<u8> {
        match self {
            Address::Base58(a) => a.script_pubkey(),
            Address::Segwit(a) => a.script_pubkey(),
        }
    }
}

/// Whichever string form this address has.
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Base58(a) => fmt::Display::fmt(a, f),
            Address::Segwit(a) => fmt::Display::fmt(a, f),
        }
    }
}

impl FromStr for Address {
    type Err = AddressError;

    /// Read either format.
    ///
    /// # How the two are told apart
    ///
    /// By the prefix, against the three this crate knows — `bc`, `tb`, `bcrt`.
    /// Not by shape: `1` is both Bech32's separator and a Base58 character, so
    /// "has a separator" would misroute a real Base58 address often enough to
    /// matter. A prefix that is *not* one of the three falls through to Base58
    /// and, if that fails too, is re-examined: a string that is well-formed
    /// Bech32 under some other prefix gets [`AddressError::UnknownHrp`] rather
    /// than a confusing Base58 complaint, which is what the published `tc1…`
    /// vector asks for.
    ///
    /// # Errors
    ///
    /// Any [`AddressError`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some(position) = trimmed.rfind(SEPARATOR) {
            // ASCII-only, like the codec below: a prefix that folds to `bc`
            // under Unicode rules is not a Bitcoin prefix.
            let hrp = trimmed[..position].to_ascii_lowercase();
            if segwit::network_for_hrp(&hrp).is_some() {
                return SegwitAddress::parse(trimmed).map(Address::Segwit);
            }
        }

        Base58Address::parse(trimmed)
            .map(Address::Base58)
            .map_err(
                |base58_error| match crate::encoding::bech32::decode(trimmed) {
                    Ok(decoded) => AddressError::UnknownHrp { hrp: decoded.hrp },
                    Err(_) => base58_error,
                },
            )
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
    use crate::hashes::sha256;
    use crate::hex;

    fn hash20(hex_str: &str) -> AddressHash {
        AddressHash::from_hex(hex_str).expect("a 20-byte hash in hex")
    }

    /// One hash, written every way an address can be written. The strings are
    /// all different and every one of them reads back as itself.
    #[test]
    fn every_format_round_trips_through_the_one_entry_point() {
        let hash = hash20("751e76e8199196d454941c45d1b3a323f1433bd6");
        let script_hash = Hash::<32>::from_bytes(sha256(b"a witness script"));
        let output_key = sha256(b"an output key");

        for address in [
            Address::p2pkh(hash, Network::Mainnet),
            Address::p2sh(hash, Network::Mainnet),
            Address::p2wpkh(hash, Network::Mainnet),
            Address::p2wsh(script_hash, Network::Mainnet),
            Address::p2tr(output_key, Network::Mainnet),
        ] {
            let text = address.to_string();
            let parsed: Address = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(parsed, address, "{text}");
            assert_eq!(parsed.network(), Network::Mainnet);
            assert_eq!(parsed.kind(), address.kind());
            assert_eq!(parsed.script_pubkey(), address.script_pubkey());
        }
    }

    /// The five kinds, and their leading characters — which is how anyone
    /// actually recognises an address.
    #[test]
    fn each_kind_has_its_own_shape() {
        let hash = hash20("751e76e8199196d454941c45d1b3a323f1433bd6");
        let wide = Hash::<32>::from_bytes([0x11; 32]);

        for (address, kind, prefix) in [
            (
                Address::p2pkh(hash, Network::Mainnet),
                AddressKind::P2pkh,
                "1",
            ),
            (
                Address::p2sh(hash, Network::Mainnet),
                AddressKind::P2sh,
                "3",
            ),
            (
                Address::p2wpkh(hash, Network::Mainnet),
                AddressKind::P2wpkh,
                "bc1q",
            ),
            (
                Address::p2wsh(wide, Network::Mainnet),
                AddressKind::P2wsh,
                "bc1q",
            ),
            (
                Address::p2tr([0x22; 32], Network::Mainnet),
                AddressKind::P2tr,
                "bc1p",
            ),
        ] {
            assert_eq!(address.kind(), Some(kind));
            assert!(
                address.to_string().starts_with(prefix),
                "{kind:?} should start with {prefix}, got {address}"
            );
        }
    }

    /// A witness program at a version nobody has defined is a valid address
    /// with no name — which is a `None`, not an error.
    #[test]
    fn an_undefined_witness_program_has_no_kind_and_is_still_an_address() {
        let address = Address::segwit(
            WitnessVersion::new(5).expect("5 is a witness version"),
            &[0xab; 30],
            Network::Mainnet,
        )
        .expect("30 bytes is legal above version 0");
        assert_eq!(address.kind(), None);
        assert!(address.is_segwit());

        let text = address.to_string();
        assert_eq!(text.parse::<Address>().unwrap(), address);
        // v0 with a length v0 does not define is a different story: that one
        // is refused outright.
        assert!(Address::segwit(WitnessVersion::V0, &[0xab; 30], Network::Mainnet).is_err());
    }

    /// The dispatch rule. A Base58 address containing the Bech32 separator
    /// must not be mistaken for a Bech32 one, and a Bech32 string with a
    /// foreign prefix must be named as such rather than reported as bad
    /// Base58.
    #[test]
    fn tells_the_two_formats_apart_by_prefix() {
        // Every one of these contains at least one `1`.
        for text in [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM",
            "3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX",
        ] {
            let address: Address = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
            assert!(!address.is_segwit(), "{text} was read as segwit");
            assert_eq!(address.to_string(), text);
        }

        // A valid bech32 string whose prefix is not a Bitcoin network.
        assert_eq!(
            "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty".parse::<Address>(),
            Err(AddressError::UnknownHrp {
                hrp: "tc".to_owned()
            })
        );
        // …while a known prefix with a broken checksum stays a bech32 error.
        assert!(matches!(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5".parse::<Address>(),
            Err(AddressError::Bech32(_))
        ));
        // …and something that is neither is reported as the base58 it looked
        // most like.
        assert!(matches!(
            "not an address".parse::<Address>(),
            Err(AddressError::Base58(_))
        ));
    }

    /// The scripts, against BIP173's published translations.
    #[test]
    fn writes_the_scripts_the_bips_publish() {
        for (text, script) in [
            (
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "76a91462e907b15cbf27d5425399ebf6f0fb50ebb88f1888ac",
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ] {
            let address: Address = text.parse().unwrap();
            assert_eq!(hex::encode(&address.script_pubkey()), script, "{text}");
        }
    }

    /// The same folding trap as the codec's, one layer up: a prefix that
    /// becomes `bc` only under Unicode rules is not a Bitcoin prefix, and must
    /// not be routed to the segwit parser as though it were.
    #[test]
    fn a_prefix_that_folds_to_a_known_one_is_not_a_known_one() {
        let good = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        assert!(good.parse::<Address>().is_ok());
        // U+212A KELVIN SIGN folds to `k` — inside the data part here.
        let smuggled = good.replacen('k', "\u{212a}", 1);
        assert!(
            smuggled.parse::<Address>().is_err(),
            "{smuggled:?} was accepted"
        );
        // …and in the prefix, where it would otherwise decide the dispatch.
        assert!("B\u{212a}1qqqqqq".parse::<Address>().is_err());
    }

    /// Surrounding whitespace is trimmed, as everywhere else in this crate.
    #[test]
    fn tolerates_surrounding_whitespace() {
        assert!(
            "  1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa \n"
                .parse::<Address>()
                .is_ok()
        );
        assert!(
            " bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4\t"
                .parse::<Address>()
                .is_ok()
        );
    }
}
