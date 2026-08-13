//! § 3.2 — Witness addresses: P2WPKH, P2WSH, P2TR, and the versions after
//! them.
//!
//! A witness address is a version number and a program, and *that is all it
//! is*. It does not commit to a key or to a script — those are what the
//! program happens to be a hash of, one version at a time. So this type stores
//! the pair and refuses to pretend it knows more: a version 2 address is
//! perfectly encodable today, and this module will read and write one without
//! having any idea what it would mean to spend it.
//!
//! That is deliberate, and BIP350 asks for it in as many words: a wallet that
//! rejects unknown versions cannot pay to a soft fork that has not happened
//! yet.

use crate::parse::display_serialize;
use std::fmt;
use std::str::FromStr;

use crate::encoding::bech32::{self, Variant};
use crate::keys::address::AddressError;
use crate::network::Network;

/// Shortest witness program BIP141 allows.
pub const MIN_PROGRAM_SIZE: usize = 2;

/// Longest witness program BIP141 allows.
pub const MAX_PROGRAM_SIZE: usize = 40;

/// The two program sizes witness version 0 defines: twenty bytes for P2WPKH,
/// thirty-two for P2WSH. Any other length is invalid *at v0 specifically* —
/// later versions are free to choose their own.
pub const V0_PROGRAM_SIZES: [usize; 2] = [20, 32];

/// The program size taproot uses: an x-only public key.
pub const TAPROOT_PROGRAM_SIZE: usize = 32;

/// A witness version: 0 to 16.
///
/// Sixteen and not 255 because the version is pushed by a single opcode —
/// `OP_0`, or `OP_1` through `OP_16` — and there is no seventeenth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct WitnessVersion(u8);

impl WitnessVersion {
    /// Version 0: P2WPKH and P2WSH.
    pub const V0: WitnessVersion = WitnessVersion(0);
    /// Version 1: taproot.
    pub const V1: WitnessVersion = WitnessVersion(1);
    /// The highest version an output script can express.
    ///
    /// A `WitnessVersion` and not a `u8`, so it reads like [`WitnessVersion::V0`]
    /// and [`WitnessVersion::V1`] beside it. Use [`WitnessVersion::to_u8`] for
    /// the number.
    pub const MAX: WitnessVersion = WitnessVersion(16);

    /// Wrap a number in `0..=16`, or `None` above it.
    #[must_use]
    pub const fn new(version: u8) -> Option<Self> {
        if version <= WitnessVersion::MAX.0 {
            Some(WitnessVersion(version))
        } else {
            None
        }
    }

    /// The version as a number.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// The opcode that pushes this version in a `scriptPubKey`.
    ///
    /// `OP_0` is `0x00` and `OP_1`…`OP_16` are `0x51`…`0x60`. The gap is why
    /// this is a table rather than an addition: version 0 is not `0x50`.
    #[must_use]
    pub const fn to_opcode(self) -> u8 {
        if self.0 == 0 { 0x00 } else { 0x50 + self.0 }
    }

    /// Which bech32 variant an address of this version must use.
    #[must_use]
    pub const fn variant(self) -> Variant {
        Variant::for_witness_version(self.0)
    }
}

/// The number, so a version reads the way it is written in a BIP.
impl fmt::Display for WitnessVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The human-readable prefix for `network`.
///
/// Signet shares testnet's `tb`, which is why a parsed `tb1…` address reports
/// testnet: the string does not carry the difference, exactly as with the
/// Base58 version bytes.
#[must_use]
pub const fn hrp_for(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "bc",
        Network::Testnet | Network::Signet => "tb",
        Network::Regtest => "bcrt",
    }
}

/// The network a prefix names, if any.
#[must_use]
pub fn network_for_hrp(hrp: &str) -> Option<Network> {
    match hrp {
        "bc" => Some(Network::Mainnet),
        "tb" => Some(Network::Testnet),
        "bcrt" => Some(Network::Regtest),
        _ => None,
    }
}

/// A segwit address: a witness version, a program, and a network.
///
/// ```
/// use bitcoin_tools_core::keys::Address;
/// use bitcoin_tools_core::network::Network;
///
/// let address: Address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4".parse()?;
/// let segwit = address.as_segwit().expect("a bc1… address is segwit");
/// assert_eq!(segwit.version().to_u8(), 0);
/// assert_eq!(segwit.program().len(), 20);
/// assert_eq!(address.network(), Network::Mainnet);
/// # Ok::<_, bitcoin_tools_core::keys::AddressError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SegwitAddress {
    version: WitnessVersion,
    program: Vec<u8>,
    network: Network,
}

/// A segwit address taken apart — the same service
/// [`Base58Parts`](super::Base58Parts) does for the older format.
///
/// The checksum is six characters rather than four bytes, because bech32's
/// checksum is over five-bit groups and never becomes bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SegwitParts {
    /// The human-readable prefix, which names the network.
    pub hrp: String,
    /// The witness version.
    pub version: WitnessVersion,
    /// The program: 20 bytes for P2WPKH, 32 for P2WSH and P2TR.
    pub program: Vec<u8>,
    /// The six checksum characters, as they appear at the end of the string.
    pub checksum: String,
}

impl SegwitAddress {
    /// Build an address from a version and a program.
    ///
    /// # Errors
    ///
    /// [`AddressError::ProgramLength`] if the program is outside
    /// `2..=40` bytes, or if the version is 0 and the length is neither 20 nor
    /// 32. Those two rules come from different places — the first is BIP141's
    /// encoding limit and the second is what v0 *means* — and both have to be
    /// checked here, because an address that fails either is one nobody can
    /// spend to.
    pub fn new(
        version: WitnessVersion,
        program: &[u8],
        network: Network,
    ) -> Result<Self, AddressError> {
        let length = program.len();
        let ok = (MIN_PROGRAM_SIZE..=MAX_PROGRAM_SIZE).contains(&length)
            && (version != WitnessVersion::V0 || V0_PROGRAM_SIZES.contains(&length));
        if !ok {
            return Err(AddressError::ProgramLength {
                version: version.to_u8(),
                got: length,
            });
        }
        Ok(SegwitAddress {
            version,
            program: program.to_vec(),
            network,
        })
    }

    /// A version 0 address paying to a public key hash.
    ///
    /// Infallible where [`SegwitAddress::new`] is not, because the argument
    /// type *is* the length check: twenty bytes is one of v0's two sizes, so
    /// there is no error left to return. Same for the two below.
    #[must_use]
    pub fn p2wpkh(hash: super::AddressHash, network: Network) -> Self {
        SegwitAddress {
            version: WitnessVersion::V0,
            program: hash.as_bytes().to_vec(),
            network,
        }
    }

    /// A version 0 address paying to a script hash — a single `SHA256` of the
    /// witness script, thirty-two bytes.
    #[must_use]
    pub fn p2wsh(script_hash: crate::hashes::Hash<32>, network: Network) -> Self {
        SegwitAddress {
            version: WitnessVersion::V0,
            program: script_hash.as_bytes().to_vec(),
            network,
        }
    }

    /// A taproot address, from an already-tweaked x-only output key.
    #[must_use]
    pub fn p2tr(output_key: [u8; TAPROOT_PROGRAM_SIZE], network: Network) -> Self {
        SegwitAddress {
            version: WitnessVersion::V1,
            program: output_key.to_vec(),
            network,
        }
    }

    /// The witness version.
    #[must_use]
    pub const fn version(&self) -> WitnessVersion {
        self.version
    }

    /// The witness program.
    #[must_use]
    pub fn program(&self) -> &[u8] {
        &self.program
    }

    /// The network this address's prefix names.
    #[must_use]
    pub const fn network(&self) -> Network {
        self.network
    }

    /// The human-readable prefix this address encodes with.
    #[must_use]
    pub const fn hrp(&self) -> &'static str {
        hrp_for(self.network)
    }

    /// Which bech32 variant this address uses, decided by its version.
    #[must_use]
    pub const fn variant(&self) -> Variant {
        self.version.variant()
    }

    /// The five-bit data part: the version, then the program regrouped.
    ///
    /// Shared by [`Display`](fmt::Display) and [`SegwitAddress::parts`] so the
    /// layout is written once.
    fn data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(1 + self.program.len() * 8 / 5 + 1);
        data.push(self.version.to_u8());
        data.extend(bech32::bytes_to_groups(&self.program));
        data
    }

    /// The address broken into prefix, version, program and checksum.
    #[must_use]
    pub fn parts(&self) -> SegwitParts {
        let data = self.data();
        let checksum = bech32::checksum(self.hrp(), &data, self.variant());
        SegwitParts {
            hrp: self.hrp().to_owned(),
            version: self.version,
            program: self.program.clone(),
            // The alphabet lives in the codec, so rendering the groups as
            // characters is asked of it rather than repeated here.
            checksum: bech32::chars_for(&checksum),
        }
    }

    /// The `scriptPubKey` this address is a way of writing: the version
    /// opcode, then a push of the program.
    ///
    /// The program is at most 40 bytes, so the push is always a single-byte
    /// length — there is no `OP_PUSHDATA` case to get wrong.
    #[must_use]
    pub fn script_pubkey(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(2 + self.program.len());
        script.push(self.version.to_opcode());
        // `new` capped the length at 40, which fits a byte.
        script.push(u8::try_from(self.program.len()).unwrap_or(u8::MAX));
        script.extend_from_slice(&self.program);
        script
    }

    /// Read a bech32 or bech32m address.
    ///
    /// # Errors
    ///
    /// [`AddressError::Bech32`] for a string that is not valid bech32 at all,
    /// [`AddressError::UnknownHrp`] for a prefix belonging to no network this
    /// crate knows, [`AddressError::EmptyProgram`],
    /// [`AddressError::InvalidWitnessVersion`] above 16,
    /// [`AddressError::ProgramEncoding`] for a data part whose bits do not
    /// regroup into whole bytes, [`AddressError::VariantMismatch`] when the
    /// checksum constant disagrees with the version, or
    /// [`AddressError::ProgramLength`].
    pub fn parse(s: &str) -> Result<Self, AddressError> {
        let decoded = bech32::decode(s)?;
        let network = network_for_hrp(&decoded.hrp).ok_or_else(|| AddressError::UnknownHrp {
            hrp: decoded.hrp.clone(),
        })?;

        let (&first, rest) = decoded
            .data
            .split_first()
            .ok_or(AddressError::EmptyProgram)?;
        let version = WitnessVersion::new(first)
            .ok_or(AddressError::InvalidWitnessVersion { value: first })?;

        // The version and the checksum constant have to agree. They are two
        // independent statements in the string, and BIP350's whole point is
        // that a v1 address carrying a bech32 checksum is not a v1 address
        // with a typo — it is a different, invalid, thing.
        if decoded.variant != version.variant() {
            return Err(AddressError::VariantMismatch {
                version: version.to_u8(),
                found: decoded.variant,
                expected: version.variant(),
            });
        }

        let program = bech32::groups_to_bytes(rest).ok_or(AddressError::ProgramEncoding)?;
        SegwitAddress::new(version, &program, network)
    }
}

/// The bech32 or bech32m string, lowercase.
impl fmt::Display for SegwitAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every way `encode` can fail is closed off by construction: the
        // prefix is one of three literals, the groups come from
        // `bytes_to_groups` and are below 32, and the longest possible string
        // — `bcrt`, a version, a 40-byte program and a checksum — is 76
        // characters against a limit of 90. Mapping to `fmt::Error` rather
        // than substituting a default keeps a broken invariant loud instead of
        // silently printing an empty address.
        let text =
            bech32::encode(self.hrp(), &self.data(), self.variant()).map_err(|_| fmt::Error)?;
        f.pad(&text)
    }
}

impl FromStr for SegwitAddress {
    type Err = AddressError;

    /// See [`SegwitAddress::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SegwitAddress::parse(s)
    }
}

display_serialize!(SegwitAddress);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// BIP173's and BIP350's valid segwit addresses, given as the
    /// `scriptPubKey` each one translates to. Asserting through the script is
    /// stronger than asserting the version and program separately: it is the
    /// bytes that actually go on the chain.
    #[test]
    fn matches_the_published_addresses_and_their_scripts() {
        for (address, script) in [
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                "0014751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
            ),
            (
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
                "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
            ),
            ("BC1SW50QGDZ25J", "6002751e"),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
                "5210751e76e8199196d454941c45d1b3a323",
            ),
            (
                "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
            ),
            (
                "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
                "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            ),
        ] {
            let parsed = SegwitAddress::parse(address).unwrap_or_else(|e| panic!("{address}: {e}"));
            assert_eq!(hex::encode(&parsed.script_pubkey()), script, "{address}");
            // …and it re-renders as the same string, lowercased.
            assert_eq!(parsed.to_string(), address.to_lowercase(), "{address}");
        }
    }

    /// The published invalid addresses, each with the reason the BIP gives.
    #[test]
    fn rejects_the_published_invalid_addresses() {
        use crate::encoding::bech32::Bech32Error;

        // A prefix belonging to no network. The checksum is valid *for that
        // prefix*, which is what makes this a distinct failure rather than a
        // corrupt string.
        assert_eq!(
            SegwitAddress::parse("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty"),
            Err(AddressError::UnknownHrp {
                hrp: "tc".to_owned()
            })
        );

        // A witness version above 16 — `3` is group 17 in the alphabet.
        assert_eq!(
            SegwitAddress::parse("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2"),
            Err(AddressError::InvalidWitnessVersion { value: 17 })
        );

        // Program lengths: one byte, forty-one bytes, and sixteen bytes at a
        // version that only allows twenty or thirty-two.
        assert_eq!(
            SegwitAddress::parse("bc1pw5dgrnzv"),
            Err(AddressError::ProgramLength { version: 1, got: 1 })
        );
        assert_eq!(
            SegwitAddress::parse(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav"
            ),
            Err(AddressError::ProgramLength {
                version: 1,
                got: 41
            })
        );
        assert_eq!(
            SegwitAddress::parse("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P"),
            Err(AddressError::ProgramLength {
                version: 0,
                got: 16
            })
        );

        // Padding: more than four leftover bits, and non-zero leftover bits.
        assert_eq!(
            SegwitAddress::parse(
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf"
            ),
            Err(AddressError::ProgramEncoding)
        );
        assert_eq!(
            SegwitAddress::parse("tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j"),
            Err(AddressError::ProgramEncoding)
        );

        // An empty data section: a checksum and nothing else.
        assert_eq!(
            SegwitAddress::parse("bc1gmk9yu"),
            Err(AddressError::EmptyProgram)
        );

        // A bad checksum, mixed case, and a character outside the alphabet all
        // fail in the codec below.
        assert!(matches!(
            SegwitAddress::parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
            Err(AddressError::Bech32(Bech32Error::BadChecksum))
        ));
        assert!(matches!(
            SegwitAddress::parse("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7"),
            Err(AddressError::Bech32(Bech32Error::MixedCase))
        ));
        assert!(matches!(
            SegwitAddress::parse("bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4"),
            Err(AddressError::Bech32(Bech32Error::InvalidChar { .. }))
        ));
    }

    /// The pairing BIP350 exists to enforce: v0 is bech32, everything above is
    /// bech32m, and a string that gets it backwards is invalid rather than
    /// merely unusual.
    ///
    /// The last three are BIP173's own invalid vectors, listed there under
    /// *program length* and *padding*. They are variant mismatches now,
    /// because BIP350 moved every version above 0 to the other constant — and
    /// this parser checks the variant first, since it is a property of the
    /// string while the length is a property of what the string decoded to.
    /// BIP350's replacements for those three cases are asserted above.
    #[test]
    fn the_version_and_the_checksum_constant_must_agree() {
        for (address, version, found) in [
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
                1,
                Variant::Bech32,
            ),
            (
                "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
                2,
                Variant::Bech32,
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
                0,
                Variant::Bech32m,
            ),
            (
                "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
                0,
                Variant::Bech32m,
            ),
            ("bc1rw5uspcuh", 3, Variant::Bech32),
            (
                "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
                15,
                Variant::Bech32,
            ),
            ("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du", 2, Variant::Bech32),
        ] {
            assert_eq!(
                SegwitAddress::parse(address),
                Err(AddressError::VariantMismatch {
                    version,
                    found,
                    expected: WitnessVersion::new(version).unwrap().variant(),
                }),
                "{address}"
            );
        }
    }

    /// A version nobody has defined is still a perfectly good address, and
    /// BIP350 explicitly asks that it be treated as one.
    #[test]
    fn accepts_versions_that_do_not_mean_anything_yet() {
        for version in 2..=WitnessVersion::MAX.to_u8() {
            let version = WitnessVersion::new(version).unwrap();
            let address = SegwitAddress::new(version, &[0x42; 20], Network::Mainnet).unwrap();
            let text = address.to_string();
            let parsed = SegwitAddress::parse(&text).unwrap();
            assert_eq!(parsed, address, "{text}");
            assert_eq!(parsed.variant(), Variant::Bech32m);
            // The version opcode is OP_1..OP_16 — never 0x50, which is not an
            // opcode at all.
            assert_eq!(parsed.script_pubkey()[0], 0x50 + version.to_u8());
        }
        assert_eq!(WitnessVersion::new(17), None);
        assert_eq!(WitnessVersion::V0.to_opcode(), 0x00);
        assert_eq!(WitnessVersion::V1.to_opcode(), 0x51);
    }

    /// Version 0's two lengths are the whole of what v0 means; every other
    /// length has to be refused at v0 and accepted above it.
    #[test]
    fn version_zero_takes_two_lengths_and_later_versions_take_any() {
        for length in 0..=42usize {
            let program = vec![0u8; length];
            let at_v0 = SegwitAddress::new(WitnessVersion::V0, &program, Network::Mainnet);
            let at_v1 = SegwitAddress::new(WitnessVersion::V1, &program, Network::Mainnet);
            assert_eq!(
                at_v0.is_ok(),
                V0_PROGRAM_SIZES.contains(&length),
                "v0 at {length} bytes"
            );
            assert_eq!(
                at_v1.is_ok(),
                (MIN_PROGRAM_SIZE..=MAX_PROGRAM_SIZE).contains(&length),
                "v1 at {length} bytes"
            );
        }
    }

    #[test]
    fn splits_into_prefix_version_program_and_checksum() {
        let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
        let parts = SegwitAddress::parse(address).unwrap().parts();
        assert_eq!(parts.hrp, "bc");
        assert_eq!(parts.version, WitnessVersion::V0);
        assert_eq!(
            hex::encode(&parts.program),
            "751e76e8199196d454941c45d1b3a323f1433bd6"
        );
        assert_eq!(
            parts.checksum,
            address[address.len() - crate::encoding::bech32::CHECKSUM_LEN..]
        );
    }

    /// Every network gets its own prefix, and the two test networks that share
    /// one are indistinguishable afterwards — the same honesty the Base58
    /// version bytes require.
    #[test]
    fn the_prefix_names_the_network() {
        for (network, hrp, parses_back_as) in [
            (Network::Mainnet, "bc", Network::Mainnet),
            (Network::Testnet, "tb", Network::Testnet),
            (Network::Signet, "tb", Network::Testnet),
            (Network::Regtest, "bcrt", Network::Regtest),
        ] {
            let address = SegwitAddress::new(WitnessVersion::V0, &[7; 20], network).unwrap();
            assert_eq!(address.hrp(), hrp);
            assert!(address.to_string().starts_with(hrp), "{network}");
            assert_eq!(
                SegwitAddress::parse(&address.to_string())
                    .unwrap()
                    .network(),
                parses_back_as,
                "{network}"
            );
        }
    }

    #[test]
    fn display_honours_width() {
        let address = SegwitAddress::new(WitnessVersion::V0, &[0; 20], Network::Mainnet).unwrap();
        let text = address.to_string();
        assert_eq!(format!("{address:>60}"), format!("{:>60}", text));
    }
}
