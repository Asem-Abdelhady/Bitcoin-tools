//! § 4.2 — Derivation paths, and the four standard shapes over them.
//!
//! BIP44, BIP49, BIP84 and BIP86 are not four algorithms. They are four
//! numbers in the first position of a path, and four decisions about what to
//! do with the key that comes out. [`Purpose`] is that pair and nothing else,
//! which is why it is an enum with two tables rather than four modules.

use std::fmt;
use std::str::FromStr;

use crate::keys::{Address, AddressKind, PublicKey, PublicKeyError};
use crate::network::Network;
use crate::parse::{display_serialize, name_table};

/// The bit that marks a child index as hardened.
///
/// Not a flag beside the number — it *is* the top bit of the number, which is
/// why a hardened index and a normal one can share one `u32` on the wire and
/// why indices only run to 2³¹ - 1.
pub const HARDENED_OFFSET: u32 = 0x8000_0000;

/// The largest index either kind may have.
pub const MAX_INDEX: u32 = HARDENED_OFFSET - 1;

/// The deepest path BIP32 can serialize, because depth is one byte.
pub const MAX_DEPTH: usize = 255;

/// One step in a path: an index, and whether it is hardened.
///
/// # What hardening buys
///
/// A hardened child is derived from the parent's *private* key, so an xpub
/// cannot derive it. That is the point: without hardening, an xpub plus any
/// one child private key recovers the parent private key and therefore the
/// whole account. Every BIP44-family path hardens the first three levels for
/// exactly that reason, and leaves the last two normal so a watch-only wallet
/// can still generate addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChildNumber(u32);

/// Why a string is not a child number.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseChildError {
    /// Not a number, once any hardened marker was removed.
    NotANumber {
        /// The text that was not a number.
        text: String,
    },
    /// A number at or above 2³¹, which cannot be an index because the top bit
    /// is the hardened marker.
    TooLarge {
        /// The index found.
        index: u32,
    },
}

impl fmt::Display for ParseChildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseChildError::NotANumber { text } => {
                write!(f, "{text:?} is not a child index")
            }
            ParseChildError::TooLarge { index } => write!(
                f,
                "{index} is past {MAX_INDEX}, the largest index either kind has"
            ),
        }
    }
}

impl std::error::Error for ParseChildError {}

impl ChildNumber {
    /// A normal child, derivable from a public parent, or `None` past
    /// [`MAX_INDEX`].
    ///
    /// An `Option` rather than a `Result`, matching
    /// [`WitnessVersion::new`](crate::keys::WitnessVersion::new) and
    /// [`WordCount::from_words`](crate::hd::WordCount::from_words): there is
    /// one way to be wrong and it is in the name of the constant. The
    /// *parsing* half is where a reason is worth carrying, and that is
    /// [`ParseChildError`].
    #[must_use]
    pub const fn normal(index: u32) -> Option<Self> {
        if index > MAX_INDEX {
            return None;
        }
        Some(ChildNumber(index))
    }

    /// A hardened child, derivable only from a private parent, or `None` past
    /// [`MAX_INDEX`].
    #[must_use]
    pub const fn hardened(index: u32) -> Option<Self> {
        if index > MAX_INDEX {
            return None;
        }
        Some(ChildNumber(index + HARDENED_OFFSET))
    }

    /// The raw four bytes as they appear in a serialized key — hardened bit
    /// included. Total, because every `u32` is a valid child number.
    #[must_use]
    pub const fn from_u32(raw: u32) -> Self {
        ChildNumber(raw)
    }

    /// The raw value, hardened bit included.
    #[must_use]
    pub const fn to_u32(self) -> u32 {
        self.0
    }

    /// The index without the hardened bit — the number a path writes.
    #[must_use]
    pub const fn index(self) -> u32 {
        self.0 & MAX_INDEX
    }

    /// Whether the top bit is set.
    #[must_use]
    pub const fn is_hardened(self) -> bool {
        self.0 >= HARDENED_OFFSET
    }
}

/// `44'` — the index, then an apostrophe when hardened.
///
/// The apostrophe rather than `h`: it is what BIP32 writes, and what every
/// path in every BIP is written with. `h` and `H` are still *read*, because
/// an apostrophe is awkward inside a shell quote and tools emit `h` for that
/// reason.
impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_hardened() {
            write!(f, "{}'", self.index())
        } else {
            write!(f, "{}", self.index())
        }
    }
}

// `44'`, not `2147483692`.
//
// The raw `u32` would be a correct transport and an unreadable one: nothing
// in the number says its top bit is a flag, so a consumer reading `0` and
// `2147483648` has to know the convention to see that they are the same
// index. Every other rendering in § 4 goes through `Display`; so does this.
display_serialize!(ChildNumber);

impl FromStr for ChildNumber {
    type Err = ParseChildError;

    /// Accepts `0`, `0'`, `0h` and `0H`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        let (digits, hardened) = match trimmed.strip_suffix(['\'', 'h', 'H']) {
            Some(rest) => (rest, true),
            None => (trimmed, false),
        };
        let index: u32 = digits.parse().map_err(|_| ParseChildError::NotANumber {
            text: trimmed.to_owned(),
        })?;
        let child = if hardened {
            ChildNumber::hardened(index)
        } else {
            ChildNumber::normal(index)
        };
        child.ok_or(ParseChildError::TooLarge { index })
    }
}

/// Why a string is not a derivation path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParsePathError {
    /// A step that is not a child number, and where it was.
    Step {
        /// Zero-based position in the path.
        position: usize,
        /// What went wrong with that step.
        error: ParseChildError,
    },
    /// More than [`MAX_DEPTH`] steps. BIP32 stores depth in one byte, so a
    /// deeper path has no serialization — the key it derives is real, but
    /// there is no way to write it down.
    TooDeep {
        /// Steps counted.
        got: usize,
    },
}

impl fmt::Display for ParsePathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParsePathError::Step { position, error } => {
                write!(f, "step {} of the path: {error}", position + 1)
            }
            ParsePathError::TooDeep { got } => {
                write!(f, "a path is at most {MAX_DEPTH} steps deep, got {got}")
            }
        }
    }
}

impl std::error::Error for ParsePathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParsePathError::Step { error, .. } => Some(error),
            ParsePathError::TooDeep { .. } => None,
        }
    }
}

/// A path from a master key to a descendant: `m/84'/0'/0'/0/0`.
///
/// ```
/// use bitcoin_tools_core::hd::DerivationPath;
///
/// let path: DerivationPath = "m/84'/0'/0'/0/0".parse()?;
/// assert_eq!(path.depth(), 5);
/// assert!(path.iter().take(3).all(|step| step.is_hardened()));
/// assert_eq!(path.to_string(), "m/84'/0'/0'/0/0");
///
/// // `h` reads the same as an apostrophe, and writes back as one.
/// assert_eq!("m/84h/0h/0h/0/0".parse::<DerivationPath>()?, path);
/// # Ok::<_, bitcoin_tools_core::hd::ParsePathError>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct DerivationPath(Vec<ChildNumber>);

// The written form, `m/84'/0'/0'/0/0`.
display_serialize!(DerivationPath);

impl DerivationPath {
    /// The empty path — the master key itself.
    #[must_use]
    pub const fn master() -> Self {
        DerivationPath(Vec::new())
    }

    /// Build from steps.
    ///
    /// # Errors
    ///
    /// [`ParsePathError::TooDeep`] past [`MAX_DEPTH`].
    pub fn from_steps(steps: &[ChildNumber]) -> Result<Self, ParsePathError> {
        if steps.len() > MAX_DEPTH {
            return Err(ParsePathError::TooDeep { got: steps.len() });
        }
        Ok(DerivationPath(steps.to_vec()))
    }

    /// This path with one more step on the end.
    ///
    /// # Errors
    ///
    /// [`ParsePathError::TooDeep`] past [`MAX_DEPTH`].
    pub fn child(&self, step: ChildNumber) -> Result<Self, ParsePathError> {
        let mut steps = self.0.clone();
        steps.push(step);
        DerivationPath::from_steps(&steps)
    }

    /// The steps, in order.
    #[must_use]
    pub fn as_slice(&self) -> &[ChildNumber] {
        &self.0
    }

    /// The steps, in order.
    pub fn iter(&self) -> std::slice::Iter<'_, ChildNumber> {
        self.0.iter()
    }

    /// How many steps — which is the `depth` byte of the key this path
    /// derives.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Whether this is the master key's own path.
    #[must_use]
    pub fn is_master(&self) -> bool {
        self.0.is_empty()
    }

    /// This path with its last step removed, or `None` at the master.
    #[must_use]
    pub fn parent(&self) -> Option<DerivationPath> {
        let (_, rest) = self.0.split_last()?;
        Some(DerivationPath(rest.to_vec()))
    }
}

impl<'a> IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = std::slice::Iter<'a, ChildNumber>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

/// `m/84'/0'/0'/0/0`, and bare `m` for the master.
impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for step in &self.0 {
            write!(f, "/{step}")?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = ParsePathError;

    /// Accepts a leading `m/` or `M/`, or no prefix at all; `m` alone is the
    /// master. Steps may use `'`, `h` or `H`.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        // A leading `m` is conventional rather than part of the data, and a
        // path pasted out of a wallet may or may not have it.
        let body = trimmed
            .strip_prefix(['m', 'M'])
            .unwrap_or(trimmed)
            .trim_start_matches('/');

        if body.is_empty() {
            return Ok(DerivationPath::master());
        }
        let mut steps = Vec::new();
        for (position, part) in body.split('/').enumerate() {
            let step = part
                .parse()
                .map_err(|error| ParsePathError::Step { position, error })?;
            steps.push(step);
        }
        DerivationPath::from_steps(&steps)
    }
}

/// The coin type for `network`: `0'` for mainnet, `1'` for every test network.
///
/// One number for all three test chains, from the SLIP-44 registry — the same
/// collapse the address version bytes make, and for the same reason: nobody
/// registered separate numbers.
///
/// A free function rather than a method on [`Purpose`], because it does not
/// depend on one: every BIP44-family layout puts the same number in the same
/// place.
#[must_use]
pub const fn coin_type(network: Network) -> ChildNumber {
    // 0 or 1, so the range check has nothing to reject — see `Purpose::child`.
    if network.is_mainnet() {
        ChildNumber(HARDENED_OFFSET)
    } else {
        ChildNumber(1 + HARDENED_OFFSET)
    }
}

/// One of the four standard account layouts.
///
/// Each is a number in the first position of a path and an output type for the
/// keys underneath it. Everything else — the coin type, the account, the
/// change flag, the address index — is identical across all four, which is why
/// this enum carries two tables and no algorithm.
///
/// ```
/// use bitcoin_tools_core::hd::Purpose;
/// use bitcoin_tools_core::keys::{AddressKind, PublicKey};
/// use bitcoin_tools_core::network::Network;
///
/// let key = PublicKey::from_hex(
///     "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
/// )?;
///
/// // One key, four standards, four addresses — and the path each belongs at.
/// for purpose in Purpose::all() {
///     let path = purpose.address_path(Network::Mainnet, 0, false, 0).expect("in range");
///     let address = purpose.address(&key, Network::Mainnet)?;
///     assert!(path.to_string().starts_with(&format!("m/{}'", purpose.number())));
///     assert_eq!(address.kind(), Some(purpose.address_kind()));
/// }
///
/// // BIP84's is the native segwit one every wallet shows today.
/// assert_eq!(Purpose::Bip84.address_kind(), AddressKind::P2wpkh);
/// assert_eq!(
///     Purpose::Bip84.address(&key, Network::Mainnet)?.to_string(),
///     "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
/// );
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Purpose {
    /// BIP44 — P2PKH, the original layout.
    Bip44,
    /// BIP49 — P2WPKH nested in P2SH, which is a `3…` address from outside.
    Bip49,
    /// BIP84 — native P2WPKH, a `bc1q…` address.
    Bip84,
    /// BIP86 — P2TR with no script tree, a `bc1p…` address.
    Bip86,
}

name_table! {
    /// Accepts `bip44` and the bare number `44`, and likewise for the other
    /// three — a path is written with the number, so that spelling has to
    /// read back.
    Purpose => UnknownPurpose,
    kind: "purpose",
    expected: "bip44, bip49, bip84, or bip86",
    {
        Bip44 => "bip44", "44";
        Bip49 => "bip49", "49";
        Bip84 => "bip84", "84";
        Bip86 => "bip86", "86";
    }
}

impl Purpose {
    /// All of them, in order.
    ///
    /// A slice rather than an array, and the enum is `#[non_exhaustive]`:
    /// purposes are a thing that gets added — BIP48's multisig layout is the
    /// obvious next one — and neither a new variant nor a longer list should
    /// be a breaking change.
    #[must_use]
    pub const fn all() -> &'static [Purpose] {
        &[
            Purpose::Bip44,
            Purpose::Bip49,
            Purpose::Bip84,
            Purpose::Bip86,
        ]
    }

    /// The number this purpose occupies in a path.
    #[must_use]
    pub const fn number(self) -> u32 {
        match self {
            Purpose::Bip44 => 44,
            Purpose::Bip49 => 49,
            Purpose::Bip84 => 84,
            Purpose::Bip86 => 86,
        }
    }

    /// The purpose a number names, if any.
    #[must_use]
    pub const fn from_number(number: u32) -> Option<Self> {
        match number {
            44 => Some(Purpose::Bip44),
            49 => Some(Purpose::Bip49),
            84 => Some(Purpose::Bip84),
            86 => Some(Purpose::Bip86),
            _ => None,
        }
    }

    /// The first step of any path under this purpose — the number, hardened.
    ///
    /// Total rather than fallible, and built here rather than through
    /// [`ChildNumber::hardened`]: the four numbers are constants far below
    /// 2³¹, so the range check has nothing to reject and returning a `Result`
    /// would push a `?` into every call site for an error that cannot occur.
    #[must_use]
    pub const fn child(self) -> ChildNumber {
        ChildNumber(self.number() + HARDENED_OFFSET)
    }

    /// What an address under this purpose pays to.
    ///
    /// BIP49's answer is [`AddressKind::P2sh`], not a witness type: the
    /// witness program is wrapped in a redeem script, so from the chain's
    /// point of view it is an ordinary P2SH output and the address starts
    /// with `3`.
    #[must_use]
    pub const fn address_kind(self) -> AddressKind {
        match self {
            Purpose::Bip44 => AddressKind::P2pkh,
            Purpose::Bip49 => AddressKind::P2sh,
            Purpose::Bip84 => AddressKind::P2wpkh,
            Purpose::Bip86 => AddressKind::P2tr,
        }
    }

    /// `m/purpose'/coin'/account'` — the level a wallet exports as an xpub.
    ///
    /// `None` for an account index past [`MAX_INDEX`], which is the only way
    /// this can fail — the other two steps are constants.
    #[must_use]
    pub fn account_path(self, network: Network, account: u32) -> Option<DerivationPath> {
        Some(DerivationPath(vec![
            self.child(),
            coin_type(network),
            ChildNumber::hardened(account)?,
        ]))
    }

    /// `m/purpose'/coin'/account'/change/index` — one address.
    ///
    /// `change` picks the second chain, which wallets use for change outputs
    /// so that a watch-only xpub can still tell its own change from a payment.
    /// Both of the last two steps are *normal*, which is what lets an xpub
    /// generate addresses at all.
    ///
    /// `None` for an account or address index past [`MAX_INDEX`].
    #[must_use]
    pub fn address_path(
        self,
        network: Network,
        account: u32,
        change: bool,
        index: u32,
    ) -> Option<DerivationPath> {
        let mut steps = self.account_path(network, account)?.0;
        steps.push(ChildNumber::normal(u32::from(change))?);
        steps.push(ChildNumber::normal(index)?);
        Some(DerivationPath(steps))
    }

    /// The address this purpose gives a key.
    ///
    /// This is the second half of what a purpose *is*: the path picks the key,
    /// and this picks what to do with it. Having it here is what keeps the
    /// four standards from becoming four code paths.
    ///
    /// # Errors
    ///
    /// [`PublicKeyError::Uncompressed`] for an uncompressed key under any
    /// purpose but BIP44 — every witness type requires a compressed key — or
    /// [`PublicKeyError::Tweak`] from BIP86's taproot tweak.
    pub fn address(self, key: &PublicKey, network: Network) -> Result<Address, PublicKeyError> {
        match self {
            Purpose::Bip44 => Ok(key.p2pkh_address(network)),
            Purpose::Bip49 => key.p2sh_p2wpkh_address(network),
            Purpose::Bip84 => key.p2wpkh_address(network),
            Purpose::Bip86 => key.p2tr_address(network),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hardened_bit_is_the_top_bit_of_the_index() {
        let normal = ChildNumber::normal(0).unwrap();
        let hardened = ChildNumber::hardened(0).unwrap();
        assert_eq!(normal.to_u32(), 0);
        assert_eq!(hardened.to_u32(), HARDENED_OFFSET);
        assert_eq!(normal.index(), hardened.index());
        assert!(!normal.is_hardened() && hardened.is_hardened());
        assert_ne!(normal, hardened, "same index, different children");

        // The largest of each, and one past.
        assert_eq!(ChildNumber::normal(MAX_INDEX).unwrap().to_u32(), MAX_INDEX);
        assert_eq!(ChildNumber::hardened(MAX_INDEX).unwrap().to_u32(), u32::MAX);
        assert_eq!(ChildNumber::normal(HARDENED_OFFSET), None);
        assert_eq!(ChildNumber::hardened(HARDENED_OFFSET), None);
        // …while every raw u32 is a child number, because the wire says so.
        assert!(ChildNumber::from_u32(u32::MAX).is_hardened());
        assert_eq!(ChildNumber::from_u32(u32::MAX).index(), MAX_INDEX);
    }

    #[test]
    fn child_numbers_read_every_spelling_and_write_one() {
        for (text, expected) in [
            ("0", ChildNumber::normal(0).unwrap()),
            ("2147483647", ChildNumber::normal(MAX_INDEX).unwrap()),
            ("0'", ChildNumber::hardened(0).unwrap()),
            ("44h", ChildNumber::hardened(44).unwrap()),
            ("44H", ChildNumber::hardened(44).unwrap()),
        ] {
            assert_eq!(text.parse::<ChildNumber>().unwrap(), expected, "{text}");
        }
        assert_eq!(ChildNumber::hardened(44).unwrap().to_string(), "44'");
        assert_eq!(ChildNumber::normal(44).unwrap().to_string(), "44");

        assert!(matches!(
            "".parse::<ChildNumber>(),
            Err(ParseChildError::NotANumber { .. })
        ));
        assert!(matches!(
            "-1".parse::<ChildNumber>(),
            Err(ParseChildError::NotANumber { .. })
        ));
        assert!(matches!(
            "4294967296'".parse::<ChildNumber>(),
            Err(ParseChildError::NotANumber { .. })
        ));
        assert_eq!(
            "2147483648".parse::<ChildNumber>(),
            Err(ParseChildError::TooLarge {
                index: HARDENED_OFFSET
            })
        );
    }

    #[test]
    fn paths_round_trip_through_their_written_form() {
        for text in [
            "m",
            "m/0",
            "m/0'",
            "m/44'/0'/0'/0/0",
            "m/2147483647'/1/2147483647",
        ] {
            let path: DerivationPath = text.parse().unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(path.to_string(), text);
        }
    }

    #[test]
    fn accepts_the_ways_a_path_gets_written() {
        let canonical: DerivationPath = "m/84'/0'/0'/0/0".parse().unwrap();
        for text in [
            "m/84'/0'/0'/0/0",
            "M/84'/0'/0'/0/0",
            "84'/0'/0'/0/0",
            "m/84h/0h/0h/0/0",
            "m/84H/0H/0H/0/0",
            "  m/84'/0'/0'/0/0  ",
        ] {
            assert_eq!(text.parse::<DerivationPath>().unwrap(), canonical, "{text}");
        }
        // The master, however it is spelled.
        for text in ["m", "M", "m/", ""] {
            assert!(
                text.parse::<DerivationPath>().unwrap().is_master(),
                "{text:?}"
            );
        }
    }

    #[test]
    fn names_the_step_that_failed() {
        assert!(matches!(
            "m/44'/x/0".parse::<DerivationPath>(),
            Err(ParsePathError::Step { position: 1, .. })
        ));
        assert_eq!(
            "m/0/2147483648".parse::<DerivationPath>(),
            Err(ParsePathError::Step {
                position: 1,
                error: ParseChildError::TooLarge {
                    index: HARDENED_OFFSET
                }
            })
        );
    }

    /// Depth is one byte on the wire, so a deeper path has no serialization.
    #[test]
    fn a_path_deeper_than_a_byte_is_refused() {
        let step = ChildNumber::normal(0).unwrap();
        let at = vec![step; MAX_DEPTH];
        assert!(DerivationPath::from_steps(&at).is_ok());

        let over = vec![step; MAX_DEPTH + 1];
        assert_eq!(
            DerivationPath::from_steps(&over),
            Err(ParsePathError::TooDeep { got: MAX_DEPTH + 1 })
        );
        let deepest = DerivationPath::from_steps(&at).unwrap();
        assert_eq!(
            deepest.child(step),
            Err(ParsePathError::TooDeep { got: MAX_DEPTH + 1 })
        );
        assert_eq!(deepest.parent().unwrap().depth(), MAX_DEPTH - 1);
        assert_eq!(DerivationPath::master().parent(), None);
    }

    /// The published account paths, written the way each BIP writes them.
    #[test]
    fn builds_the_standard_paths() {
        for (purpose, mainnet, testnet) in [
            (Purpose::Bip44, "m/44'/0'/0'", "m/44'/1'/0'"),
            (Purpose::Bip49, "m/49'/0'/0'", "m/49'/1'/0'"),
            (Purpose::Bip84, "m/84'/0'/0'", "m/84'/1'/0'"),
            (Purpose::Bip86, "m/86'/0'/0'", "m/86'/1'/0'"),
        ] {
            assert_eq!(
                purpose
                    .account_path(Network::Mainnet, 0)
                    .unwrap()
                    .to_string(),
                mainnet
            );
            assert_eq!(
                purpose
                    .account_path(Network::Testnet, 0)
                    .unwrap()
                    .to_string(),
                testnet
            );
            // The first receiving address, and the first change address.
            assert_eq!(
                purpose
                    .address_path(Network::Mainnet, 0, false, 0)
                    .unwrap()
                    .to_string(),
                format!("{mainnet}/0/0")
            );
            assert_eq!(
                purpose
                    .address_path(Network::Mainnet, 0, true, 7)
                    .unwrap()
                    .to_string(),
                format!("{mainnet}/1/7")
            );
        }
    }

    /// Signet and regtest are testnets for coin-type purposes. One number for
    /// three chains, as SLIP-44 has it.
    #[test]
    fn every_test_network_shares_coin_type_one() {
        assert_eq!(coin_type(Network::Mainnet).index(), 0);
        for network in [Network::Testnet, Network::Signet, Network::Regtest] {
            assert_eq!(coin_type(network).index(), 1, "{network}");
            assert!(coin_type(network).is_hardened());
        }
    }

    /// The first three levels are hardened and the last two are not — the
    /// property that lets a watch-only wallet work without exposing the
    /// account's siblings.
    #[test]
    fn the_first_three_levels_are_hardened_and_the_last_two_are_not() {
        for &purpose in Purpose::all() {
            let path = purpose.address_path(Network::Mainnet, 3, false, 9).unwrap();
            let steps: Vec<ChildNumber> = path.iter().copied().collect();
            assert_eq!(steps.len(), 5);
            assert!(steps[..3].iter().all(|s| s.is_hardened()), "{purpose}");
            assert!(
                !steps[3].is_hardened() && !steps[4].is_hardened(),
                "{purpose}"
            );
            assert_eq!(steps[0].index(), purpose.number());
            assert_eq!(steps[2].index(), 3);
            assert_eq!(steps[4].index(), 9);
        }
    }

    #[test]
    fn purposes_name_themselves_by_word_and_by_number() {
        for &purpose in Purpose::all() {
            assert_eq!(purpose.to_string().parse(), Ok(purpose));
            assert_eq!(purpose.number().to_string().parse(), Ok(purpose));
            assert_eq!(Purpose::from_number(purpose.number()), Some(purpose));
            assert_eq!(purpose.child().index(), purpose.number());
            assert!(purpose.child().is_hardened());
        }
        assert_eq!(Purpose::from_number(45), None);
        assert!("bip45".parse::<Purpose>().is_err());
    }

    /// Four purposes, four output types — and BIP49's is P2SH, not a witness
    /// type, because the witness program is inside a redeem script.
    #[test]
    fn each_purpose_names_its_own_output_type() {
        assert_eq!(Purpose::Bip44.address_kind(), AddressKind::P2pkh);
        assert_eq!(Purpose::Bip49.address_kind(), AddressKind::P2sh);
        assert_eq!(Purpose::Bip84.address_kind(), AddressKind::P2wpkh);
        assert_eq!(Purpose::Bip86.address_kind(), AddressKind::P2tr);
    }

    /// …and the address a purpose builds has to agree with the kind it claims.
    #[test]
    fn the_address_matches_the_kind_the_purpose_names() {
        let key = PublicKey::from_hex(
            "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        )
        .expect("a compressed key");

        for &purpose in Purpose::all() {
            let address = purpose.address(&key, Network::Mainnet).unwrap();
            assert_eq!(
                address.kind(),
                Some(purpose.address_kind()),
                "{purpose} built a {:?}",
                address.kind()
            );
        }
    }

    /// Every purpose but BIP44 needs a compressed key, and says so rather than
    /// compressing one behind the caller's back.
    #[test]
    fn the_witness_purposes_refuse_an_uncompressed_key() {
        let uncompressed = PublicKey::from_hex(
            "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352\
             2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6",
        )
        .expect("an uncompressed key");
        assert!(!uncompressed.compressed);

        assert!(
            Purpose::Bip44
                .address(&uncompressed, Network::Mainnet)
                .is_ok()
        );
        for purpose in [Purpose::Bip49, Purpose::Bip84] {
            assert_eq!(
                purpose.address(&uncompressed, Network::Mainnet),
                Err(PublicKeyError::Uncompressed),
                "{purpose}"
            );
        }
        // BIP86 is x-only, so compression never comes up: the key's `y` is
        // discarded either way.
        assert!(
            Purpose::Bip86
                .address(&uncompressed, Network::Mainnet)
                .is_ok()
        );
    }
}
