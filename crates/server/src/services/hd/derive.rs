//! Expanding a seed into the keys a derivation path names.

use std::fmt;

use serde::Deserialize;

use crate::services::default_network;
use crate::services::error::ServiceError;
use crate::services::input::{InputError, hex_bytes};
use bitcoin_tools_core::hd::path::MAX_INDEX;
use bitcoin_tools_core::hd::xkey::MAX_SEED_SIZE;
use bitcoin_tools_core::hd::{
    Bip32Error, ChildNumber, DerivationPath, ParsePathError, Purpose, Xpriv,
};
use bitcoin_tools_core::network::Network;

/// The noun this endpoint's messages use for its input.
const SUBJECT: &str = "seed";

/// One key unless asked for more: the path names a branch, and the smallest
/// useful answer is its first child.
const fn default_count() -> u32 {
    1
}

/// How many children one request may ask for.
///
/// A bound rather than a domain rule — BIP32 has none — because each key costs
/// an HMAC, a point multiplication and four addresses, and the response grows
/// with it. Twenty is what a wallet shows on a page; a hundred leaves room to
/// page through an account without letting one request derive a million keys.
pub const MAX_COUNT: u32 = 100;

/// What `/hd/derive` accepts.
///
/// [`Debug`] is hand-written, not derived: the seed is the wallet, and a
/// derived one prints it in full. Request logging is the obvious next thing
/// this server grows, and the first `tracing` layer anyone adds formats an
/// extractor's output with `{:?}`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeriveRequest {
    /// The BIP32 seed, hex — 16 to 64 bytes. `/hd/mnemonic` returns one.
    pub seed: String,
    /// The branch to derive, `m/84'/0'/0'/0`. Apostrophe or `h` for hardened.
    pub path: String,
    /// How many children of that branch to return, starting at
    /// [`start_index`](DeriveRequest::start_index). At most [`MAX_COUNT`].
    #[serde(default = "default_count")]
    pub count: u32,
    /// The first child index, so an account can be paged through.
    #[serde(default)]
    pub start_index: u32,
    /// The network the extended keys and addresses belong to.
    #[serde(default = "default_network")]
    pub network: Network,
}

impl fmt::Debug for DeriveRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeriveRequest")
            .field("seed", &"<redacted>")
            .field("path", &self.path)
            .field("count", &self.count)
            .field("start_index", &self.start_index)
            .field("network", &self.network)
            .finish()
    }
}

/// Why a seed and a path did not produce keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeriveError {
    /// The path is not a path.
    Path(ParsePathError),
    /// The seed, or a derivation from it, was refused by BIP32.
    Bip32(Bip32Error),
    /// More children than one request may ask for.
    TooMany {
        /// Children requested.
        requested: u32,
        /// The ceiling.
        max: u32,
    },
    /// The last child would be past the normal-index range.
    ///
    /// Children here are always *normal* — an address index is what BIP44 puts
    /// in the last two steps, and a hardened one could not be derived from an
    /// xpub. So the walk stops at 2³¹−1 rather than wrapping into the hardened
    /// half, which would silently return keys from a different subtree.
    IndexOutOfRange {
        /// The index that does not exist. A `u64` because it is the sum of two
        /// `u32` fields and the whole point is that it overflowed.
        index: u64,
    },
}

impl fmt::Display for DeriveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeriveError::Path(e) => write!(f, "{e}"),
            DeriveError::Bip32(e) => write!(f, "{e}"),
            DeriveError::TooMany { requested, max } => {
                write!(f, "at most {max} keys per request, asked for {requested}")
            }
            DeriveError::IndexOutOfRange { index } => write!(
                f,
                "child index {index} is past the largest normal index, {MAX_INDEX}"
            ),
        }
    }
}

impl std::error::Error for DeriveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DeriveError::Path(e) => Some(e),
            DeriveError::Bip32(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ParsePathError> for DeriveError {
    fn from(e: ParsePathError) -> Self {
        DeriveError::Path(e)
    }
}

impl From<Bip32Error> for DeriveError {
    fn from(e: Bip32Error) -> Self {
        DeriveError::Bip32(e)
    }
}

/// Lets a BIP32 failure travel out of [`derive`] on a bare `?`.
///
/// Permitted because `ServiceError` is this crate's own type; without it every
/// derivation call site needs the same `map_err` and one of them will
/// eventually get a different one.
impl From<Bip32Error> for DeriveServiceError {
    fn from(e: Bip32Error) -> Self {
        ServiceError::Domain(DeriveError::Bip32(e))
    }
}

/// Bad input, or a seed and path that do not derive.
pub type DeriveServiceError = ServiceError<DeriveError>;

/// One derived child, with the path that reached it.
#[derive(Debug)]
pub struct DerivedKey {
    pub index: u32,
    pub path: DerivationPath,
    pub key: Xpriv,
}

/// A branch and the children asked for beneath it.
#[derive(Debug)]
pub struct Derivation {
    /// The key at the requested path itself. This is the level a wallet
    /// exports: its xpub watches every child below without carrying a secret.
    pub branch: Xpriv,
    pub path: DerivationPath,
    /// What the path's first step says the addresses are for, when it says
    /// anything. `None` for a path that does not begin with a purpose BIP43
    /// has assigned — `m/0/1` is a perfectly good path that names no standard.
    pub purpose: Option<Purpose>,
    pub keys: Vec<DerivedKey>,
    pub network: Network,
}

/// Derive a branch and `count` normal children beneath it.
///
/// # Errors
///
/// [`DeriveServiceError`] for unusable hex, a seed outside 16–64 bytes, an
/// unparseable path, a count past [`MAX_COUNT`], an index past
/// [`MAX_INDEX`], or a BIP32 refusal.
pub fn derive(request: &DeriveRequest) -> Result<Derivation, DeriveServiceError> {
    if request.count > MAX_COUNT {
        return Err(ServiceError::Domain(DeriveError::TooMany {
            requested: request.count,
            max: MAX_COUNT,
        }));
    }
    // A seed is a *range*, not a width, so `hex_bytes_exact` does not apply —
    // but the same rule does: BIP32 states both ends, so both answer with
    // BIP32's error rather than one of them borrowing `input-too-large`, which
    // elsewhere means a 10 kB script. The transport cap still refuses anything
    // genuinely large before this allocates.
    let seed = hex_bytes(&request.seed, SUBJECT, MAX_SEED_SIZE).map_err(|e| match e {
        InputError::TooLarge { got_bytes, .. } => {
            ServiceError::Domain(DeriveError::Bip32(Bip32Error::SeedLength {
                got: got_bytes,
            }))
        }
        other => ServiceError::Input(other),
    })?;
    let path: DerivationPath = request
        .path
        .parse()
        .map_err(|e: ParsePathError| ServiceError::Domain(e.into()))?;

    let master = Xpriv::new_master(&seed, request.network)?;
    let branch = master.derive_path(&path)?;

    let last = u64::from(request.start_index) + u64::from(request.count.saturating_sub(1));
    if request.count > 0 && last > u64::from(MAX_INDEX) {
        return Err(ServiceError::Domain(DeriveError::IndexOutOfRange {
            index: last,
        }));
    }

    let keys = (request.start_index..)
        .take(request.count as usize)
        .map(|index| {
            // Checked above, so this cannot be `None` — but the bound is
            // enforced by the range check rather than asserted here, and a
            // `?` costs nothing.
            let step = ChildNumber::normal(index).ok_or(DeriveError::IndexOutOfRange {
                index: u64::from(index),
            })?;
            Ok(DerivedKey {
                index,
                path: path.child(step).map_err(DeriveError::from)?,
                key: branch.derive_child(step).map_err(DeriveError::from)?,
            })
        })
        .collect::<Result<Vec<_>, DeriveError>>()
        .map_err(ServiceError::Domain)?;

    Ok(Derivation {
        purpose: path
            .as_slice()
            .first()
            .and_then(|step| Purpose::from_number(step.index())),
        branch,
        path,
        keys,
        network: request.network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::input::InputError;
    use bitcoin_tools_core::hd::Mnemonic;

    /// BIP39's all-zero-entropy mnemonic, whose seed every published vector
    /// uses — so the keys below are checkable against BIP32/44/49/84/86
    /// tooling rather than against this crate.
    fn known_seed() -> String {
        let mnemonic = Mnemonic::from_entropy(&[0; 16]).expect("16 bytes is a defined size");
        bitcoin_tools_core::hex::encode(&mnemonic.to_seed(""))
    }

    fn request(path: &str, count: u32) -> DeriveRequest {
        DeriveRequest {
            seed: known_seed(),
            path: path.to_owned(),
            count,
            start_index: 0,
            network: Network::Mainnet,
        }
    }

    #[test]
    fn derives_the_branch_and_its_children() {
        let derived = derive(&request("m/84'/0'/0'/0", 3)).unwrap();

        assert_eq!(derived.path.to_string(), "m/84'/0'/0'/0");
        assert_eq!(derived.branch.depth(), 4);
        assert_eq!(derived.keys.len(), 3);
        for (i, key) in derived.keys.iter().enumerate() {
            let i = u32::try_from(i).expect("three");
            assert_eq!(key.index, i);
            assert_eq!(key.path.to_string(), format!("m/84'/0'/0'/0/{i}"));
            assert_eq!(key.key.depth(), 5);
        }
    }

    /// The path's first step is what says which standard the addresses follow.
    #[test]
    fn the_purpose_comes_from_the_path() {
        for (path, expected) in [
            ("m/44'/0'/0'/0", Some(Purpose::Bip44)),
            ("m/49'/0'/0'/0", Some(Purpose::Bip49)),
            ("m/84'/0'/0'/0", Some(Purpose::Bip84)),
            ("m/86'/0'/0'/0", Some(Purpose::Bip86)),
            // A perfectly good path that names no standard.
            ("m/0/1", None),
            ("m", None),
        ] {
            assert_eq!(
                derive(&request(path, 1)).unwrap().purpose,
                expected,
                "{path}"
            );
        }
    }

    #[test]
    fn start_index_pages_through_an_account() {
        let mut paged = request("m/84'/0'/0'/0", 2);
        paged.start_index = 5;
        let derived = derive(&paged).unwrap();

        assert_eq!(derived.keys[0].index, 5);
        assert_eq!(derived.keys[1].index, 6);
        assert_eq!(derived.keys[1].path.to_string(), "m/84'/0'/0'/0/6");

        // …and the same key comes back whichever way it was reached.
        let straight = derive(&request("m/84'/0'/0'/0", 6)).unwrap();
        assert_eq!(
            straight.keys[5].key.to_base58(),
            derived.keys[0].key.to_base58()
        );
    }

    #[test]
    fn a_count_of_zero_returns_the_branch_and_nothing_else() {
        let derived = derive(&request("m/84'/0'/0'", 0)).unwrap();
        assert!(derived.keys.is_empty());
        assert_eq!(derived.branch.depth(), 3, "the branch is still derived");
    }

    #[test]
    fn the_count_is_capped() {
        assert_eq!(
            derive(&request("m", MAX_COUNT + 1)).unwrap_err(),
            ServiceError::Domain(DeriveError::TooMany {
                requested: MAX_COUNT + 1,
                max: MAX_COUNT
            })
        );
    }

    /// Children are normal indices, so the walk stops at 2³¹−1 instead of
    /// wrapping into the hardened half and returning another subtree's keys.
    #[test]
    fn the_walk_stops_at_the_end_of_the_normal_range() {
        let mut past_the_end = request("m/84'/0'/0'/0", 2);
        past_the_end.start_index = MAX_INDEX;
        assert_eq!(
            derive(&past_the_end).unwrap_err(),
            ServiceError::Domain(DeriveError::IndexOutOfRange {
                index: u64::from(MAX_INDEX) + 1
            })
        );

        // Exactly at the end is fine.
        let mut at_the_end = request("m/84'/0'/0'/0", 1);
        at_the_end.start_index = MAX_INDEX;
        assert_eq!(derive(&at_the_end).unwrap().keys[0].index, MAX_INDEX);
    }

    #[test]
    fn a_bad_path_says_which_step() {
        let error = derive(&request("m/84'/nope/0'", 1)).unwrap_err();
        assert!(
            matches!(error, ServiceError::Domain(DeriveError::Path(_))),
            "{error:?}"
        );
        assert!(error.to_string().contains("step 2"), "{error}");
    }

    #[test]
    fn a_seed_outside_the_range_is_refused() {
        let mut short = request("m", 1);
        short.seed = "00".repeat(15);
        assert_eq!(
            derive(&short).unwrap_err(),
            ServiceError::Domain(DeriveError::Bip32(Bip32Error::SeedLength { got: 15 })),
            "the floor is a security rule, not an encoding one"
        );

        // …and past the ceiling it is the same error, because it is the same
        // rule. `input-too-large` would name one bound and borrow a slug that
        // elsewhere means a 10 kB script.
        let mut long = request("m", 1);
        long.seed = "00".repeat(MAX_SEED_SIZE + 1);
        assert_eq!(
            derive(&long).unwrap_err(),
            ServiceError::Domain(DeriveError::Bip32(Bip32Error::SeedLength {
                got: MAX_SEED_SIZE + 1
            }))
        );
    }

    /// The seed is the wallet, and `{:?}` is how it would escape.
    #[test]
    fn the_seed_does_not_appear_in_debug_output() {
        let rendered = format!("{:?}", request("m/84'/0'/0'/0", 1));
        assert!(!rendered.contains(&known_seed()), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("m/84'/0'/0'/0"),
            "…while the fields that are not secret still print: {rendered}"
        );
    }

    #[test]
    fn unusable_input_stays_an_input_error() {
        let mut empty = request("m", 1);
        empty.seed = "  ".to_owned();
        assert_eq!(
            derive(&empty).unwrap_err(),
            ServiceError::Input(InputError::Empty { subject: "seed" })
        );
    }
}
