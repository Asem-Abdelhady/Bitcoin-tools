//! Minting a BIP39 mnemonic, as a use case.

use serde::Deserialize;

use std::fmt;

use crate::services::default_network;
use bitcoin_tools_core::hd::{Bip32Error, Mnemonic, MnemonicError, SEED_SIZE, WordCount, Xpriv};
use bitcoin_tools_core::network::Network;

/// Twelve words unless asked otherwise — 128 bits of entropy, and what every
/// wallet offers first.
const fn default_word_count() -> usize {
    12
}

/// What `/hd/mnemonic` accepts.
///
/// Every field is optional, so `{}` mints a twelve-word mainnet mnemonic with
/// no passphrase.
///
/// [`Debug`] is hand-written for the passphrase's sake — see
/// [`DeriveRequest`](crate::services::hd::derive::DeriveRequest).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateMnemonicRequest {
    /// 12, 15, 18, 21 or 24 — the five lengths BIP39 defines.
    ///
    /// A plain number rather than a name, because that is how a mnemonic's
    /// length is spoken about and the domain already offers
    /// [`WordCount::from_words`] for exactly this.
    #[serde(default = "default_word_count")]
    pub word_count: usize,
    /// BIP39's optional passphrase — the "25th word".
    ///
    /// It does not change the mnemonic; it changes the *seed* the mnemonic
    /// produces, so every passphrase gives a different and equally valid
    /// wallet from the same sentence. There is no way to tell a wrong
    /// passphrase from a right one, which is the feature and the danger.
    ///
    /// **Keep the seed, not just the words.** This API cannot recompute a seed
    /// from a sentence — `/hd/derive` takes the seed, and nothing here takes a
    /// mnemonic — so the BIP39-trained habit of writing down the words and the
    /// passphrase and discarding the rest will not let you come back here. See
    /// [the module note](crate::services::hd) and `/hd/seed`, which is the
    /// endpoint that would close this.
    #[serde(default)]
    pub passphrase: String,
    /// The network the master key's version bytes name.
    #[serde(default = "default_network")]
    pub network: Network,
}

impl fmt::Debug for GenerateMnemonicRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenerateMnemonicRequest")
            .field("word_count", &self.word_count)
            .field("passphrase", &"<redacted>")
            .field("network", &self.network)
            .finish()
    }
}

/// Why a mnemonic could not be generated.
///
/// Two variants for two genuinely different failures, rather than one error
/// wearing the other's name. The alternative — deriving the master key in the
/// handler and squeezing a BIP32 failure into a `MnemonicError` — would report
/// an unusable scalar as a problem with the *words*, which is false and would
/// send a caller looking in the wrong place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateMnemonicError {
    /// A length BIP39 does not define. The only reachable one.
    Words(MnemonicError),
    /// BIP32 refusing the seed. A 64-byte seed is always the right size, so
    /// this is the 2⁻¹²⁷ case the spec calls "the master key is invalid" —
    /// unreachable in practice, and given a name anyway so it cannot become a
    /// panic or a lie.
    Master(Bip32Error),
}

impl fmt::Display for GenerateMnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GenerateMnemonicError::Words(e) => write!(f, "{e}"),
            GenerateMnemonicError::Master(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GenerateMnemonicError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            GenerateMnemonicError::Words(e) => Some(e),
            GenerateMnemonicError::Master(e) => Some(e),
        }
    }
}

/// A generated mnemonic, the seed it produces under the given passphrase, and
/// the wallet that seed roots.
///
/// All three travel together because the seed depends on the passphrase and
/// the passphrase is not stored anywhere — return them apart and a caller has
/// no way to recover the pairing.
pub struct GeneratedMnemonic {
    pub mnemonic: Mnemonic,
    pub seed: [u8; SEED_SIZE],
    /// The master key the seed roots. Built here rather than in the handler so
    /// that its one failure mode has somewhere honest to go.
    pub master: Xpriv,
    /// Whether a passphrase was applied, so the response can say so without
    /// echoing it. The passphrase is a secret in its own right and there is no
    /// reason to send one back.
    pub passphrase_used: bool,
    pub network: Network,
}

/// Redacts, because the two secrets it holds already do.
///
/// `Mnemonic` and `Xpriv` each hand-write a `Debug` that hides their contents,
/// so deriving one here would have quietly undone both — a `[u8; 64]` seed
/// prints in full, and this struct is the only place the three sit together.
impl fmt::Debug for GeneratedMnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedMnemonic")
            .field("mnemonic", &self.mnemonic)
            .field("seed", &"<redacted>")
            .field("master", &self.master)
            .field("passphrase_used", &self.passphrase_used)
            .field("network", &self.network)
            .finish()
    }
}

/// Draw a new mnemonic from the operating system's randomness.
///
/// # This endpoint hands a wallet over the wire
///
/// The same caveat as `/keys/generate`, and more so: a mnemonic is not one key
/// but every key derivable beneath it. Generated on the server's machine with
/// that machine's RNG, and travelling back in a response body, it is only as
/// private as the process, the hop, and anything logging either. A mnemonic
/// meant to hold value should be generated on the device that will keep it.
///
/// # Errors
///
/// [`GenerateMnemonicError::Words`] for a length BIP39 does not define — the
/// only one a caller can trigger. The entropy comes from the RNG at the size
/// the word count fixes, so the checksum is computed rather than checked.
pub fn generate(
    request: &GenerateMnemonicRequest,
) -> Result<GeneratedMnemonic, GenerateMnemonicError> {
    let count = WordCount::from_words(request.word_count).ok_or(GenerateMnemonicError::Words(
        MnemonicError::WordCount {
            got: request.word_count,
        },
    ))?;
    let mnemonic = Mnemonic::generate(count);
    let seed = mnemonic.to_seed(&request.passphrase);
    let master =
        Xpriv::new_master(&seed, request.network).map_err(GenerateMnemonicError::Master)?;

    Ok(GeneratedMnemonic {
        seed,
        master,
        passphrase_used: !request.passphrase.is_empty(),
        mnemonic,
        network: request.network,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(word_count: usize, passphrase: &str) -> GenerateMnemonicRequest {
        GenerateMnemonicRequest {
            word_count,
            passphrase: passphrase.to_owned(),
            network: Network::Mainnet,
        }
    }

    #[test]
    fn every_bip39_length_is_accepted() {
        for count in WordCount::all() {
            let generated = generate(&request(count.words(), "")).expect("a defined length");
            assert_eq!(generated.mnemonic.word_count(), count);
            assert_eq!(generated.mnemonic.words().len(), count.words());
            assert_eq!(generated.mnemonic.entropy().len(), count.entropy_bytes());
        }
    }

    #[test]
    fn a_length_bip39_does_not_define_is_refused() {
        assert_eq!(
            generate(&request(13, "")).unwrap_err(),
            GenerateMnemonicError::Words(MnemonicError::WordCount { got: 13 })
        );
        assert_eq!(
            generate(&request(0, "")).unwrap_err(),
            GenerateMnemonicError::Words(MnemonicError::WordCount { got: 0 })
        );
    }

    /// The passphrase changes the seed and nothing else — which is the whole
    /// of BIP39's "25th word", and the reason a wrong one is undetectable.
    #[test]
    fn the_passphrase_changes_the_seed_and_not_the_words() {
        let mnemonic = generate(&request(12, "")).expect("twelve words").mnemonic;
        let plain = mnemonic.to_seed("");
        let with_passphrase = mnemonic.to_seed("TREZOR");

        assert_ne!(plain, with_passphrase);
        assert_eq!(
            mnemonic.to_phrase(),
            mnemonic.to_phrase(),
            "the sentence is unchanged by either"
        );
        assert_eq!(plain.len(), SEED_SIZE);
    }

    /// The master key is the seed's, so it must move with the passphrase too.
    #[test]
    fn the_master_key_follows_the_seed() {
        let generated = generate(&request(12, "")).unwrap();
        assert_eq!(generated.master.depth(), 0, "the master is at depth 0");
        assert!(generated.master.parent_fingerprint().is_master());
        assert_eq!(
            generated.master.to_base58(),
            Xpriv::new_master(&generated.seed, Network::Mainnet)
                .unwrap()
                .to_base58(),
            "…and it is the key that seed roots, not another one"
        );
    }

    #[test]
    fn passphrase_used_reports_without_echoing() {
        assert!(!generate(&request(12, "")).unwrap().passphrase_used);
        assert!(generate(&request(12, "hunter2")).unwrap().passphrase_used);
    }

    /// Not a test of the RNG. It rules out the failure that would matter.
    #[test]
    fn two_draws_differ() {
        let a = generate(&request(24, "")).unwrap();
        let b = generate(&request(24, "")).unwrap();
        assert_ne!(a.mnemonic.entropy(), b.mnemonic.entropy());
    }

    /// A passphrase is a secret in its own right, and `{:?}` is how it would
    /// reach a log line.
    #[test]
    fn the_passphrase_does_not_appear_in_debug_output() {
        let rendered = format!("{:?}", request(12, "hunter2"));
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("word_count: 12"), "{rendered}");
    }

    /// The generated secrets, on the way back out.
    #[test]
    fn a_generated_wallet_does_not_appear_in_debug_output() {
        let generated = generate(&request(12, "")).unwrap();
        let rendered = format!("{generated:?}");
        assert!(!rendered.contains(&bitcoin_tools_core::hex::encode(&generated.seed)));
        assert!(!rendered.contains(&generated.mnemonic.to_phrase()));
        assert!(!rendered.contains(&generated.master.to_base58()));
    }

    #[test]
    fn the_defaults_are_the_ones_documented() {
        let request: GenerateMnemonicRequest = serde_json::from_str("{}").expect("an empty object");
        assert_eq!(request.word_count, 12);
        assert!(request.passphrase.is_empty());
        assert_eq!(request.network, Network::Mainnet);
    }
}
