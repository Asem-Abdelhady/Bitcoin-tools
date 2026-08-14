//! HTTP surface for mnemonic generation.

use std::fmt;

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::{ApiError, ApiRejection};
use crate::handlers::hd::ExtendedKeyView;
use crate::handlers::{NO_STORE, Secret};
use crate::services::hd::mnemonic::{GenerateMnemonicError, GenerateMnemonicRequest, generate};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::network::Network;

/// A mnemonic taken apart — the words, and what they are made of.
///
/// BIP39 is one of the few places in Bitcoin where a human-readable form is
/// the canonical one, so showing the machinery underneath is most of the
/// point: the entropy is the actual secret, the words are a rendering of it,
/// and the checksum is what makes a typo detectable.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicView {
    /// The sentence, space-separated. This is what gets written down.
    pub phrase: String,
    /// The same words as a list, for a caller that wants to number them.
    pub words: Vec<&'static str>,
    /// Each word's position in the 2048-word list, which is the eleven bits it
    /// actually encodes.
    pub indices: Vec<u16>,
    /// The entropy the words spell, hex. This — not the sentence — is the
    /// secret; the sentence is a way of writing it down that survives being
    /// read aloud.
    pub entropy: String,
    /// 128, 160, 192, 224 or 256.
    pub entropy_bits: usize,
    /// The number of words: 12, 15, 18, 21 or 24.
    pub word_count: usize,
    /// The checksum bits carried by the final word, right-aligned in a byte.
    ///
    /// Hex rather than a number because it is a bit field, and how many of
    /// those bits are meaningful is [`checksum_bits`](MnemonicView::checksum_bits)
    /// — four for a twelve-word mnemonic, eight for a twenty-four.
    pub checksum: String,
    /// How many of the checksum's bits are meaningful: entropy bits ÷ 32.
    pub checksum_bits: usize,
}

/// Redacts the four fields that are the wallet, and prints the four that are
/// only its shape.
///
/// `phrase`, `words`, `indices` and `entropy` are one secret written four
/// ways. The sizes and the checksum are not: they are fixed by the word count,
/// which a caller sent in the request.
impl fmt::Debug for MnemonicView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MnemonicView")
            .field("phrase", &"<redacted>")
            .field("words", &"<redacted>")
            .field("indices", &"<redacted>")
            .field("entropy", &"<redacted>")
            .field("entropy_bits", &self.entropy_bits)
            .field("word_count", &self.word_count)
            .field("checksum", &self.checksum)
            .field("checksum_bits", &self.checksum_bits)
            .finish()
    }
}

/// A mnemonic, the seed it produces, and the wallet that seed roots.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateMnemonicResponse {
    /// The network the master key's version bytes name.
    pub network: Network,
    pub mnemonic: MnemonicView,
    /// Whether a passphrase was applied.
    ///
    /// The passphrase itself is never echoed — it is a secret in its own right
    /// and the caller already has it. This flag exists so a caller can confirm
    /// the field registered, since a passphrase that was silently ignored
    /// produces a different wallet with no other sign.
    pub passphrase_used: bool,
    /// The 64-byte BIP32 seed, hex. Feed this to `/hd/derive`.
    ///
    /// It depends on both the mnemonic *and* the passphrase, so a different
    /// passphrase over the same sentence gives a different and equally valid
    /// wallet — with no way to tell which was intended.
    pub seed: String,
    /// The master key the seed produces, `m`.
    pub master_key: ExtendedKeyView,
}

/// The one composite that cannot simply derive: `seed` is its own field, and a
/// `String` prints itself.
impl fmt::Debug for GenerateMnemonicResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GenerateMnemonicResponse")
            .field("network", &self.network)
            .field("mnemonic", &self.mnemonic)
            .field("passphrase_used", &self.passphrase_used)
            .field("seed", &"<redacted>")
            .field("master_key", &self.master_key)
            .finish()
    }
}

/// `POST /hd/mnemonic`
///
/// Every field is optional, so `{}` mints a twelve-word mainnet mnemonic.
pub async fn post_generate_mnemonic(
    payload: Result<Json<GenerateMnemonicRequest>, JsonRejection>,
) -> Result<Secret<GenerateMnemonicResponse>, ApiRejection<GenerateMnemonicError>> {
    let Json(request) = payload?;
    let generated = generate(&request).map_err(ApiRejection::Domain)?;

    let mnemonic = &generated.mnemonic;
    let count = mnemonic.word_count();

    Ok((
        NO_STORE,
        Json(GenerateMnemonicResponse {
            network: generated.network,
            mnemonic: MnemonicView {
                phrase: mnemonic.to_phrase(),
                words: mnemonic.words(),
                indices: mnemonic.indices(),
                entropy: hex::encode(mnemonic.entropy()),
                entropy_bits: count.entropy_bytes() * 8,
                word_count: count.words(),
                checksum: format!("{:02x}", mnemonic.checksum()),
                checksum_bits: count.checksum_bits(),
            },
            passphrase_used: generated.passphrase_used,
            seed: hex::encode(&generated.seed),
            master_key: ExtendedKeyView::of(&generated.master, "m".to_string()),
        }),
    ))
}

/// This endpoint's failure vocabulary, beside the endpoint that needs it.
///
/// Both variants are a 400: a word count BIP39 does not define is the caller's
/// mistake, and the unreachable master-key failure is not something a status
/// code can usefully distinguish.
impl ApiError for GenerateMnemonicError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            GenerateMnemonicError::Words(_) => "invalid-word-count",
            GenerateMnemonicError::Master(_) => "invalid-seed",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::hd::ExtendedKeyView;
    use crate::services::hd::mnemonic::{GenerateMnemonicRequest, generate};

    /// Every secret this endpoint returns, through the whole composite: the
    /// phrase, the entropy, the seed and the xprv.
    #[test]
    fn no_part_of_the_wallet_appears_in_debug_output() {
        let request = GenerateMnemonicRequest {
            word_count: 12,
            passphrase: String::new(),
            network: Network::Mainnet,
        };
        let generated = generate(&request).expect("twelve words");
        let mnemonic = &generated.mnemonic;
        let count = mnemonic.word_count();

        let response = GenerateMnemonicResponse {
            network: generated.network,
            mnemonic: MnemonicView {
                phrase: mnemonic.to_phrase(),
                words: mnemonic.words(),
                indices: mnemonic.indices(),
                entropy: hex::encode(mnemonic.entropy()),
                entropy_bits: count.entropy_bytes() * 8,
                word_count: count.words(),
                checksum: format!("{:02x}", mnemonic.checksum()),
                checksum_bits: count.checksum_bits(),
            },
            passphrase_used: generated.passphrase_used,
            seed: hex::encode(&generated.seed),
            master_key: ExtendedKeyView::of(&generated.master, "m".to_string()),
        };
        let rendered = format!("{response:?}");

        for secret in [
            mnemonic.to_phrase(),
            hex::encode(mnemonic.entropy()),
            hex::encode(&generated.seed),
            generated.master.to_base58(),
        ] {
            assert!(!rendered.contains(&secret), "{secret} leaked: {rendered}");
        }
        // The first word on its own would be enough to start guessing.
        assert!(!rendered.contains(mnemonic.words()[0]), "{rendered}");

        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("word_count: 12") && rendered.contains("xpub"),
            "…and the public half still prints: {rendered}"
        );
    }
}
