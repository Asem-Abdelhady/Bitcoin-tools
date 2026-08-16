//! `hd mnemonic` — a new BIP39 sentence, and the wallet under it.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::hd::{Mnemonic, WordCount, Xpriv};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::network::Network;

use crate::commands::hd::{ExtendedKeyView, write_extended_key};
use crate::commands::keys::default_network;
use crate::input;
use crate::output::{Context, Fields, Output, yes_no};

/// The word count a request with no opinion gets.
///
/// Twelve, matching the API — 128 bits of entropy, which is what every wallet
/// offers first and is not the weak link in anything.
const fn default_word_count() -> usize {
    12
}

/// A word count, refused at parse time if BIP39 does not define it.
fn word_count(value: &str) -> Result<usize, String> {
    let words: usize = value
        .parse()
        .map_err(|_| format!("{value:?} is not a number"))?;

    WordCount::from_words(words)
        .map(|_| words)
        .ok_or_else(|| "a BIP39 word count is 12, 15, 18, 21 or 24".to_owned())
}

/// What `hd mnemonic` accepts.
///
/// Nothing is required: `hd mnemonic` on its own is twelve mainnet words with no
/// passphrase. `--input` replaces all three flags and therefore conflicts with
/// them, rather than joining them in a group that would forbid using two
/// together.
#[derive(Debug, clap::Args)]
#[command(override_usage = "bt hd mnemonic [--words <N>] \
                            [--passphrase-file <FILE>] [--network <NETWORK>]\n\
                          \x20      bt hd mnemonic --input <FILE>")]
pub struct Args {
    /// How many words: 12, 15, 18, 21 or 24.
    ///
    /// Each step is 32 more bits of entropy and one more checksum bit. Twelve is
    /// 128 bits, which is not the weak link in any wallet.
    // Checked at parse time, so a wrong *argument* exits 2 like `--network foo`
    // and `--type foo` do. The same check runs again in `run`, because a request
    // file can carry a word count too and that one is data rather than argv.
    #[arg(long, value_name = "N", default_value_t = default_word_count(),
          value_parser = word_count)]
    words: usize,

    /// A file holding the BIP39 passphrase, or `-` for stdin.
    ///
    /// The "25th word": it changes the seed completely, is not recoverable from
    /// the sentence, and is not checksummed — a typo in it silently opens a
    /// different, empty wallet. There is deliberately no flag that takes it
    /// inline.
    #[arg(long, value_name = "FILE")]
    passphrase_file: Option<PathBuf>,

    /// Which network the master key is for.
    #[arg(long, value_name = "NETWORK", default_value_t = default_network())]
    network: Network,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds {"wordCount"?, "passphrase"?, "network"?} — the HTTP API's
    /// request body, in which all three are optional.
    #[arg(long, value_name = "FILE",
          conflicts_with_all = ["words", "passphrase_file", "network"])]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
///
/// Hand-writes `Debug`: it holds the passphrase.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    #[serde(default = "default_word_count")]
    word_count: usize,
    #[serde(default)]
    passphrase: String,
    #[serde(default = "default_network")]
    network: Network,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("word_count", &self.word_count)
            .field("passphrase", &"<redacted>")
            .field("network", &self.network)
            .finish()
    }
}

/// A sentence, and everything it is made of.
///
/// # This type hand-writes its `Debug`
///
/// The phrase, the words, the indices and the entropy are four spellings of one
/// secret — reconstructing any of them reconstructs the wallet. The counts and
/// the checksum keep printing, because they are what makes a `Debug` worth
/// having.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MnemonicView {
    /// The sentence, space-separated.
    phrase: String,
    /// The same words, as a list.
    words: Vec<&'static str>,
    /// Each word's index in the BIP39 English wordlist.
    indices: Vec<u16>,
    /// The entropy the words encode, hex.
    entropy: String,
    /// How many bits of it there are.
    entropy_bits: usize,
    /// How many words that is.
    word_count: usize,
    /// The checksum byte, right-aligned in a byte.
    checksum: String,
    /// How many of its bits are the checksum.
    checksum_bits: usize,
}

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

/// A generated wallet, from the words down to the master key.
///
/// # This type hand-writes its `Debug`
///
/// `seed` is a bare hex string sitting beside two composites that redact
/// themselves, and it is the one field a derived `Debug` would print in full.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateMnemonicResponse {
    network: Network,
    mnemonic: MnemonicView,
    /// Whether a passphrase went into the seed. Not the passphrase.
    passphrase_used: bool,
    /// The 64-byte seed the sentence and passphrase derive, hex.
    seed: String,
    master_key: ExtendedKeyView,
}

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

impl Output for GenerateMnemonicResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields
            .row("network", self.network)
            .row("passphraseUsed", yes_no(self.passphrase_used))
            .blank()
            .row("phrase", &self.mnemonic.phrase)
            .row("wordCount", self.mnemonic.word_count)
            .row("entropy", &self.mnemonic.entropy)
            .row("entropyBits", self.mnemonic.entropy_bits)
            .row("checksum", &self.mnemonic.checksum)
            .row("checksumBits", self.mnemonic.checksum_bits)
            .row(
                "indices",
                self.mnemonic
                    .indices
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(" "),
            )
            .blank()
            .row("seed", &self.seed);

        write_extended_key(w, &mut fields, "masterKey", &self.master_key)
    }
}

/// Generate the sentence, derive the seed and the master key, emit.
///
/// # Errors
///
/// If the request cannot be read, the word count is not one of the five BIP39
/// defines, or the seed is one BIP32 refuses.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let passphrase_file = args.passphrase_file.take();

    let request: Request = input::resolve_reading(source.as_deref(), || {
        Ok(Some(Request {
            word_count: args.words,
            passphrase: match passphrase_file.as_deref() {
                Some(path) => input::secret_from(path)?,
                None => String::new(),
            },
            network: args.network,
        }))
    })?;

    let count = WordCount::from_words(request.word_count).with_context(|| {
        format!(
            "{} is not a BIP39 word count; it is 12, 15, 18, 21 or 24",
            request.word_count
        )
    })?;

    let mnemonic = Mnemonic::generate(count);
    let seed = mnemonic.to_seed(&request.passphrase);
    let master = Xpriv::new_master(&seed, request.network).context("deriving the master key")?;

    ctx.emit(&GenerateMnemonicResponse {
        network: request.network,
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
        passphrase_used: !request.passphrase.is_empty(),
        seed: hex::encode(&seed),
        master_key: ExtendedKeyView::of(&master, "m".to_owned()),
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(passphrase: &str) -> (Mnemonic, [u8; 64], Xpriv, GenerateMnemonicResponse) {
        let count = WordCount::from_words(12).expect("twelve");
        let mnemonic = Mnemonic::generate(count);
        let seed = mnemonic.to_seed(passphrase);
        let master = Xpriv::new_master(&seed, Network::Mainnet).expect("a generated seed");

        let response = GenerateMnemonicResponse {
            network: Network::Mainnet,
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
            passphrase_used: !passphrase.is_empty(),
            seed: hex::encode(&seed),
            master_key: ExtendedKeyView::of(&master, "m".to_owned()),
        };

        (mnemonic, seed, master, response)
    }

    /// Every spelling of the wallet is redacted, and the public half is not —
    /// a `Debug` that blanked the struct would pass half of this and lose the
    /// only reason it exists.
    #[test]
    fn no_part_of_the_wallet_appears_in_debug_output() {
        let (mnemonic, seed, master, response) = response("");
        let rendered = format!("{response:?}");

        for secret in [
            mnemonic.to_phrase(),
            hex::encode(mnemonic.entropy()),
            hex::encode(&seed),
            master.to_base58(),
        ] {
            assert!(!rendered.contains(&secret), "{secret} leaked: {rendered}");
        }
        assert!(!rendered.contains(mnemonic.words()[0]), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("word_count: 12") && rendered.contains("xpub"),
            "…and the public half still prints: {rendered}"
        );
    }

    /// A sentinel, not a memorable phrase.
    ///
    /// The sentence this test renders is **generated**, so a passphrase built
    /// out of wordlist words can turn up in it by chance and fail the test for
    /// a leak that never happened. `correct horse battery staple` did exactly
    /// that: `horse` is BIP39 word 889, and twelve draws from 2048 hit it about
    /// once in every 170 runs.
    ///
    /// The hyphens are what make this safe. A BIP39 sentence is lowercase
    /// letters and spaces, entropy and seeds are hex, and the extended keys are
    /// base58 — none of those alphabets contains `-`, so neither of the strings
    /// below can appear in this response unless the passphrase itself was
    /// printed.
    const PASSPHRASE: &str = "correct-horse-battery-staple-42";

    /// A prefix of [`PASSPHRASE`], so a leak of *part* of it still fails.
    const LEAK_FRAGMENT: &str = "correct-horse";

    /// The request holds the passphrase, so its `Debug` redacts it — and the
    /// answer reports only *whether* one was used.
    #[test]
    fn the_passphrase_is_never_printed_back() {
        let request = Request {
            word_count: 12,
            passphrase: PASSPHRASE.to_owned(),
            network: Network::Mainnet,
        };
        let rendered = format!("{request:?}");
        assert!(!rendered.contains(PASSPHRASE), "{rendered}");
        assert!(!rendered.contains(LEAK_FRAGMENT), "{rendered}");

        let (_, _, _, response) = response(PASSPHRASE);
        let json = serde_json::to_string(&response).unwrap();
        assert!(!json.contains(PASSPHRASE), "{json}");
        assert!(!json.contains(LEAK_FRAGMENT), "{json}");
        assert!(json.contains(r#""passphraseUsed":true"#), "{json}");
    }

    /// A passphrase changes the seed completely and is not recoverable from the
    /// sentence, which is why a typo in one is a silently different wallet.
    #[test]
    fn a_passphrase_produces_a_different_seed_from_the_same_words() {
        let mnemonic = Mnemonic::generate(WordCount::from_words(12).unwrap());

        assert_ne!(mnemonic.to_seed(""), mnemonic.to_seed("x"));
    }

    #[test]
    fn an_empty_request_file_is_twelve_mainnet_words() {
        let request: Request = serde_json::from_str("{}").unwrap();

        assert_eq!(request.word_count, 12);
        assert_eq!(request.network, Network::Mainnet);
        assert!(request.passphrase.is_empty());
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"wordcount":24}"#).is_err());
    }
}
