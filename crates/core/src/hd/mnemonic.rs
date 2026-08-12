//! § 4.1 — BIP39 mnemonic seeds.
//!
//! Entropy ⇄ sentence ⇄ seed. The sentence is a *rendering* of the entropy,
//! not a second copy of it, which is why this type stores only the entropy and
//! derives everything else: there is no state in which the words and the bytes
//! disagree.

use std::fmt;
use std::str::FromStr;

use unicode_normalization::UnicodeNormalization;

use crate::bytes;
use crate::hashes::{SHA512_SIZE, pbkdf2_hmac_sha512, sha256};
use crate::hd::wordlist::{self, BITS_PER_WORD};

/// [`BITS_PER_WORD`] in the width [`bytes::pack_bits`] takes.
const BITS_PER_WORD_U32: u32 = BITS_PER_WORD as u32;

/// Bytes in the seed a mnemonic produces: 512 bits, whatever the word count.
pub const SEED_SIZE: usize = SHA512_SIZE;

/// PBKDF2 iterations BIP39 specifies. Fixed by the standard — a different
/// number is a different seed, so this is not a tuning knob.
pub const PBKDF2_ROUNDS: u32 = 2048;

/// The literal BIP39 prepends to the passphrase to make the PBKDF2 salt.
const SALT_PREFIX: &str = "mnemonic";

/// How long a mnemonic is, which fixes its entropy and checksum sizes too.
///
/// Not `#[non_exhaustive]`: BIP39 defines these five and [`WordCount::all`]
/// promises to return all of them. A sixth would be a new standard, not a new
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WordCount {
    /// 12 words — 128 bits of entropy, 4 checksum bits.
    Twelve,
    /// 15 words — 160 bits of entropy, 5 checksum bits.
    Fifteen,
    /// 18 words — 192 bits of entropy, 6 checksum bits.
    Eighteen,
    /// 21 words — 224 bits of entropy, 7 checksum bits.
    TwentyOne,
    /// 24 words — 256 bits of entropy, 8 checksum bits.
    TwentyFour,
}

impl WordCount {
    /// Every length BIP39 defines, shortest first.
    #[must_use]
    pub const fn all() -> [WordCount; 5] {
        [
            WordCount::Twelve,
            WordCount::Fifteen,
            WordCount::Eighteen,
            WordCount::TwentyOne,
            WordCount::TwentyFour,
        ]
    }

    /// The number of words.
    #[must_use]
    pub const fn words(self) -> usize {
        match self {
            WordCount::Twelve => 12,
            WordCount::Fifteen => 15,
            WordCount::Eighteen => 18,
            WordCount::TwentyOne => 21,
            WordCount::TwentyFour => 24,
        }
    }

    /// The length a word count names, or `None` for anything else.
    ///
    /// The way a caller that has a number — a CLI argument, a JSON field —
    /// gets a `WordCount` without this module having to grow a `FromStr` for
    /// what is already an integer.
    #[must_use]
    pub const fn from_words(words: usize) -> Option<Self> {
        match words {
            12 => Some(WordCount::Twelve),
            15 => Some(WordCount::Fifteen),
            18 => Some(WordCount::Eighteen),
            21 => Some(WordCount::TwentyOne),
            24 => Some(WordCount::TwentyFour),
            _ => None,
        }
    }

    /// Bytes of entropy behind a mnemonic this long: 16, 20, 24, 28 or 32.
    #[must_use]
    pub const fn entropy_bytes(self) -> usize {
        // Every word carries 11 bits, of which the checksum takes ENT/32. So
        // words * 11 = ENT + ENT/32, and ENT = words * 32 / 3 bits.
        self.words() * 4 / 3
    }

    /// Checksum bits, which is the entropy size in bits over 32: 4 to 8.
    #[must_use]
    pub const fn checksum_bits(self) -> usize {
        self.entropy_bytes() * 8 / 32
    }

    /// The length for a given entropy size, or `None` if that size is not one
    /// BIP39 defines.
    #[must_use]
    pub const fn from_entropy_bytes(bytes: usize) -> Option<Self> {
        match bytes {
            16 => Some(WordCount::Twelve),
            20 => Some(WordCount::Fifteen),
            24 => Some(WordCount::Eighteen),
            28 => Some(WordCount::TwentyOne),
            32 => Some(WordCount::TwentyFour),
            _ => None,
        }
    }
}

/// Why a byte string or a sentence is not a mnemonic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MnemonicError {
    /// Entropy of a size BIP39 does not define. It must be 16, 20, 24, 28 or
    /// 32 bytes — 128 to 256 bits in steps of 32.
    EntropyLength {
        /// Bytes supplied.
        got: usize,
    },
    /// A sentence whose word count is not 12, 15, 18, 21 or 24.
    WordCount {
        /// Words counted.
        got: usize,
    },
    /// A word outside the list. The position is what a caller needs in order
    /// to point at it — this is the error a typed backup actually produces.
    UnknownWord {
        /// Zero-based position in the sentence.
        position: usize,
        /// The word that is not in the list.
        word: String,
    },
    /// The trailing checksum bits do not match the entropy the words carry.
    /// Both values are given, right-aligned in a byte, because a tool should
    /// be able to show the difference rather than only announce it.
    Checksum {
        /// The bits the sentence carried.
        found: u8,
        /// The bits its entropy implies.
        expected: u8,
    },
}

impl fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MnemonicError::EntropyLength { got } => write!(
                f,
                "a mnemonic holds 16, 20, 24, 28 or 32 bytes of entropy, got {got}"
            ),
            MnemonicError::WordCount { got } => {
                write!(f, "a mnemonic is 12, 15, 18, 21 or 24 words, got {got}")
            }
            MnemonicError::UnknownWord { position, word } => {
                write!(f, "word {} is not in the list: {word:?}", position + 1)
            }
            MnemonicError::Checksum { found, expected } => write!(
                f,
                "checksum is {found:#04x} but this entropy implies {expected:#04x}"
            ),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// A BIP39 mnemonic: entropy, and the sentence that spells it.
///
/// # What it stores
///
/// The entropy, and nothing else. The words, the checksum and the eleven-bit
/// indices are all computed, so they cannot drift apart from it — a type
/// holding both a `Vec<String>` and a `Vec<u8>` has a state where they
/// disagree, and no way to say which one is the mnemonic.
///
/// # It is a secret
///
/// A mnemonic *is* the wallet. So this type follows
/// [`PrivateKey`](crate::keys::PrivateKey) exactly: a [`Debug`](fmt::Debug)
/// that redacts, no `Display`, no `Serialize`, and getting the words out means
/// naming [`Mnemonic::to_phrase`]. [`FromStr`] is implemented, because reading
/// a secret is not a leak.
///
/// ```
/// use bitcoin_tools_core::hd::Mnemonic;
///
/// // The all-zero entropy, whose sentence is the one every BIP39 test uses.
/// let mnemonic = Mnemonic::from_entropy(&[0; 16])?;
/// assert_eq!(
///     mnemonic.to_phrase(),
///     "abandon abandon abandon abandon abandon abandon \
///      abandon abandon abandon abandon abandon about"
/// );
///
/// // …and it reads back to the entropy it came from.
/// let parsed: Mnemonic = mnemonic.to_phrase().parse()?;
/// assert_eq!(parsed.entropy(), &[0; 16]);
/// # Ok::<_, bitcoin_tools_core::hd::MnemonicError>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Mnemonic {
    /// 16 to 32 bytes, checked on the way in. The words, the indices and the
    /// checksum are all views of this.
    entropy: Vec<u8>,
    /// Implied by `entropy.len()`, and stored anyway so that implication is
    /// resolved once — in the constructor, where the length was checked —
    /// rather than re-derived by every accessor with a "this cannot fail"
    /// fallback to get wrong.
    count: WordCount,
}

impl Mnemonic {
    /// Wrap entropy of a size BIP39 defines.
    ///
    /// # Errors
    ///
    /// [`MnemonicError::EntropyLength`] for any other size.
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, MnemonicError> {
        // The size is validated by asking whether a word count exists for it,
        // so the two tables cannot disagree about which sizes are legal.
        let count = WordCount::from_entropy_bytes(entropy.len())
            .ok_or(MnemonicError::EntropyLength { got: entropy.len() })?;
        Ok(Mnemonic {
            entropy: entropy.to_vec(),
            count,
        })
    }

    /// Generate a mnemonic from the operating system's randomness.
    ///
    /// Behind the `rand` feature, for the reason
    /// [`PrivateKey::generate`](crate::keys::PrivateKey::generate) is: a tool
    /// that inspects a backup should not be able to mint one by accident.
    #[cfg(feature = "rand")]
    #[must_use]
    pub fn generate(count: WordCount) -> Self {
        use rand::RngCore;
        let mut entropy = vec![0u8; count.entropy_bytes()];
        rand::rng().fill_bytes(&mut entropy);
        Mnemonic { entropy, count }
    }

    /// Read a sentence, checking its checksum.
    ///
    /// # What counts as a sentence someone may have typed
    ///
    /// The input is NFKD-normalised, then split on any run of whitespace, and
    /// each word is compared case-insensitively. A backup written in capitals,
    /// with a newline every three words, or pasted with a trailing space, is
    /// the same mnemonic.
    ///
    /// Being lenient here is safe in a way it would not be in a wallet that
    /// hashed the caller's string directly: [`Mnemonic::to_seed`] hashes the
    /// canonical sentence this type *re-renders* from the entropy, so a
    /// leniently-read mnemonic still produces the standard seed rather than a
    /// seed nobody else can reproduce.
    ///
    /// # Errors
    ///
    /// [`MnemonicError::WordCount`] for a length BIP39 does not define,
    /// [`MnemonicError::UnknownWord`] naming the first word outside the list,
    /// or [`MnemonicError::Checksum`] when the trailing bits disagree with the
    /// entropy.
    pub fn parse(sentence: &str) -> Result<Self, MnemonicError> {
        let normalised: String = sentence.nfkd().collect();
        let words: Vec<&str> = normalised.split_whitespace().collect();
        let count = WordCount::from_words(words.len())
            .ok_or(MnemonicError::WordCount { got: words.len() })?;

        let mut indices = Vec::with_capacity(words.len());
        for (position, word) in words.iter().enumerate() {
            let lowered = word.to_lowercase();
            let index = wordlist::index_of(&lowered).ok_or_else(|| MnemonicError::UnknownWord {
                position,
                word: (*word).to_owned(),
            })?;
            indices.push(index);
        }

        // Repack the eleven-bit groups as bytes. The entropy comes out whole
        // and the checksum lands in the top of one more byte, because
        // `words * 11` is `entropy bits + checksum bits` and nothing else.
        let unpacked: Vec<u8> = bytes::pack_bits(indices, BITS_PER_WORD_U32, 8)
            .into_iter()
            .map(|byte| (byte & 0xff) as u8)
            .collect();
        let (entropy, tail) = unpacked.split_at(count.entropy_bytes());

        // The checksum occupies the top `checksum_bits` of the next byte; the
        // rest of that byte is padding this writer zeroed.
        let shift = 8 - count.checksum_bits();
        let found = tail.first().copied().unwrap_or(0) >> shift;
        let expected = checksum_of(entropy, count);
        if found != expected {
            return Err(MnemonicError::Checksum { found, expected });
        }
        Ok(Mnemonic {
            entropy: entropy.to_vec(),
            count,
        })
    }

    /// The entropy the sentence encodes.
    #[must_use]
    pub fn entropy(&self) -> &[u8] {
        &self.entropy
    }

    /// How long this mnemonic is.
    #[must_use]
    pub const fn word_count(&self) -> WordCount {
        self.count
    }

    /// The checksum bits, right-aligned in a byte.
    ///
    /// Four to eight bits taken from the top of `SHA256(entropy)`. Exposed
    /// because "which bits are the checksum" is exactly the question a tool
    /// showing a mnemonic should be able to answer.
    #[must_use]
    pub fn checksum(&self) -> u8 {
        checksum_of(&self.entropy, self.word_count())
    }

    /// The eleven-bit value of each word — the numbers the sentence really is.
    #[must_use]
    pub fn indices(&self) -> Vec<u16> {
        let count = self.word_count();
        let mut buf = self.entropy.clone();
        // The checksum bits sit at the top of one appended byte, which is
        // exactly where the last word's low bits read from.
        buf.push(self.checksum() << (8 - count.checksum_bits()));

        // One group past the words comes back, because the appended byte is
        // eight bits where the checksum needs four to eight — the extra is
        // padding this discards.
        let mut groups = bytes::pack_bits(buf.into_iter().map(u16::from), 8, BITS_PER_WORD_U32);
        groups.truncate(count.words());
        groups
    }

    /// The words, in order.
    #[must_use]
    pub fn words(&self) -> Vec<&'static str> {
        self.indices()
            .into_iter()
            // Every index came from eleven bits, so it is below 2048 and the
            // lookup cannot miss.
            .filter_map(wordlist::word)
            .collect()
    }

    /// The sentence: the words joined by single spaces.
    ///
    /// This is the canonical rendering, and the string
    /// [`Mnemonic::to_seed`] hashes.
    #[must_use]
    pub fn to_phrase(&self) -> String {
        self.words().join(" ")
    }

    /// The 512-bit seed, optionally stretched by a passphrase.
    ///
    /// `PBKDF2-HMAC-SHA512(phrase, "mnemonic" + passphrase, 2048)`. Pass `""`
    /// for no passphrase — that is the standard case, and it is not a special
    /// case in the algorithm.
    ///
    /// # The passphrase is a second secret, not a password
    ///
    /// There is no wrong passphrase. Every one of them produces a valid seed,
    /// and therefore a different, equally real wallet. That is the feature —
    /// it is what "plausible deniability" means here — and it is also why a
    /// typo in a passphrase silently empties a wallet.
    ///
    /// Both strings are NFKD-normalised, as BIP39 requires. For the sentence
    /// that is a formality, since this crate renders it from the ASCII English
    /// list; for the passphrase it is not, and a passphrase containing
    /// composed accents would otherwise derive a seed no other wallet agrees
    /// with.
    #[must_use]
    pub fn to_seed(&self, passphrase: &str) -> [u8; SEED_SIZE] {
        let phrase: String = self.to_phrase().nfkd().collect();
        let salt: String = format!("{SALT_PREFIX}{passphrase}").nfkd().collect();
        pbkdf2_hmac_sha512(phrase.as_bytes(), salt.as_bytes(), PBKDF2_ROUNDS)
    }
}

/// The first `checksum_bits` of `SHA256(entropy)`, right-aligned in a byte.
///
/// One definition, used by both directions — rendering a mnemonic and checking
/// one — so the two cannot disagree about which bits these are. The count is
/// at most eight, so the first byte of the digest is all that is ever read.
fn checksum_of(entropy: &[u8], count: WordCount) -> u8 {
    let digest = sha256(entropy);
    digest[0] >> (8 - count.checksum_bits())
}

impl FromStr for Mnemonic {
    type Err = MnemonicError;

    /// Reads a sentence — see [`Mnemonic::parse`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Mnemonic::parse(s)
    }
}

/// Redacted. The word count is safe to show and is the field worth having when
/// something is wrong; the words are the wallet.
impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("words", &self.word_count().words())
            .field("entropy", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// The sentence for all-zero entropy, which is the one every BIP39-adjacent
    /// standard uses in its own vectors.
    const ZERO_12: &str = "abandon abandon abandon abandon abandon abandon \
                           abandon abandon abandon abandon abandon about";

    #[test]
    fn the_word_count_tables_agree_with_each_other() {
        for count in WordCount::all() {
            assert_eq!(WordCount::from_words(count.words()), Some(count));
            assert_eq!(
                WordCount::from_entropy_bytes(count.entropy_bytes()),
                Some(count)
            );
            // The defining relation: every word is 11 bits, and the checksum
            // is one bit per 32 bits of entropy.
            assert_eq!(
                count.words() * BITS_PER_WORD,
                count.entropy_bytes() * 8 + count.checksum_bits(),
                "{count:?} does not add up"
            );
            assert!((4..=8).contains(&count.checksum_bits()));
        }
        assert_eq!(WordCount::from_words(13), None);
        assert_eq!(WordCount::from_entropy_bytes(31), None);
    }

    #[test]
    fn renders_the_canonical_zero_sentence() {
        let mnemonic = Mnemonic::from_entropy(&[0; 16]).unwrap();
        assert_eq!(mnemonic.to_phrase(), ZERO_12);
        assert_eq!(mnemonic.word_count(), WordCount::Twelve);
        // Eleven words of index 0, and a last word carrying the checksum.
        assert_eq!(mnemonic.indices()[..11], [0u16; 11]);
        assert_eq!(mnemonic.words()[0], "abandon");
        assert_eq!(mnemonic.words()[11], "about");
        // `about` is index 3, which is the four checksum bits of SHA256(0…0).
        assert_eq!(mnemonic.indices()[11], 3);
        assert_eq!(mnemonic.checksum(), 3);
    }

    #[test]
    fn round_trips_at_every_length() {
        for count in WordCount::all() {
            let entropy: Vec<u8> = (0..count.entropy_bytes())
                .map(|i| {
                    u8::try_from(i)
                        .unwrap_or(0)
                        .wrapping_mul(37)
                        .wrapping_add(11)
                })
                .collect();
            let mnemonic = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(mnemonic.words().len(), count.words());
            let parsed = Mnemonic::parse(&mnemonic.to_phrase()).unwrap();
            assert_eq!(parsed.entropy(), &entropy[..], "{count:?}");
            assert_eq!(parsed, mnemonic);
        }
    }

    #[test]
    fn rejects_entropy_of_the_wrong_size() {
        for len in [0usize, 15, 17, 31, 33, 64] {
            assert_eq!(
                Mnemonic::from_entropy(&vec![0; len]),
                Err(MnemonicError::EntropyLength { got: len })
            );
        }
    }

    #[test]
    fn rejects_a_sentence_of_the_wrong_length() {
        assert_eq!(
            Mnemonic::parse("abandon abandon"),
            Err(MnemonicError::WordCount { got: 2 })
        );
        assert_eq!(
            Mnemonic::parse(""),
            Err(MnemonicError::WordCount { got: 0 })
        );
    }

    #[test]
    fn names_the_word_that_is_not_in_the_list() {
        let broken = ZERO_12.replacen("abandon", "abandoned", 1);
        assert_eq!(
            Mnemonic::parse(&broken),
            Err(MnemonicError::UnknownWord {
                position: 0,
                word: "abandoned".to_owned()
            })
        );
    }

    /// The checksum is what makes a mis-transcribed backup fail loudly instead
    /// of opening an empty wallet.
    #[test]
    fn a_wrong_last_word_fails_the_checksum() {
        let broken = ZERO_12.replace("about", "abandon");
        match Mnemonic::parse(&broken) {
            Err(MnemonicError::Checksum { found, expected }) => {
                assert_eq!(found, 0, "the sentence claimed these bits");
                assert_eq!(expected, 3, "the entropy implies these");
            }
            other => panic!("expected a checksum error, got {other:?}"),
        }
    }

    /// Every single-word substitution in a 12-word mnemonic either changes the
    /// entropy or fails the checksum — it can never be silently ignored.
    #[test]
    fn no_substitution_is_silently_accepted() {
        let original = Mnemonic::from_entropy(&[0; 16]).unwrap();
        let words: Vec<&str> = original.words();
        let mut checksum_failures = 0;

        for position in 0..words.len() {
            for replacement in ["zoo", "hello", "legal"] {
                if words[position] == replacement {
                    continue;
                }
                let mut candidate = words.clone();
                candidate[position] = replacement;
                match Mnemonic::parse(&candidate.join(" ")) {
                    Ok(other) => assert_ne!(
                        other.entropy(),
                        original.entropy(),
                        "changing word {position} to {replacement} kept the entropy"
                    ),
                    Err(MnemonicError::Checksum { .. }) => checksum_failures += 1,
                    Err(e) => panic!("unexpected error: {e}"),
                }
            }
        }
        // A four-bit checksum catches about fifteen in sixteen, so most of
        // those substitutions should have been rejected outright.
        assert!(
            checksum_failures > 20,
            "only {checksum_failures} substitutions were caught by the checksum"
        );
    }

    #[test]
    fn reads_a_sentence_the_way_someone_would_have_typed_it() {
        let canonical = Mnemonic::parse(ZERO_12).unwrap();
        for messy in [
            &format!("  {ZERO_12}  \n"),
            &ZERO_12.to_uppercase(),
            &ZERO_12.replace(' ', "\n"),
            &ZERO_12.replace(' ', "   "),
        ] {
            assert_eq!(Mnemonic::parse(messy).unwrap(), canonical, "{messy:?}");
            // …and the seed is the canonical one, not one derived from the
            // string as typed.
            assert_eq!(
                Mnemonic::parse(messy).unwrap().to_seed(""),
                canonical.to_seed("")
            );
        }
    }

    /// The BIP39 vector for all-zero entropy with the standard `TREZOR`
    /// passphrase. The full vector file is asserted in `tests/hd_vectors.rs`;
    /// this one is here so the module is not silent about its own headline
    /// operation.
    #[test]
    fn produces_the_published_seed() {
        let mnemonic = Mnemonic::parse(ZERO_12).unwrap();
        assert_eq!(
            hex::encode(&mnemonic.to_seed("TREZOR")),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    /// A passphrase is a second secret, and every one of them is valid.
    #[test]
    fn each_passphrase_is_a_different_wallet() {
        let mnemonic = Mnemonic::parse(ZERO_12).unwrap();
        let mut seen = std::collections::HashSet::new();
        for passphrase in ["", "TREZOR", "trezor", " ", "a"] {
            assert!(
                seen.insert(mnemonic.to_seed(passphrase)),
                "{passphrase:?} collided with an earlier passphrase"
            );
        }
    }

    /// Composed and decomposed spellings of the same passphrase are the same
    /// passphrase, which is the whole reason BIP39 specifies NFKD.
    #[test]
    fn passphrases_are_normalised_before_hashing() {
        let mnemonic = Mnemonic::parse(ZERO_12).unwrap();
        // U+00E9, and `e` followed by U+0301.
        assert_eq!(mnemonic.to_seed("café"), mnemonic.to_seed("cafe\u{301}"));
    }

    #[test]
    fn debug_does_not_leak_the_words() {
        let shown = format!("{:?}", Mnemonic::from_entropy(&[0; 16]).unwrap());
        assert!(
            !shown.contains("abandon"),
            "Debug leaked the phrase: {shown}"
        );
        assert!(shown.contains("redacted"));
        assert!(shown.contains("12"), "the safe field is still useful");
    }

    #[cfg(feature = "rand")]
    #[test]
    fn generated_mnemonics_are_valid_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for count in WordCount::all() {
            for _ in 0..8 {
                let mnemonic = Mnemonic::generate(count);
                assert_eq!(mnemonic.word_count(), count);
                assert_eq!(mnemonic.words().len(), count.words());
                assert_eq!(
                    Mnemonic::parse(&mnemonic.to_phrase()).unwrap(),
                    mnemonic,
                    "a generated mnemonic failed its own checksum"
                );
                assert!(seen.insert(mnemonic.to_phrase()), "generated a repeat");
            }
        }
    }
}
