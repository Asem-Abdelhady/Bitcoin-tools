//! Hierarchical deterministic wallets.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `mnemonic.rs` | BIP39 — entropy ⇄ sentence ⇄ seed, optional passphrase |
//! | `wordlist.rs` | The 2048 English words |
//! | `xkey.rs` | BIP32 — `Xpriv`, `Xpub`, `ChainCode`, `Fingerprint` |
//! | `path.rs` | `DerivationPath`, `ChildNumber`, and the BIP44/49/84/86 shapes |
//!
//! BIP44, BIP49, BIP84 and BIP86 are not four derivation algorithms; they are
//! four purpose numbers and four output script types over the one BIP32
//! algorithm. [`Purpose`] encodes that difference and nothing more.
//!
//! Both features have official test vectors, and they are the acceptance
//! criteria rather than an extra: `tests/hd_vectors.rs` runs BIP32's four
//! seeded vectors *and* its fifth — the sixteen extended keys that must be
//! rejected — all 24 English BIP39 vectors, and the BIP49/84/86 derivations
//! end to end.
//!
//! ## The seed is the seam
//!
//! BIP39 ends at 64 bytes and BIP32 begins at them. Nothing in `xkey.rs`
//! mentions a mnemonic, and nothing in `mnemonic.rs` mentions a key — BIP32
//! takes any seed between 16 and 64 bytes, and a mnemonic is one way to have
//! produced it. Keeping that seam clean is why [`Xpriv::new_master`] takes a
//! `&[u8]` rather than a `&Mnemonic`, and why a caller who already has a seed from
//! somewhere else does not have to invent a mnemonic to use this crate.
//!
//! ## SLIP-132 prefixes are deliberately absent
//!
//! `ypub` and `zpub` — the prefixes BIP49's and BIP84's own test vectors are
//! written in — are not implemented. They encode an intended script type in
//! the version bytes of an extended key, and BIP32 says nothing about script
//! types: the same key is a valid P2PKH, P2WPKH and P2TR key at once, so a
//! prefix claiming otherwise is a wallet's opinion travelling as if it were
//! part of the format. [`Purpose`] carries that opinion instead, where it can
//! be read and changed.
//!
//! The cost is that this crate reads a `zpub` as an unknown version rather
//! than as an xpub for a bech32 account. Adding the table later is additive,
//! and the BIP49/84 vectors are still asserted end to end — through the
//! addresses and WIF keys they derive, which is what those standards are
//! actually for.

pub mod mnemonic;
pub mod path;
pub mod wordlist;
pub mod xkey;

pub use mnemonic::{Mnemonic, MnemonicError, SEED_SIZE, WordCount};
pub use path::{
    ChildNumber, DerivationPath, ParseChildError, ParsePathError, Purpose, UnknownPurpose,
};
pub use xkey::{Bip32Error, ChainCode, Fingerprint, Xpriv, Xpub};
