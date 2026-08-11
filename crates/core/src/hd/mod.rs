//! § 4 — Hierarchical deterministic wallets.
//!
//! ## Planned
//!
//! | File | Feature |
//! |---|---|
//! | `mnemonic.rs` | 4.1 BIP39 — entropy ⇄ sentence ⇄ seed, optional passphrase |
//! | `wordlist.rs` | 4.1 The 2048 English words, `const` |
//! | `xkey.rs` | 4.2 BIP32 — `Xpriv`, `Xpub`, `ChainCode`, `Fingerprint` |
//! | `path.rs` | 4.2 `DerivationPath`, `ChildNumber`, and the BIP44/49/84/86 shapes |
//!
//! BIP44, BIP49, BIP84 and BIP86 are not four derivation algorithms; they are
//! four purpose numbers and four output script types over the one BIP32
//! algorithm. `path.rs` encodes that difference and nothing more.
//!
//! Both features have official test vectors. They are the acceptance criteria,
//! not an extra.
