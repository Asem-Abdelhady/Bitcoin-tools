//! § 4 — BIP39 mnemonics and BIP32 derivation.
//!
//! ## Both endpoints return secrets, and that is the point
//!
//! A seed *is* the wallet, and so is a mnemonic. `/hd/mnemonic` mints one and
//! `/hd/derive` expands one into the keys it implies — producing secrets is
//! what each is for, which is the test [`keys`](crate::services::keys) states.
//! Both set `no-store`.
//!
//! ## Why they take a seed rather than a mnemonic
//!
//! `/hd/derive` takes the 64 bytes, not the sentence. A seed is what BIP32
//! actually consumes; a mnemonic is one of several ways to arrive at one, and
//! wallets exist that were never given a sentence at all. Taking the seed
//! keeps derivation independent of how it was produced, and
//! `/hd/mnemonic` hands one over ready to paste.
//!
//! The cost is real and worth stating: because the sentence is not an input
//! anywhere, there is no way to ask *this* mnemonic for its seed under a
//! different passphrase — the passphrase can only be varied at the moment a
//! new mnemonic is generated. Reading back an existing sentence is a separate
//! endpoint, and a deliberate omission rather than an oversight.

pub mod derive;
pub mod mnemonic;
