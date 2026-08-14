//! HTTP surface for `/hd`.

pub mod derive;
pub mod mnemonic;

use std::fmt;

use serde::Serialize;

use bitcoin_tools_core::hd::Xpriv;

/// An extended key pair at one point in the tree.
///
/// Both halves, because the whole reason BIP32 is interesting is that they are
/// separable: the xpub below watches every non-hardened descendant without
/// carrying anything that can spend. Shown together so a caller can see which
/// one to export.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedKeyView {
    /// The path that reached this key.
    pub path: String,
    /// Derivations from the master — the byte BIP32 stores, so 255 is the
    /// deepest a key can be written down.
    pub depth: u8,
    /// This key's own fingerprint: the first four bytes of `HASH160` of its
    /// public key.
    pub fingerprint: String,
    /// The parent's fingerprint, or zeros at the master. This is the field a
    /// descriptor uses to say which wallet a key came from.
    pub parent_fingerprint: String,
    /// The 32 bytes that make derivation deterministic without being secret on
    /// their own — an xpub carries the chain code, which is exactly why an
    /// xpub plus one child *private* key exposes the whole branch.
    pub chain_code: String,
    /// The private half. This is the wallet.
    pub xprv: String,
    /// The public half, safe to hand to a watch-only wallet.
    pub xpub: String,
}

/// Redacts the half that can spend.
///
/// The chain code is *not* redacted, and that is deliberate rather than an
/// oversight: it is already inside the `xpub` printed beside it, so hiding one
/// while showing the other would be theatre. The `xprv` is the field that
/// matters, and it is the one that goes.
impl fmt::Debug for ExtendedKeyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedKeyView")
            .field("path", &self.path)
            .field("depth", &self.depth)
            .field("fingerprint", &self.fingerprint)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("chain_code", &self.chain_code)
            .field("xprv", &"<redacted>")
            .field("xpub", &self.xpub)
            .finish()
    }
}

impl ExtendedKeyView {
    /// Rendered from the private half, since it is the only one that can
    /// produce both.
    pub fn of(key: &Xpriv, path: String) -> Self {
        ExtendedKeyView {
            path,
            depth: key.depth(),
            fingerprint: key.fingerprint().to_string(),
            parent_fingerprint: key.parent_fingerprint().to_string(),
            chain_code: key.chain_code().to_string(),
            xprv: key.to_base58(),
            xpub: key.to_xpub().to_base58(),
        }
    }
}
