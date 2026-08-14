//! HTTP surface for BIP32 derivation.

use std::fmt;

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::address::AddressesView;
use crate::handlers::error::{ApiError, ApiRejection};
use crate::handlers::hd::ExtendedKeyView;
use crate::handlers::{NO_STORE, Secret};
use crate::services::hd::derive::{
    DeriveError, DeriveRequest, DeriveServiceError, DerivedKey, derive,
};
use bitcoin_tools_core::hd::Purpose;
use bitcoin_tools_core::hex;
use bitcoin_tools_core::network::Network;

/// The private half of a derived key.
///
/// Two renderings, not four: `/keys/generate` also shows the key in decimal
/// and binary, which are the right thing to show for *one* key a caller is
/// studying. Here there may be a hundred rows, and a 256-character binary
/// string on each of them buries the two fields anyone reads.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedPrivateKeyView {
    /// The 32-byte scalar, hex.
    pub hex: String,
    /// Wallet Import Format. Always compressed — BIP32 has no way to say
    /// otherwise, since it serializes public keys in 33 bytes.
    pub wif: String,
}

/// Redacts: both fields are the same scalar.
impl fmt::Debug for DerivedPrivateKeyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedPrivateKeyView(<redacted>)")
    }
}

/// One address in a derived branch.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedKeyView {
    /// The child index beneath the requested path.
    pub index: u32,
    /// The full path to this key.
    pub path: String,
    pub private_key: DerivedPrivateKeyView,
    /// The compressed public key, hex.
    pub public_key: String,
    /// The twenty bytes a P2PKH or P2WPKH output commits to.
    pub pubkey_hash: String,
    /// The address the path's own purpose calls for — BIP84 means the
    /// `bc1q…` one, BIP49 the `3…` one.
    ///
    /// `null` when the path names no standard, which is not an error: `m/0/1`
    /// is a valid path that says nothing about what to pay to. The four
    /// candidates are always in [`addresses`](DerivedKeyView::addresses); this
    /// field is the one the path *asked* for, so a caller does not have to
    /// implement BIP44/49/84/86 to pick.
    pub address: Option<String>,
    /// Every address this key can produce, as `/keys/public` renders them.
    pub addresses: AddressesView,
}

/// A branch, and the keys derived beneath it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveResponse {
    pub network: Network,
    /// What the path's first step says these addresses are for, or `null` for
    /// a path that names no standard.
    pub purpose: Option<Purpose>,
    /// The key at the requested path itself.
    ///
    /// Returned as well as the children because this is the level a wallet
    /// exports: hand over its `xpub` and a watch-only wallet can generate
    /// every address below without holding anything that can spend.
    pub branch: ExtendedKeyView,
    /// The children asked for, in index order.
    pub keys: Vec<DerivedKeyView>,
}

fn view(purpose: Option<Purpose>, network: Network, derived: &DerivedKey) -> DerivedKeyView {
    let private = derived.key.private_key();
    let public = private.public_key();

    DerivedKeyView {
        index: derived.index,
        path: derived.path.to_string(),
        private_key: DerivedPrivateKeyView {
            hex: hex::encode(&private.to_be_bytes()),
            wif: private.to_wif(),
        },
        public_key: public.to_string(),
        pubkey_hash: public.pubkey_hash().to_string(),
        // Every key here is compressed, so the only failure `Purpose::address`
        // has left is BIP86's tweak at 2⁻¹²⁷ — `null` rather than a 500 for
        // something no caller can produce or act on.
        address: purpose.and_then(|p| p.address(&public, network).ok().map(|a| a.to_string())),
        addresses: AddressesView::of(&public, network),
    }
}

/// `POST /hd/derive`
pub async fn post_derive(
    payload: Result<Json<DeriveRequest>, JsonRejection>,
) -> Result<Secret<DeriveResponse>, ApiRejection<DeriveServiceError>> {
    let Json(request) = payload?;
    let derivation = derive(&request).map_err(ApiRejection::Domain)?;

    Ok((
        NO_STORE,
        Json(DeriveResponse {
            network: derivation.network,
            purpose: derivation.purpose,
            branch: ExtendedKeyView::of(&derivation.branch, derivation.path.to_string()),
            keys: derivation
                .keys
                .iter()
                .map(|key| view(derivation.purpose, derivation.network, key))
                .collect(),
        }),
    ))
}

/// Each failure names the field the caller has to fix.
///
/// Per-rule slugs rather than one `invalid-derivation`, for the reason the
/// transaction builder gives: a client branching on these can say *which* of
/// the four inputs was wrong, and there is no ambiguity between them.
impl ApiError for DeriveError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            DeriveError::Path(_) => "invalid-derivation-path",
            DeriveError::Bip32(_) => "invalid-seed",
            DeriveError::TooMany { .. } => "too-many-keys",
            DeriveError::IndexOutOfRange { .. } => "index-out-of-range",
        }
    }
}
