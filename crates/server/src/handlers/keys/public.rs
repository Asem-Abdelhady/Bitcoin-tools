//! HTTP surface for public keys and the addresses they derive.
//!
//! This endpoint receives a secret and returns none: everything below is
//! public data. That is not an oversight to be fixed by adding the WIF back —
//! it is the reason `/keys/generate` exists separately.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::address::AddressesView;
use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::keys::public::{KeyServiceError, PublicKeyRequest, derive};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{PrivateKeyError, PublicKey};
use bitcoin_tools_core::network::Network;

/// This endpoint's failure vocabulary.
///
/// Only this one: `/keys/generate` parses no bytes and declares
/// `ApiRejection<Infallible>`, so a `PrivateKeyError` can arrive from nowhere
/// else. Every variant is a 400 — the request named something that is not a
/// key, and there is no partial answer to give.
impl ApiError for PrivateKeyError {
    fn status(&self) -> StatusCode {
        StatusCode::BAD_REQUEST
    }

    fn slug(&self) -> &'static str {
        match self {
            // The shared vocabulary for the shared mistake, as everywhere else.
            PrivateKeyError::Hex(_) => "invalid-hex",
            // `PrivateKeyError` is #[non_exhaustive], and most of its variants
            // describe WIF payloads this endpoint never parses. One slug for
            // all of them is right: they all mean "that is not a private key",
            // and the message says which way.
            _ => "invalid-private-key",
        }
    }
}

/// The public key in every serialization anyone asks for.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyView {
    /// The serialization this key actually uses — the bytes that get hashed,
    /// and so the bytes that decide the addresses. Equal to one of the two
    /// below depending on `compressed`.
    pub hex: String,
    /// 33 bytes: `02` or `03` by the parity of y, then x.
    pub compressed: String,
    /// 65 bytes: `04`, then x, then y.
    pub uncompressed: String,
    /// Just x, 32 bytes — what taproot signs with, and what BIP340 means by a
    /// public key.
    ///
    /// Byte-identical to [`x`](PublicKeyView::x), always. Both are here
    /// because the name is the point: a BIP340 public key *is* the x
    /// coordinate, and seeing the same 64 characters under two headings is
    /// how that stops being surprising.
    pub x_only: String,
    /// The x coordinate.
    pub x: String,
    /// The y coordinate. Recoverable from x and one parity bit, which is the
    /// whole idea behind the compressed form.
    pub y: String,
    /// `HASH160` of [`hex`](PublicKeyView::hex) — the twenty bytes a P2PKH or
    /// P2WPKH output commits to. Wire order, and never shown reversed.
    pub pubkey_hash: String,
}

impl From<&PublicKey> for PublicKeyView {
    fn from(key: &PublicKey) -> Self {
        let (x, y) = key.coordinates();
        PublicKeyView {
            hex: key.to_string(),
            compressed: hex::encode(&key.to_compressed()),
            uncompressed: hex::encode(&key.to_uncompressed()),
            x_only: hex::encode(&key.to_x_only()),
            x: hex::encode(&x),
            y: hex::encode(&y),
            pubkey_hash: key.pubkey_hash().to_string(),
        }
    }
}

/// Everything a private key implies that is safe to publish.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyResponse {
    /// The network every address below belongs to.
    pub network: Network,
    /// Whether the key is used compressed, which decides both the
    /// serialization that gets hashed and which addresses exist at all.
    pub compressed: bool,
    pub public_key: PublicKeyView,
    pub addresses: AddressesView,
    /// BIP49's redeem script, `OP_0 <20-byte pubkey hash>`, hex.
    ///
    /// Here rather than inside `p2shP2wpkh` because it is not part of that
    /// address — the address is `HASH160` of it. A spending input has to push
    /// this, and it cannot be recovered from the address, so a tool that shows
    /// the address without it shows half of what is needed.
    ///
    /// `null` for an uncompressed key, rendered rather than omitted: it goes
    /// absent for exactly the reason `p2shP2wpkh` does, and one absence
    /// spelled two ways in one response is a difference that means nothing.
    pub p2wpkh_redeem_script: Option<String>,
}

/// `POST /keys/public`
pub async fn post_public_key(
    payload: Result<Json<PublicKeyRequest>, JsonRejection>,
) -> Result<Json<PublicKeyResponse>, ApiRejection<KeyServiceError>> {
    let Json(request) = payload?;
    let private = derive(&request).map_err(ApiRejection::Domain)?;

    let network = private.network;
    let key = private.public_key();

    Ok(Json(PublicKeyResponse {
        network,
        compressed: private.compressed,
        public_key: (&key).into(),
        addresses: AddressesView::of(&key, network),
        p2wpkh_redeem_script: key.p2wpkh_redeem_script().ok().map(|s| hex::encode(&s)),
    }))
}
