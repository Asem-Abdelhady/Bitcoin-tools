//! HTTP surface for key generation.
//!
//! The only response in this API that carries a secret, which is why the
//! cache directive below is here and not on its sibling.

use std::convert::Infallible;

use axum::http::header;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::ApiRejection;
use crate::services::keys::generate::{GenerateKeyRequest, generate};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::PrivateKey;
use bitcoin_tools_core::network::Network;

/// A private key rendered every way § 3.1 asks for.
///
/// Built here and nowhere else. `/keys/public` receives a secret and
/// deliberately does not echo one back, so this type appears in exactly one
/// response in the API — the one whose purpose is to hand a key over.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PrivateKeyView {
    /// The 32-byte field, hex, zero-padded — the form a key is written in.
    pub hex: String,
    /// The same value in base 10.
    ///
    /// A private key *is* a 256-bit integer, and this is it as one. Note the
    /// numeric views drop leading zeros, because that is what a number does:
    /// a key whose first byte is zero is 63 hex digits as a number and 64 as a
    /// field, and [`hex`](PrivateKeyView::hex) is the field.
    pub decimal: String,
    /// The same value in base 2.
    pub binary: String,
    /// Wallet Import Format: the key, its network, and its compression flag,
    /// in one Base58Check string. This is the field a wallet imports.
    pub wif: String,
}

impl From<&PrivateKey> for PrivateKeyView {
    fn from(key: &PrivateKey) -> Self {
        let number = key.to_number();
        PrivateKeyView {
            hex: hex::encode(&key.to_be_bytes()),
            decimal: number.to_decimal(),
            binary: number.to_binary(),
            wif: key.to_wif(),
        }
    }
}

/// A freshly minted key and the two flags that decide what it means.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GenerateKeyResponse {
    /// The network the WIF and every derived address belong to.
    pub network: Network,
    /// Whether the derived public key is used compressed.
    pub compressed: bool,
    /// The secret itself.
    pub private_key: PrivateKeyView,
}

/// The one header this API sets, and the only control it can assert over a
/// response body that is a credential.
///
/// A conforming cache will not store a POST response without explicit
/// freshness information, so this is belt over braces on the server side — but
/// it also covers the client: devtools, disk-backed HTTP client caches, and
/// anything replaying a session. `/keys/public` does not need it, and that
/// asymmetry is the split between the two endpoints made visible.
const NO_STORE: [(header::HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];

/// `POST /keys/generate`
///
/// Both request fields are optional, so `{}` mints a compressed mainnet key.
///
/// The response is not idempotent and deliberately so — POST is the method
/// precisely because each call creates something new. Sending it twice gives
/// two different keys, which is the point.
pub async fn post_generate_key(
    // `Infallible`: past the body there is nothing here that can fail, and
    // saying so in the type is better than naming an error the endpoint cannot
    // return.
    payload: Result<Json<GenerateKeyRequest>, JsonRejection>,
) -> Result<
    (
        [(header::HeaderName, &'static str); 1],
        Json<GenerateKeyResponse>,
    ),
    ApiRejection<Infallible>,
> {
    let Json(request) = payload?;
    let key = generate(&request);

    Ok((
        NO_STORE,
        Json(GenerateKeyResponse {
            network: key.network,
            compressed: key.compressed,
            private_key: (&key).into(),
        }),
    ))
}
