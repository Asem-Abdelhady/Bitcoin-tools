//! HTTP surface for key generation.
//!
//! The only response in this API that carries a secret, which is why the
//! cache directive below is here and not on its sibling.

use std::convert::Infallible;
use std::fmt;

use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::ApiRejection;
use crate::handlers::{NO_STORE, Secret};
use crate::services::keys::generate::{GenerateKeyRequest, generate};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::PrivateKey;
use bitcoin_tools_core::network::Network;

/// A private key in every representation: hex, decimal, binary and WIF.
///
/// Built here and nowhere else in `/keys`. `/keys/public` receives a secret
/// and deliberately does not echo one back — see
/// [`services::keys`](crate::services::keys) for the rule that split enforces.
/// `/hd` returns secrets of its own, and does so for the same reason this
/// endpoint may: producing them is what it is for.
#[derive(Serialize)]
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

/// Redacts, because every field is the same secret in another base.
///
/// The composites that hold this — [`GenerateKeyResponse`] — still derive
/// `Debug`: a derived impl calls each field's, so redaction propagates for
/// free and only the leaves need writing.
impl fmt::Debug for PrivateKeyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKeyView(<redacted>)")
    }
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
) -> Result<Secret<GenerateKeyResponse>, ApiRejection<Infallible>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_tools_core::keys::PrivateKey;

    /// The claim on [`PrivateKeyView`]'s `Debug`: redaction propagates through
    /// a composite that merely derives, because a derived impl calls each
    /// field's. If that were false, only the leaf would be safe.
    #[test]
    fn a_derived_debug_inherits_the_leafs_redaction() {
        let key = PrivateKey::generate(Network::Mainnet, true);
        let response = GenerateKeyResponse {
            network: key.network,
            compressed: key.compressed,
            private_key: (&key).into(),
        };
        let rendered = format!("{response:?}");

        assert!(!rendered.contains(&key.to_wif()), "{rendered}");
        assert!(
            !rendered.contains(&hex::encode(&key.to_be_bytes())),
            "{rendered}"
        );
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("Mainnet"),
            "…and the rest still prints: {rendered}"
        );
    }
}
