//! Minting a private key, as a use case.

use serde::Deserialize;

use crate::services::keys::{default_compressed, default_network};
use bitcoin_tools_core::keys::PrivateKey;
use bitcoin_tools_core::network::Network;

/// What `/keys/generate` accepts.
///
/// Both fields are optional, so `{}` is a valid request and generates a
/// compressed mainnet key. They are not decoration: the network decides the
/// WIF prefix and every address version byte, and the compression flag changes
/// the public key's serialization and therefore the addresses — so a key
/// generated with the wrong one of either is a key for a wallet the caller
/// does not have.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GenerateKeyRequest {
    /// `mainnet`, `testnet`, `signet` or `regtest`.
    #[serde(default = "default_network")]
    pub network: Network,
    /// Whether the derived public key is used in compressed form.
    #[serde(default = "default_compressed")]
    pub compressed: bool,
}

/// Draw a new private key from the operating system's randomness.
///
/// Infallible: the domain retries the vanishingly rare out-of-range draw
/// rather than handing back an error nobody could act on.
///
/// # This endpoint hands a secret over the wire
///
/// That is the request, and for a locally-run inspection tool it is a
/// reasonable one — but it is worth being clear about what it means. The key
/// is generated on the *server's* machine using that machine's RNG, and
/// travels back in a response body, so it is only as private as the process,
/// the network hop, and anything logging either. A key meant to hold value
/// should be generated on the device that will keep it. This one is for
/// looking at.
#[must_use]
pub fn generate(request: &GenerateKeyRequest) -> PrivateKey {
    PrivateKey::generate(request.network, request.compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated(network: Network, compressed: bool) -> PrivateKey {
        generate(&GenerateKeyRequest {
            network,
            compressed,
        })
    }

    #[test]
    fn a_generated_key_carries_what_was_asked_for() {
        let key = generated(Network::Testnet, false);
        assert_eq!(key.network, Network::Testnet);
        assert!(!key.compressed);
        assert!(
            key.to_wif().starts_with('9'),
            "an uncompressed testnet WIF: {}",
            key.to_wif()
        );
    }

    /// Not a statistical test — that belongs to the RNG, not to this. It only
    /// rules out the failure that would matter: a constant.
    #[test]
    fn two_draws_differ() {
        let (a, b) = (
            generated(Network::Mainnet, true),
            generated(Network::Mainnet, true),
        );
        assert_ne!(a.to_be_bytes(), b.to_be_bytes());
    }

    #[test]
    fn the_defaults_are_the_ones_documented() {
        let request: GenerateKeyRequest = serde_json::from_str("{}").expect("an empty object");
        assert_eq!(request.network, Network::Mainnet);
        assert!(request.compressed);
    }

    #[test]
    fn an_unknown_field_is_refused() {
        assert!(
            serde_json::from_str::<GenerateKeyRequest>(r#"{"netowrk":"mainnet"}"#).is_err(),
            "a typo must not silently generate a mainnet key"
        );
    }
}
