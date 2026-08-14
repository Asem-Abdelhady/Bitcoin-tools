//! Deriving a public key from a private one, as a use case.

use std::fmt;

use serde::Deserialize;

use crate::services::default_network;
use crate::services::error::ServiceError;
use crate::services::input::hex_bytes_exact;
use crate::services::keys::default_compressed;
use bitcoin_tools_core::crypto::secp::SCALAR_SIZE;
use bitcoin_tools_core::keys::{PrivateKey, PrivateKeyError};
use bitcoin_tools_core::network::Network;

/// The noun this endpoint's messages use for its input.
const SUBJECT: &str = "private key";

/// What `/keys/public` accepts.
///
/// `network` and `compressed` are optional and mean what they do at
/// `/keys/generate` — but here they are not cosmetic either. The scalar alone
/// does not determine an address: the same 32 bytes give a different P2PKH
/// address compressed and uncompressed, and a different one again per network.
///
/// [`Debug`] is hand-written so the key does not print — see
/// [`DeriveRequest`](crate::services::hd::derive::DeriveRequest).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicKeyRequest {
    /// The secret, as 64 hex digits. `0x` and whitespace are tolerated.
    pub private_key: String,
    /// `mainnet`, `testnet`, `signet` or `regtest`.
    #[serde(default = "default_network")]
    pub network: Network,
    /// Whether the public key is used in compressed form.
    #[serde(default = "default_compressed")]
    pub compressed: bool,
}

impl fmt::Debug for PublicKeyRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKeyRequest")
            .field("private_key", &"<redacted>")
            .field("network", &self.network)
            .field("compressed", &self.compressed)
            .finish()
    }
}

/// Bad input, or 32 bytes that are not a usable key.
pub type KeyServiceError = ServiceError<PrivateKeyError>;

/// Validate a hex private key and return it, ready to derive from.
///
/// Returns the *private* key rather than the public one because the network
/// and compression flag ride along with it, and every address the handler
/// renders needs all three. Nothing here shows the secret; that decision is
/// the response view's, and it declines.
///
/// # Errors
///
/// [`KeyServiceError`] for unusable hex, for anything other than 32 bytes, or
/// for 32 bytes that are not a scalar — zero, or at or above the group order.
/// That last one is not a length check restated: a value can be exactly the
/// right size and still be no key at all, and secp256k1 says which.
pub fn derive(request: &PublicKeyRequest) -> Result<PrivateKey, KeyServiceError> {
    let bytes: [u8; SCALAR_SIZE] = hex_bytes_exact(&request.private_key, SUBJECT, |got| {
        PrivateKeyError::WrongLength { got }
    })?;

    PrivateKey::from_be_bytes(&bytes, request.network, request.compressed)
        .map_err(ServiceError::Domain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::input::InputError;
    use bitcoin_tools_core::crypto::ScalarError;

    /// The published key→address worked example.
    ///
    /// Its two addresses below were recomputed from scratch — scalar
    /// multiplication, HASH160, Base58Check — rather than copied from this
    /// crate's own output, so they are an independent expectation and not a
    /// snapshot of whatever the code currently does.
    const KEY: &str = "1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd";

    /// The same key, compressed and uncompressed, gives two different
    /// addresses — which is the whole reason the flag travels with the key.
    const UNCOMPRESSED_ADDRESS: &str = "1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x";
    const COMPRESSED_ADDRESS: &str = "1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy";

    fn derived(private_key: &str) -> Result<PrivateKey, KeyServiceError> {
        derive(&PublicKeyRequest {
            private_key: private_key.to_owned(),
            network: Network::Mainnet,
            compressed: false,
        })
    }

    #[test]
    fn derives_the_worked_example() {
        let key = derived(KEY).unwrap();
        assert_eq!(
            key.public_key().to_string(),
            "04f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a\
             07cf33da18bd734c600b96a72bbc4749d5141c90ec8ac328ae52ddfe2e505bdb"
        );
        assert_eq!(
            key.public_key().p2pkh_address(Network::Mainnet).to_string(),
            UNCOMPRESSED_ADDRESS
        );
    }

    /// One scalar, two addresses. A tool that ignored the compression flag
    /// would send funds to the wrong one of these and be certain it was right.
    #[test]
    fn the_compression_flag_changes_the_address() {
        let compressed = derive(&PublicKeyRequest {
            private_key: KEY.to_owned(),
            network: Network::Mainnet,
            compressed: true,
        })
        .unwrap();

        assert_eq!(
            compressed
                .public_key()
                .p2pkh_address(Network::Mainnet)
                .to_string(),
            COMPRESSED_ADDRESS
        );
        assert_ne!(COMPRESSED_ADDRESS, UNCOMPRESSED_ADDRESS);
        assert_eq!(
            compressed.to_be_bytes(),
            derived(KEY).unwrap().to_be_bytes(),
            "…from the identical secret"
        );
    }

    #[test]
    fn tolerates_prefix_and_whitespace() {
        assert_eq!(
            derived(&format!("  0x{KEY}\n")).unwrap().to_be_bytes(),
            derived(KEY).unwrap().to_be_bytes()
        );
    }

    /// Both directions of the width are the caller's error, with the size they
    /// sent — the rule `hex_bytes_exact` owns.
    #[test]
    fn a_key_is_thirty_two_bytes_in_both_directions() {
        assert_eq!(
            derived(&KEY[..62]).unwrap_err(),
            ServiceError::Domain(PrivateKeyError::WrongLength { got: 31 })
        );
        assert_eq!(
            derived(&format!("{KEY}00")).unwrap_err(),
            ServiceError::Domain(PrivateKeyError::WrongLength { got: 33 })
        );
    }

    /// The right size and still not a key. Zero has no public key, and the
    /// group order wraps to it — neither is something a length check sees.
    #[test]
    fn thirty_two_bytes_can_still_be_no_key_at_all() {
        assert_eq!(
            derived(&"00".repeat(32)).unwrap_err(),
            ServiceError::Domain(PrivateKeyError::Scalar(ScalarError::Zero))
        );

        let order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
        assert!(
            matches!(
                derived(order).unwrap_err(),
                ServiceError::Domain(PrivateKeyError::Scalar(_))
            ),
            "the group order itself is not a key"
        );
    }

    #[test]
    fn unusable_input_stays_an_input_error() {
        assert_eq!(
            derived("   ").unwrap_err(),
            ServiceError::Input(InputError::Empty {
                subject: "private key"
            })
        );
        assert!(matches!(
            derived("zz").unwrap_err(),
            ServiceError::Input(InputError::Hex(_))
        ));
    }

    /// The one field of this request that must never reach a log line.
    #[test]
    fn the_private_key_does_not_appear_in_debug_output() {
        let rendered = format!(
            "{:?}",
            PublicKeyRequest {
                private_key: KEY.to_owned(),
                network: Network::Testnet,
                compressed: true,
            }
        );
        assert!(!rendered.contains(KEY), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("Testnet"), "{rendered}");
    }

    #[test]
    fn the_flags_reach_the_key() {
        let request = PublicKeyRequest {
            private_key: KEY.to_owned(),
            network: Network::Testnet,
            compressed: true,
        };
        let key = derive(&request).unwrap();
        assert_eq!(key.network, Network::Testnet);
        assert!(key.compressed);
        assert_eq!(
            key.public_key().to_string().len(),
            66,
            "compressed asked for, compressed serialization"
        );
    }
}
