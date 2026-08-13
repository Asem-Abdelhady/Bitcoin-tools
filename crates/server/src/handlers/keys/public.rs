//! HTTP surface for public keys and the addresses they derive.
//!
//! This endpoint receives a secret and returns none: everything below is
//! public data. That is not an oversight to be fixed by adding the WIF back —
//! it is the reason `/keys/generate` exists separately.

use axum::http::StatusCode;
use axum::{Json, extract::rejection::JsonRejection};
use serde::Serialize;

use crate::handlers::error::{ApiError, ApiRejection};
use crate::services::keys::public::{KeyServiceError, PublicKeyRequest, derive};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{Address, PrivateKeyError, PublicKey};
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

/// An address, plus the pieces the string is made of.
///
/// The point of the tool is that an address is not an opaque string: a Base58
/// address is a version byte, a hash and a checksum, and a Bech32 one is a
/// prefix, a witness version, a program and a checksum. Exactly one of
/// [`base58`](AddressView::base58) and [`bech32`](AddressView::bech32) is
/// present, decided by the format rather than by the caller.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressView {
    /// The address as it is written down.
    pub address: String,
    /// The `scriptPubKey` this address is a way of spelling — the bytes that
    /// actually go in an output. Feed it to `/transactions/script` to see it
    /// decoded.
    pub script_pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base58: Option<Base58View>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bech32: Option<Bech32View>,
}

/// The three fields a Base58Check address is built from.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Base58View {
    /// The version byte, which names the kind and the network at once — `00`
    /// for a mainnet P2PKH, `05` for a mainnet P2SH.
    pub version: u8,
    /// The same byte in hex, since that is how prefix tables are written.
    pub version_hex: String,
    /// The twenty bytes being committed to.
    pub hash: String,
    /// The four checksum bytes, which are the last four of a double SHA-256
    /// over the version byte and the hash.
    pub checksum: String,
}

/// The four fields a Bech32 address is built from.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Bech32View {
    /// The human-readable part, which names the network: `bc`, `tb` or `bcrt`.
    pub hrp: String,
    /// The witness version — 0 for P2WPKH, 1 for taproot.
    pub witness_version: u8,
    /// The program: twenty bytes for P2WPKH, thirty-two for taproot.
    pub program: String,
    /// The six checksum characters. Six *characters*, not bytes — bech32's
    /// checksum is computed over five-bit groups and never becomes bytes.
    pub checksum: String,
}

impl From<Address> for AddressView {
    fn from(address: Address) -> Self {
        AddressView {
            address: address.to_string(),
            script_pubkey: hex::encode(&address.script_pubkey()),
            base58: address.as_base58().map(|a| {
                let parts = a.parts();
                Base58View {
                    version: parts.version,
                    version_hex: format!("{:02x}", parts.version),
                    hash: parts.hash.to_string(),
                    checksum: hex::encode(&parts.checksum),
                }
            }),
            bech32: address.as_segwit().map(|a| {
                let parts = a.parts();
                Bech32View {
                    hrp: parts.hrp,
                    witness_version: parts.version.to_u8(),
                    program: hex::encode(&parts.program),
                    checksum: parts.checksum,
                }
            }),
        }
    }
}

/// Every address a single public key produces.
///
/// Four, not five: P2WSH commits to a script rather than to a key, so it is
/// not something one key derives.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesView {
    /// Pay to public key hash — the original address format, starting with
    /// `1` on mainnet.
    pub p2pkh: AddressView,
    /// BIP49: a witness program wrapped in P2SH, starting with `3`. From
    /// outside it is an ordinary P2SH address, because what the output commits
    /// to is the hash of the *redeem script* rather than of the key.
    ///
    /// `null` for an uncompressed key — see
    /// [`note`](AddressesView::note).
    pub p2sh_p2wpkh: Option<AddressView>,
    /// BIP84: native segwit v0, starting with `bc1q`. `null` for an
    /// uncompressed key.
    pub p2wpkh: Option<AddressView>,
    /// BIP86: taproot, starting with `bc1p`. Present for uncompressed keys
    /// too, because taproot uses only the x coordinate and so the compression
    /// flag has nothing to say about it.
    pub p2tr: Option<AddressView>,
    /// Why the segwit v0 addresses are `null`, present only when they are.
    ///
    /// One field rather than a reason per address, because there is one
    /// reason. Without it a caller sees two nulls and has to already know
    /// BIP143 to understand them. Scoped to the v0 pair on purpose: it is set
    /// from the compression flag, which is the only thing that makes those two
    /// absent, and it does not speak for `p2tr`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
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

/// The one reason an address can be missing from a response.
const UNCOMPRESSED: &str = "an uncompressed public key cannot appear in a version 0 witness \
                            program (BIP143), so this key has no P2WPKH or P2SH-P2WPKH address";

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
        addresses: AddressesView {
            p2pkh: key.p2pkh_address(network).into(),
            p2sh_p2wpkh: key.p2sh_p2wpkh_address(network).ok().map(Into::into),
            p2wpkh: key.p2wpkh_address(network).ok().map(Into::into),
            // Unlike the two above, this fails only on a tweak that is not a
            // scalar — around 2⁻¹²⁷, and not something the compression flag
            // decides.
            p2tr: key.p2tr_address(network).ok().map(Into::into),
            note: (!private.compressed).then_some(UNCOMPRESSED),
        },
        p2wpkh_redeem_script: key.p2wpkh_redeem_script().ok().map(|s| hex::encode(&s)),
    }))
}
