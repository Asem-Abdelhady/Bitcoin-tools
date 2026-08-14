//! How this API renders a Bitcoin address.
//!
//! Shared rather than owned by an endpoint: `/keys/public` renders one key's
//! addresses and `/hd/derive` renders up to a hundred, and the two must agree
//! about which addresses exist. Two places deciding that is two places to
//! forget BIP143.

use serde::Serialize;

use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{Address, PublicKey};
use bitcoin_tools_core::network::Network;

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

/// The one reason an address can be missing from a response.
const UNCOMPRESSED: &str = "an uncompressed public key cannot appear in a version 0 witness \
                            program (BIP143), so this key has no P2WPKH or P2SH-P2WPKH address";

impl AddressesView {
    /// Every address a key produces on a network.
    ///
    /// A constructor rather than four lines in a handler because `/hd/derive`
    /// renders the same shape for up to a hundred keys, and two places
    /// deciding which addresses exist is two places to forget BIP143.
    pub fn of(key: &PublicKey, network: Network) -> Self {
        AddressesView {
            p2pkh: key.p2pkh_address(network).into(),
            p2sh_p2wpkh: key.p2sh_p2wpkh_address(network).ok().map(Into::into),
            p2wpkh: key.p2wpkh_address(network).ok().map(Into::into),
            // Unlike the two above, this fails only on a tweak that is not a
            // scalar — around 2⁻¹²⁷, and not something the compression flag
            // decides.
            p2tr: key.p2tr_address(network).ok().map(Into::into),
            note: (!key.compressed).then_some(UNCOMPRESSED),
        }
    }
}
