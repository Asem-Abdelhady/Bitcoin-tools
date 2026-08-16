//! How this program renders a Bitcoin address.
//!
//! Shared rather than owned by a command: `keys public` renders one key's
//! addresses and `hd derive` renders up to a hundred, and the two must agree
//! about which addresses exist. Two places deciding that is two places to
//! forget BIP143.
//!
//! The shapes and their JSON spellings are the HTTP API's, field for field.

use std::io::{self, Write};

use serde::Serialize;

use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{Address, PublicKey};
use bitcoin_tools_core::network::Network;

use crate::output::Fields;

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
    /// actually go in an output. Feed it to `transactions script` to see it
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

impl AddressView {
    /// Write this address and its parts into a block, `depth` levels in.
    fn render(&self, fields: &mut Fields, depth: usize) {
        fields.nested(depth, "address", &self.address).nested(
            depth,
            "scriptPubkey",
            &self.script_pubkey,
        );

        if let Some(parts) = &self.base58 {
            fields
                .nested(
                    depth,
                    "version",
                    format!("{} ({})", parts.version, parts.version_hex),
                )
                .nested(depth, "hash", &parts.hash)
                .nested(depth, "checksum", &parts.checksum);
        }

        if let Some(parts) = &self.bech32 {
            fields
                .nested(depth, "hrp", &parts.hrp)
                .nested(depth, "witnessVersion", parts.witness_version)
                .nested(depth, "program", &parts.program)
                .nested(depth, "checksum", &parts.checksum);
        }
    }
}

/// Every address a single public key produces.
///
/// Four, not five: P2WSH commits to a script rather than to a key, so it is not
/// something one key derives.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddressesView {
    /// Pay to public key hash — the original address format, starting with `1`
    /// on mainnet.
    pub p2pkh: AddressView,
    /// BIP49: a witness program wrapped in P2SH, starting with `3`. From
    /// outside it is an ordinary P2SH address, because what the output commits
    /// to is the hash of the *redeem script* rather than of the key.
    ///
    /// `null` for an uncompressed key — see [`note`](AddressesView::note).
    pub p2sh_p2wpkh: Option<AddressView>,
    /// BIP84: native segwit v0, starting with `bc1q`. `null` for an
    /// uncompressed key.
    pub p2wpkh: Option<AddressView>,
    /// BIP86: taproot, starting with `bc1p`. Present for uncompressed keys too,
    /// because taproot uses only the x coordinate and so the compression flag
    /// has nothing to say about it.
    pub p2tr: Option<AddressView>,
    /// Why the segwit v0 addresses are `null`, present only when they are.
    ///
    /// One field rather than a reason per address, because there is one reason.
    /// Without it a caller sees two nulls and has to already know BIP143 to
    /// understand them.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
}

/// The one reason an address can be missing from this output.
const UNCOMPRESSED: &str = "an uncompressed public key cannot appear in a version 0 witness \
                            program (BIP143), so this key has no P2WPKH or P2SH-P2WPKH address";

impl AddressesView {
    /// Every address a key produces on a network.
    ///
    /// A constructor rather than four lines in a command, because `hd derive`
    /// renders the same shape for up to a hundred keys.
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

    /// Write every address that exists into a block, headed by its name.
    ///
    /// An absent address prints nothing rather than a null: the JSON says which
    /// of the four are missing and this says which are there, and a reader who
    /// wants to know *why* gets the note, which is the part that helps.
    pub fn render(&self, fields: &mut Fields, depth: usize) {
        let addresses = [
            ("p2pkh", Some(&self.p2pkh)),
            ("p2shP2wpkh", self.p2sh_p2wpkh.as_ref()),
            ("p2wpkh", self.p2wpkh.as_ref()),
            ("p2tr", self.p2tr.as_ref()),
        ];

        for (name, address) in addresses {
            if let Some(address) = address {
                fields.heading(depth, name);
                address.render(fields, depth + 1);
            }
        }

        fields.maybe(depth, "note", self.note);
    }

    /// The one-line form: each address that exists, by name.
    ///
    /// What `hd derive` prints per key when it is showing many of them, since
    /// the full breakdown of four addresses for a hundred keys is not something
    /// anyone reads.
    pub fn render_briefly(&self, fields: &mut Fields, depth: usize) {
        fields.nested(depth, "p2pkh", &self.p2pkh.address);

        for (name, address) in [
            ("p2shP2wpkh", self.p2sh_p2wpkh.as_ref()),
            ("p2wpkh", self.p2wpkh.as_ref()),
            ("p2tr", self.p2tr.as_ref()),
        ] {
            fields.maybe(depth, name, address.map(|a| &a.address));
        }
    }
}

/// Write a whole address set as its own block, for a command whose answer is
/// one key.
///
/// # Errors
///
/// Whatever `w` produced.
pub fn write_addresses(
    w: &mut dyn Write,
    fields: &mut Fields,
    addresses: &AddressesView,
) -> io::Result<()> {
    fields.blank().heading(0, "addresses");
    addresses.render(fields, 1);
    fields.write(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_tools_core::keys::PrivateKey;

    fn key(compressed: bool) -> PublicKey {
        PrivateKey::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000001",
            Network::Mainnet,
            compressed,
        )
        .expect("one is a scalar")
        .public_key()
    }

    /// The shape is the HTTP API's, key for key. A field renamed on one front
    /// end and not the other is the drift this whole crate is arranged to
    /// avoid, and the four address keys are the ones a script indexes by name.
    #[test]
    fn the_json_keys_are_the_ones_the_api_answers_under() {
        let view = AddressesView::of(&key(true), Network::Mainnet);
        let json = serde_json::to_value(&view).unwrap();
        let object = json.as_object().unwrap();

        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["p2pkh", "p2shP2wpkh", "p2tr", "p2wpkh"]);

        let p2pkh = object["p2pkh"].as_object().unwrap();
        assert!(p2pkh.contains_key("scriptPubkey"), "{json}");
        assert!(
            p2pkh["base58"]
                .as_object()
                .unwrap()
                .contains_key("versionHex"),
            "{json}"
        );
    }

    /// An uncompressed key has no version 0 witness program, and says why once
    /// rather than leaving two nulls to be interpreted.
    #[test]
    fn an_uncompressed_key_loses_the_segwit_v0_pair_and_says_so() {
        let view = AddressesView::of(&key(false), Network::Mainnet);

        assert!(view.p2wpkh.is_none());
        assert!(view.p2sh_p2wpkh.is_none());
        assert!(view.p2tr.is_some(), "taproot uses only the x coordinate");
        assert!(view.note.is_some_and(|note| note.contains("BIP143")));
    }

    /// The brief form is not a different answer: every address in it is the
    /// same string the full one renders.
    #[test]
    fn the_brief_form_prints_the_same_addresses_as_the_full_one() {
        let view = AddressesView::of(&key(true), Network::Mainnet);

        let render = |f: fn(&AddressesView, &mut Fields, usize)| {
            let mut fields = Fields::new();
            f(&view, &mut fields, 0);
            let mut out = Vec::new();
            fields.write(&mut out).unwrap();
            String::from_utf8(out).unwrap()
        };

        let full = render(AddressesView::render);
        let brief = render(AddressesView::render_briefly);

        for address in [
            &view.p2pkh.address,
            &view.p2wpkh.as_ref().unwrap().address,
            &view.p2sh_p2wpkh.as_ref().unwrap().address,
            &view.p2tr.as_ref().unwrap().address,
        ] {
            assert!(full.contains(address), "missing from full:\n{full}");
            assert!(brief.contains(address), "missing from brief:\n{brief}");
        }
    }
}
