//! Public keys and addresses against real mainnet transactions.
//!
//! `hash_vectors.rs` checks that `hash160` agrees with the network. This
//! checks the layer above it: that [`PublicKey`] parses a real compressed key,
//! infers the compression flag from the encoding rather than being told, picks
//! the right bytes to hash, and lands on the same twenty bytes the redeem
//! script commits to.
//!
//! The route is the same P2SH-P2WPKH input — its `scriptSig` is a push of
//! `OP_0 <20 bytes>`, and those bytes are `HASH160` of the public key in that
//! input's witness. Going through `PublicKey` rather than `hash160` directly
//! is the point: a key that guessed compression wrong would hash 65 bytes
//! instead of 33 and miss.

use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{Address, AddressHash, AddressKind, PublicKey};
use bitcoin_tools_core::network::Network;
use bitcoin_tools_core::transactions::tx::Tx;
use bitcoin_tools_vectors::segwit;

/// `push 22 | OP_0 | push 20` — a P2SH-P2WPKH redeem script, pushed whole.
const P2WPKH_REDEEM_PUSH: [u8; 3] = [0x16, 0x00, 0x14];

/// How many the vectors hold. Asserted exactly, so a decoder change that
/// stopped producing them fails here instead of leaving a vacuous pass.
const P2SH_P2WPKH_INPUTS: usize = 5;

#[test]
fn real_public_keys_hash_to_their_committed_pubkey_hash() {
    let mut checked = 0;

    for (i, vector) in segwit().iter().enumerate() {
        let raw = vector["rawTx"].as_str().expect("vector has a rawTx");
        let tx = Tx::from_hex(raw).unwrap_or_else(|e| panic!("segwit[{i}] failed to decode: {e}"));

        for (n, input) in tx.inputs.iter().enumerate() {
            let script_sig = input.script_sig.as_bytes();
            if script_sig.len() != 23 || script_sig[..3] != P2WPKH_REDEEM_PUSH {
                continue;
            }
            let at = format!("segwit[{i}] input {n}");
            let witness = input.witness.items();
            assert_eq!(witness.len(), 2, "{at}: expected a signature and a key");

            let key = PublicKey::from_sec1(&witness[1])
                .unwrap_or_else(|e| panic!("{at}: witness key did not parse: {e}"));

            // Every key spent this way is compressed — a 33-byte encoding —
            // and the flag comes from the bytes rather than from us.
            assert!(
                key.compressed,
                "{at}: a 33-byte key must report itself compressed"
            );
            assert_eq!(key.to_bytes().len(), 33, "{at}");

            assert_eq!(
                key.pubkey_hash().as_bytes(),
                &script_sig[3..],
                "{at}: the key {} does not hash to the committed value",
                hex::encode(&key.to_bytes())
            );

            // The same twenty bytes are a legitimate P2PKH address, and it has
            // to survive a trip through its own text form.
            let address = key.p2pkh_address(Network::Mainnet);
            assert!(
                address.to_string().starts_with('1'),
                "{at}: a mainnet P2PKH address starts with 1, got {address}"
            );
            let parsed: Address = address
                .to_string()
                .parse()
                .unwrap_or_else(|e| panic!("{at}: address did not parse back: {e}"));
            assert_eq!(parsed, address, "{at}");
            assert_eq!(parsed.kind(), AddressKind::P2pkh, "{at}");
            assert_eq!(parsed.hash(), key.pubkey_hash(), "{at}");

            checked += 1;
        }
    }

    assert_eq!(
        checked, P2SH_P2WPKH_INPUTS,
        "expected {P2SH_P2WPKH_INPUTS} P2SH-P2WPKH inputs in the vectors, found {checked}"
    );
}

/// Every P2SH output in the vectors is a real script hash. Turning each into
/// an address and reading it back exercises the P2SH version byte against
/// mainnet data rather than one hand-picked hash.
#[test]
fn p2sh_outputs_round_trip_as_addresses() {
    let mut checked = 0;

    for txs in [bitcoin_tools_vectors::legacy(), segwit()] {
        for tx in &txs {
            for output in tx["outputs"].as_array().expect("outputs is an array") {
                let script = output["scriptPubkey"].as_str().expect("a hex script");
                let bytes = hex::decode(script).expect("vectors hold valid hex");
                // `OP_HASH160 <20 bytes> OP_EQUAL`
                if bytes.len() != 23 || bytes[0] != 0xa9 || bytes[1] != 0x14 || bytes[22] != 0x87 {
                    continue;
                }
                let mut raw = [0u8; 20];
                raw.copy_from_slice(&bytes[2..22]);
                let hash = AddressHash::from_bytes(raw);

                let address = Address::p2sh(hash, Network::Mainnet);
                assert!(
                    address.to_string().starts_with('3'),
                    "a mainnet P2SH address starts with 3, got {address}"
                );
                let parsed: Address = address.to_string().parse().expect("parses back");
                assert_eq!(parsed.hash(), hash);
                assert_eq!(parsed.kind(), AddressKind::P2sh);
                assert_eq!(parsed.network(), Network::Mainnet);
                checked += 1;
            }
        }
    }

    assert!(
        checked > 0,
        "no P2SH outputs found — this test proved nothing"
    );
}
