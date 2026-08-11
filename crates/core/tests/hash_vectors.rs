//! HASH160 and SHA-256 against real mainnet transactions.
//!
//! The unit tests in `hashes/` check published vectors — FIPS 180-2 for
//! SHA-256, the Bitcoin wiki worked example for HASH160. Those prove the
//! primitives. This proves something the vectors cannot: that these functions
//! agree with the hashes Bitcoin Core actually computed, in the compositions
//! this crate claims they are used in.
//!
//! Two input types commit to a preimage that travels in the *same*
//! transaction, which is what makes the check self-contained:
//!
//! | Input | `scriptSig` | Commitment | Preimage |
//! |---|---|---|---|
//! | P2SH-P2WPKH | push of `OP_0 <20 bytes>` | `HASH160` | the witness public key |
//! | P2SH-P2WSH | push of `OP_0 <32 bytes>` | `SHA256` | the witness script |
//!
//! The 20-versus-32 split is the same one `hash160`'s documentation claims:
//! a key commitment is HASH160, a script commitment is a single SHA-256. This
//! test is that claim checked against the network rather than asserted in
//! prose.
//!
//! Native (non-wrapped) witness inputs cannot be used the same way — their
//! commitment lives in the previous output's `scriptPubKey`, which a raw
//! transaction does not carry.

use bitcoin_tools_core::hashes::{hash160, sha256};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::transactions::tx::Tx;
use bitcoin_tools_vectors::segwit;

/// `push 22 | OP_0 | push 20` — a P2SH-P2WPKH redeem script, pushed whole.
const P2WPKH_REDEEM_PUSH: [u8; 3] = [0x16, 0x00, 0x14];
/// `push 34 | OP_0 | push 32` — the P2SH-P2WSH equivalent.
const P2WSH_REDEEM_PUSH: [u8; 3] = [0x22, 0x00, 0x20];

/// How many of each shape the vectors hold today. Asserted exactly so that a
/// decoder change which silently stopped producing them fails here, rather
/// than leaving a test that passes while checking nothing.
const P2SH_P2WPKH_INPUTS: usize = 5;
const P2SH_P2WSH_INPUTS: usize = 3;

#[test]
fn wrapped_witness_commitments_match_their_preimages() {
    let mut keys_checked = 0;
    let mut scripts_checked = 0;

    for (i, vector) in segwit().iter().enumerate() {
        let raw = vector["rawTx"].as_str().expect("vector has a rawTx");
        let tx = Tx::from_hex(raw).unwrap_or_else(|e| panic!("segwit[{i}] failed to decode: {e}"));

        for (n, input) in tx.inputs.iter().enumerate() {
            let script_sig = input.script_sig.as_bytes();
            let witness = input.witness.items();
            let at = format!("segwit[{i}] input {n}");

            if script_sig.len() == 23 && script_sig[..3] == P2WPKH_REDEEM_PUSH {
                // A signature and the public key. Fewer items than that is a
                // decoder bug, not a shape to skip — the scriptSig has already
                // established what this input is.
                assert_eq!(
                    witness.len(),
                    2,
                    "{at}: P2SH-P2WPKH must spend with a signature and a key"
                );
                let pubkey = &witness[1];
                assert_eq!(
                    hash160(pubkey),
                    &script_sig[3..],
                    "{at}: hash160 of the witness pubkey {} is not the hash \
                     its redeem script commits to",
                    hex::encode(pubkey)
                );
                keys_checked += 1;
            } else if script_sig.len() == 35 && script_sig[..3] == P2WSH_REDEEM_PUSH {
                // The witness script is the last stack item.
                let witness_script = witness
                    .last()
                    .unwrap_or_else(|| panic!("{at}: P2SH-P2WSH spent with an empty witness"));
                assert_eq!(
                    sha256(witness_script),
                    &script_sig[3..],
                    "{at}: sha256 of the witness script is not the hash its \
                     redeem script commits to"
                );
                scripts_checked += 1;
            }
        }
    }

    assert_eq!(
        keys_checked, P2SH_P2WPKH_INPUTS,
        "expected {P2SH_P2WPKH_INPUTS} P2SH-P2WPKH inputs in the vectors, found {keys_checked}"
    );
    assert_eq!(
        scripts_checked, P2SH_P2WSH_INPUTS,
        "expected {P2SH_P2WSH_INPUTS} P2SH-P2WSH inputs in the vectors, found {scripts_checked}"
    );
}
