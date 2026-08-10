//! Runs the script decoder over every script in the mainnet vectors in
//! `src/examples/`. These are real transactions, so anything the decoder
//! rejects here is a bug in the decoder, not in the data.

use bitcoin_tools_web_server::types::transactions::script::{Script, ScriptKind};
use serde_json::Value;

const LEGACY: &str = include_str!("../src/examples/legacy_txs.json");
const SEGWIT: &str = include_str!("../src/examples/sigwit_txs.json");

fn load(raw: &str) -> Vec<Value> {
    serde_json::from_str(raw).expect("vectors parse as JSON")
}

/// Decode, then re-encode, and require the bytes back exactly.
fn assert_round_trips(script: &Script, what: &str) {
    let (steps, err) = script.disassemble();
    assert!(
        err.is_none(),
        "{what} failed to decode: {} in {script}",
        err.unwrap()
    );
    let mut out = Vec::new();
    for step in &steps {
        step.instruction.encode_into(&mut out);
    }
    assert_eq!(
        out,
        script.as_bytes(),
        "{what} did not survive a decode/encode round trip: {script}"
    );
}

fn script_at(v: &Value, key: &str) -> Script {
    Script::from_hex(v[key].as_str().unwrap()).expect("vectors hold valid hex")
}

#[test]
fn every_script_pubkey_round_trips() {
    let mut n = 0;
    for txs in [load(LEGACY), load(SEGWIT)] {
        for tx in &txs {
            for out in tx["outputs"].as_array().unwrap() {
                assert_round_trips(&script_at(out, "scriptPubkey"), "scriptPubkey");
                n += 1;
            }
        }
    }
    assert!(n > 40, "expected a meaningful number of outputs, got {n}");
    println!("{n} scriptPubkeys round-tripped");
}

#[test]
fn every_script_sig_round_trips() {
    let mut n = 0;
    for txs in [load(LEGACY), load(SEGWIT)] {
        for tx in &txs {
            for inp in tx["inputs"].as_array().unwrap() {
                let script = script_at(inp, "scriptSig");
                if script.is_empty() {
                    continue; // native segwit inputs have none
                }
                assert_round_trips(&script, "scriptSig");
                n += 1;
            }
        }
    }
    println!("{n} scriptSigs round-tripped");
}

/// The last witness item of a P2WSH spend is the witness script itself.
#[test]
fn witness_scripts_decode() {
    let txs = load(SEGWIT);
    let mut n = 0;
    for tx in &txs {
        for w in tx["witness"].as_array().unwrap() {
            let count = usize::from_str_radix(w["stackItems"].as_str().unwrap(), 16).unwrap();
            if count == 0 {
                continue;
            }
            let last = w[&(count - 1).to_string()]["item"].as_str().unwrap();
            let script = Script::from_hex(last).unwrap();
            // Only the multisig-shaped ones are actually scripts; a P2WPKH
            // spend ends in a pubkey, and taproot ends in a control block.
            if script.kind() == ScriptKind::P2MS {
                assert_round_trips(&script, "witness script");
                n += 1;
            }
        }
    }
    assert!(n > 0, "expected at least one P2WSH witness script");
    println!("{n} witness scripts decoded as bare multisig");
}

#[test]
fn classification_matches_the_vectors() {
    use std::collections::BTreeMap;

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for txs in [load(LEGACY), load(SEGWIT)] {
        for tx in &txs {
            for out in tx["outputs"].as_array().unwrap() {
                let kind = script_at(out, "scriptPubkey").kind();
                *counts.entry(kind.to_string()).or_default() += 1;
            }
        }
    }
    println!("output kinds: {counts:?}");

    // The vectors were picked to cover every standard template.
    for expected in ["P2PKH", "P2SH", "P2WPKH", "P2WSH", "P2TR", "OP_RETURN"] {
        assert!(
            counts.contains_key(expected),
            "no {expected} outputs in the vectors; counts = {counts:?}"
        );
    }
    assert_eq!(
        counts.get("NONSTANDARD"),
        None,
        "every output in the vectors should classify: {counts:?}"
    );
}

#[test]
fn no_vector_uses_a_disabled_opcode() {
    for txs in [load(LEGACY), load(SEGWIT)] {
        for tx in &txs {
            for out in tx["outputs"].as_array().unwrap() {
                let script = script_at(out, "scriptPubkey");
                // OP_RETURN payloads are arbitrary data, not executed code,
                // so a "disabled opcode" byte in one is meaningless.
                if script.kind() == ScriptKind::OpReturn {
                    continue;
                }
                assert!(
                    !script.has_disabled_opcode(),
                    "confirmed output uses a disabled opcode: {script}"
                );
            }
        }
    }
}
