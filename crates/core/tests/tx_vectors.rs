//! `Tx::decode` and `Tx::breakdown` against real mainnet transactions.
//!
//! These 22 vectors are the acceptance criteria for feature 5.2. They live
//! here, in the library's own suite, rather than only behind the web server:
//! the decoder is the thing being verified, and it must be provably correct
//! for a CLI that will never construct an HTTP response.
//!
//! Nothing here restates an expectation. Every assertion compares against the
//! vector file, so a disagreement is a bug in the decoder or a bad vector, and
//! never a stale copy of what the decoder used to do.

use bitcoin_tools_core::general::reverse_hex;
use bitcoin_tools_core::transactions::tx::{Tx, TxBreakdown};
use bitcoin_tools_vectors::{field, legacy, segwit};
use serde_json::Value;

fn check(vector: &Value, at: &str) {
    let raw = field(vector, "rawTx", at);
    let tx = Tx::from_hex(raw).unwrap_or_else(|e| panic!("{at}: {raw} failed to decode: {e}"));

    // Re-encoding must be byte-exact. A decoder that silently canonicalises —
    // rewriting a varint width or a segwit flag — reports fields the sender
    // never wrote, which for this crate is worse than refusing the input.
    assert_eq!(
        bitcoin_tools_core::hex::encode(&tx.encode()),
        raw,
        "{at}: re-encoding changed the bytes"
    );

    // Feature 1.1 against real data, and a cross-check between the crate's two
    // independent implementations of the same flip: `Txid`'s `Display` writes
    // wire order backwards, and `reverse_hex` reverses a hex string it knows
    // nothing else about. Both must produce the txid the vector shows.
    let wire = bitcoin_tools_core::hex::encode(&tx.txid().to_wire());
    assert_eq!(
        reverse_hex(&wire).unwrap_or_else(|e| panic!("{at}: {e}")),
        field(vector, "txid", at),
        "{at}: reversing the wire-order txid must give the displayed one"
    );

    let b: TxBreakdown = tx.breakdown();

    assert_eq!(b.txid, field(vector, "txid", at), "{at}: txid");
    assert_eq!(b.version, field(vector, "version", at), "{at}: version");
    assert_eq!(b.locktime, field(vector, "locktime", at), "{at}: locktime");
    assert_eq!(b.raw_tx, raw, "{at}: rawTx");
    assert_eq!(
        b.input_count,
        field(vector, "inputCount", at),
        "{at}: inputCount"
    );
    assert_eq!(
        b.output_count,
        field(vector, "outputCount", at),
        "{at}: outputCount"
    );

    // Segwit-only fields are present exactly when the vector has them.
    assert_eq!(
        b.wtxid.as_deref(),
        vector["wtxid"].as_str(),
        "{at}: wtxid presence or value"
    );
    assert_eq!(
        b.marker.as_deref(),
        vector["marker"].as_str(),
        "{at}: marker"
    );
    assert_eq!(b.flag.as_deref(), vector["flag"].as_str(), "{at}: flag");

    let inputs = vector["inputs"]
        .as_array()
        .unwrap_or_else(|| panic!("{at}: inputs is not an array"));
    assert_eq!(b.inputs.len(), inputs.len(), "{at}: input count");
    for (i, (got, want)) in b.inputs.iter().zip(inputs).enumerate() {
        let at = &format!("{at} input[{i}]");
        // Wire order, deliberately: this is the txid as the bytes carry it,
        // not the reversed form shown at the top level.
        assert_eq!(got.txid, field(want, "txid", at), "{at}: txid");
        assert_eq!(got.vout, field(want, "vout", at), "{at}: vout");
        assert_eq!(
            got.script_sig_size,
            field(want, "scriptSigSize", at),
            "{at}: scriptSigSize"
        );
        assert_eq!(
            got.script_sig,
            field(want, "scriptSig", at),
            "{at}: scriptSig"
        );
        assert_eq!(got.sequence, field(want, "sequence", at), "{at}: sequence");
    }

    let outputs = vector["outputs"]
        .as_array()
        .unwrap_or_else(|| panic!("{at}: outputs is not an array"));
    assert_eq!(b.outputs.len(), outputs.len(), "{at}: output count");
    for (i, (got, want)) in b.outputs.iter().zip(outputs).enumerate() {
        let at = &format!("{at} output[{i}]");
        assert_eq!(got.amount, field(want, "amount", at), "{at}: amount");
        assert_eq!(
            got.script_pubkey_size,
            field(want, "scriptPubkeySize", at),
            "{at}: scriptPubkeySize"
        );
        assert_eq!(
            got.script_pubkey,
            field(want, "scriptPubkey", at),
            "{at}: scriptPubkey"
        );
    }

    match (&b.witness, vector["witness"].as_array()) {
        (None, None) => {}
        (Some(got), Some(want)) => {
            // One witness per input, always — including inputs that have none.
            assert_eq!(got.len(), b.inputs.len(), "{at}: witness arity");
            assert_eq!(got.len(), want.len(), "{at}: witness count");
            for (i, (got, want)) in got.iter().zip(want).enumerate() {
                let at = &format!("{at} witness[{i}]");
                assert_eq!(
                    got.stack_items,
                    field(want, "stackItems", at),
                    "{at}: stackItems"
                );
                for (j, item) in got.items.iter().enumerate() {
                    // The vector keys stack entries by their index as a string.
                    let want = &want[j.to_string()];
                    let at = &format!("{at}[{j}]");
                    assert_eq!(item.size, field(want, "size", at), "{at}: size");
                    assert_eq!(item.item, field(want, "item", at), "{at}: item");
                }
            }
        }
        (got, want) => panic!(
            "{at}: witness presence disagrees — decoder {}, vector {}",
            if got.is_some() { "has one" } else { "has none" },
            if want.is_some() {
                "has one"
            } else {
                "has none"
            },
        ),
    }
}

#[test]
fn reproduces_every_legacy_vector() {
    let set = legacy();
    // Pinned, not just non-empty: the module doc claims 22 vectors are the
    // acceptance criteria, and a truncated file would otherwise pass with one.
    assert_eq!(set.len(), 10, "legacy vector count changed");
    for (i, v) in set.iter().enumerate() {
        check(v, &format!("legacy[{i}]"));
        assert!(v["marker"].is_null(), "legacy[{i}] vector claims a marker");
    }
}

#[test]
fn reproduces_every_segwit_vector() {
    let set = segwit();
    assert_eq!(set.len(), 12, "segwit vector count changed");
    for (i, v) in set.iter().enumerate() {
        check(v, &format!("segwit[{i}]"));
    }
}

#[test]
fn txid_and_wtxid_differ_only_when_a_witness_is_present() {
    for (i, v) in segwit().iter().enumerate() {
        let raw = v["rawTx"].as_str().unwrap();
        let tx = Tx::from_hex(raw).unwrap();
        let has_witness = tx.inputs.iter().any(|i| !i.witness.is_empty());
        assert_eq!(
            tx.txid() != tx.wtxid(),
            has_witness,
            "segwit[{i}]: txid/wtxid relationship"
        );
    }
}

#[test]
fn a_displayed_txid_parses_back_to_itself() {
    for (i, v) in legacy().iter().chain(segwit().iter()).enumerate() {
        let tx = Tx::from_hex(v["rawTx"].as_str().unwrap()).unwrap();
        let shown = tx.txid().to_string();
        assert_eq!(shown.parse(), Ok(tx.txid()), "vector[{i}]: txid round trip");
        // And it is the reverse of the wire bytes, not the wire bytes.
        assert_ne!(
            shown,
            bitcoin_tools_core::hex::encode(&tx.txid().to_wire()),
            "vector[{i}]: display order equals wire order — one of them is wrong"
        );
    }
}
