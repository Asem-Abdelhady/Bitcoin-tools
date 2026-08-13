//! Building a transaction as a use case, independent of how it was requested.
//!
//! The transport hands this layer strings and numbers; it hands back a [`Tx`].
//! What makes that more than a type conversion is *where* each check lives:
//! hex, sizes and emptiness are input policy and belong here, while the rules
//! about what makes a transaction a transaction — an input that is spent
//! twice, a value above 21 million, a segwit encoding with nothing to put in
//! it — belong to [`TxBuilder`], which enforces them for a CLI too.
//!
//! # The request shape lives here, not in the handler
//!
//! [`TxSpec`] carries its own serde attributes, so there is one set of structs
//! rather than a handler DTO mirrored by a service model with an identity
//! `From` between them. Adding a field to a mirrored pair means four edits and
//! the compiler catches three.
//!
//! The layer table in CLAUDE.md puts DTOs in handlers, and this is the reading
//! of it that holds: what a request *is allowed to contain* — `camelCase`
//! spelling, `deny_unknown_fields`, which fields are optional — is input
//! policy, which is this layer's job. serde is a serialization crate, not a
//! transport one; `core` derives it too. What stays in the handler is the
//! *response*, which renders values into strings and is a view rather than a
//! spec.

use std::fmt;

use serde::Deserialize;

use crate::services::input::{InputError, hex_bytes_allowing_empty};
use bitcoin_tools_core::general::Amount;
use bitcoin_tools_core::hashes::HashParseError;
use bitcoin_tools_core::transactions::builder::{BuildError, TxBuilder, TxKind};
use bitcoin_tools_core::transactions::script::Script;
use bitcoin_tools_core::transactions::tx::{Input, OutPoint, Output, Tx, Txid, Witness};

/// One output to spend, as a request describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InputSpec {
    /// The funding transaction, in the **displayed** order an explorer shows.
    pub txid: String,
    /// Which of its outputs.
    pub vout: u32,
    /// Unlocking script, hex. Defaults to empty, which is what an unsigned
    /// input and every native segwit input carry — see
    /// [`hex_bytes_allowing_empty`].
    #[serde(default)]
    pub script_sig: String,
    /// Defaults to [`TxBuilder::SEQUENCE_FINAL`] when the request omits it.
    pub sequence: Option<u32>,
    /// Witness stack items, bottom first, each hex. Only for
    /// [`TxKind::Segwit`].
    #[serde(default)]
    pub witness: Vec<String>,
}

/// One payment, as a request describes it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputSpec {
    /// Satoshis.
    pub amount: u64,
    /// Locking script, hex.
    pub script_pubkey: String,
}

/// Everything needed to build a transaction.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TxSpec {
    /// Legacy or segwit — the serialization, which is not inferred, and the
    /// one field with no default: it changes the bytes, the txid, and whether
    /// a witness survives at all. See [`TxKind`].
    #[serde(rename = "type")]
    pub kind: TxKind,
    /// Defaults to [`TxBuilder::DEFAULT_VERSION`].
    pub version: Option<u32>,
    /// Defaults to zero.
    pub lock_time: Option<u32>,
    /// What to spend.
    pub inputs: Vec<InputSpec>,
    /// What to pay.
    pub outputs: Vec<OutputSpec>,
}

/// Where in the request a field problem was found.
///
/// Every located error prints as `<subject> <index> <field>`, so a client
/// reads one grammar rather than one per variant, and a witness item names
/// its own position in the stack — without which "witness: invalid hex" on a
/// hundred-item stack is exactly the bisecting this type exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Located {
    /// `input` or `output`.
    pub subject: &'static str,
    /// Which one, counting from zero.
    pub index: usize,
    /// Which field of it, spelled the way the wire spells it.
    pub field: &'static str,
    /// Which witness stack item, where the field is a stack.
    pub item: Option<usize>,
}

impl fmt::Display for Located {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.subject, self.index, self.field)?;
        match self.item {
            Some(item) => write!(f, "[{item}]"),
            None => Ok(()),
        }
    }
}

/// A field of the request that could not be read, or a transaction that the
/// domain refuses to build.
///
/// There is no `Input` arm and no [`ServiceError`](crate::services::error::ServiceError)
/// wrapper around this, deliberately: every input failure at this endpoint has
/// a *position*, so all of them are located variants here. Wrapping would add
/// a layer whose other half nothing can construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildFailure {
    /// A `txid` was not thirty-two bytes of hex in displayed order.
    Txid {
        /// Which input.
        at: Located,
        /// What was wrong with it.
        error: HashParseError,
    },
    /// A hex field of one input or output was unusable.
    ///
    /// The status and slug come from the [`InputError`] inside, so a bad
    /// script here reports exactly what a bad script reports at every other
    /// endpoint; only the message gains the position.
    Field {
        /// Where it was.
        at: Located,
        /// What was wrong with it.
        error: InputError,
    },
    /// The parts were readable but do not make a transaction.
    Rules(BuildError),
}

impl fmt::Display for BuildFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildFailure::Txid { at, error } => write!(f, "{at}: {error}"),
            BuildFailure::Field { at, error } => write!(f, "{at}: {error}"),
            BuildFailure::Rules(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for BuildFailure {}

/// Assemble a transaction from the parts a request described.
///
/// # Errors
///
/// [`BuildFailure`], naming the input or output at fault.
pub fn build_tx(spec: &TxSpec) -> Result<Tx, BuildFailure> {
    let mut builder = TxBuilder::new(spec.kind);
    if let Some(version) = spec.version {
        builder = builder.version(version);
    }
    if let Some(lock_time) = spec.lock_time {
        builder = builder.lock_time(lock_time);
    }

    for (index, input) in spec.inputs.iter().enumerate() {
        builder = builder.input(read_input(index, input)?);
    }
    for (index, output) in spec.outputs.iter().enumerate() {
        builder = builder.output(read_output(index, output)?);
    }

    builder.build().map_err(BuildFailure::Rules)
}

/// A hex field, capped at the size a script may be. The real ceiling is the
/// finished transaction's, which [`TxBuilder::build`] applies once everything
/// is assembled — this catches a single absurd field before the whole request
/// is walked.
///
/// Returns bytes rather than a [`Script`], because a witness item is not a
/// script: a signature and a public key are stack items, and wrapping them in
/// a script type to unwrap them again would allocate twice to say something
/// untrue.
fn field_bytes(at: Located, hex: &str) -> Result<Vec<u8>, BuildFailure> {
    hex_bytes_allowing_empty(hex, at.field, Script::MAX_SIZE)
        .map_err(|error| BuildFailure::Field { at, error })
}

fn read_input(index: usize, spec: &InputSpec) -> Result<Input, BuildFailure> {
    let at = |field, item| Located {
        subject: "input",
        index,
        field,
        item,
    };

    let txid: Txid = spec.txid.parse().map_err(|error| BuildFailure::Txid {
        at: at("txid", None),
        error,
    })?;

    let witness = spec
        .witness
        .iter()
        .enumerate()
        .map(|(item, hex)| field_bytes(at("witness", Some(item)), hex))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Input {
        previous_output: OutPoint {
            txid,
            vout: spec.vout,
        },
        script_sig: Script::new(field_bytes(at("scriptSig", None), &spec.script_sig)?),
        sequence: spec.sequence.unwrap_or(TxBuilder::SEQUENCE_FINAL),
        witness: Witness::new(witness),
    })
}

fn read_output(index: usize, spec: &OutputSpec) -> Result<Output, BuildFailure> {
    let at = Located {
        subject: "output",
        index,
        field: "scriptPubkey",
        item: None,
    };
    Ok(Output {
        value: Amount::from_sat(spec.amount),
        script_pubkey: Script::new(field_bytes(at, &spec.script_pubkey)?),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_tools_core::hex;

    const FUNDING: &str = "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7";
    const P2WPKH: &str = "0014275b468073affad6c1b2833d026416ec07392b7f";

    fn input() -> InputSpec {
        InputSpec {
            txid: FUNDING.to_string(),
            vout: 1,
            script_sig: String::new(),
            sequence: None,
            witness: Vec::new(),
        }
    }

    fn output() -> OutputSpec {
        OutputSpec {
            amount: 54_697,
            script_pubkey: P2WPKH.to_string(),
        }
    }

    fn legacy() -> TxSpec {
        TxSpec {
            kind: TxKind::Legacy,
            version: None,
            lock_time: None,
            inputs: vec![input()],
            outputs: vec![output()],
        }
    }

    #[test]
    fn builds_a_legacy_transaction_from_its_parts() {
        let tx = build_tx(&legacy()).expect("a complete request");

        assert_eq!(tx.version, 2, "the builder's default, not the wire's");
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs[0].value.to_sat(), 54_697);
        assert!(!tx.segwit);
        // The txid the request named is the *displayed* form, and appears
        // reversed in the serialization.
        assert_eq!(tx.inputs[0].previous_output.txid.to_string(), FUNDING);
        assert!(
            hex::encode(&tx.encode())
                .contains(&hex::encode(&tx.inputs[0].previous_output.txid.to_wire()))
        );
    }

    #[test]
    fn optional_fields_fall_back_to_the_builders_defaults() {
        let tx = build_tx(&legacy()).expect("a complete request");
        assert_eq!(tx.inputs[0].sequence, TxBuilder::SEQUENCE_FINAL);
        assert_eq!(tx.lock_time, 0);

        let spec = TxSpec {
            version: Some(1),
            lock_time: Some(500_000),
            inputs: vec![InputSpec {
                sequence: Some(0xffff_fffd),
                ..input()
            }],
            ..legacy()
        };
        let tx = build_tx(&spec).expect("a complete request");
        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 500_000);
        assert_eq!(tx.inputs[0].sequence, 0xffff_fffd, "RBF signalled");
    }

    #[test]
    fn a_witness_makes_it_a_segwit_transaction() {
        let spec = TxSpec {
            kind: TxKind::Segwit,
            inputs: vec![InputSpec {
                witness: vec!["30".repeat(71), "02".repeat(33)],
                ..input()
            }],
            ..legacy()
        };
        let tx = build_tx(&spec).expect("a complete request");

        assert!(tx.segwit);
        assert_eq!(tx.inputs[0].witness.len(), 2);
        assert_ne!(tx.txid(), tx.wtxid());
    }

    #[test]
    fn empty_scripts_and_witness_items_are_values_not_mistakes() {
        let spec = TxSpec {
            kind: TxKind::Segwit,
            inputs: vec![InputSpec {
                script_sig: String::new(),
                witness: vec![String::new(), "01".to_string()],
                ..input()
            }],
            outputs: vec![OutputSpec {
                script_pubkey: String::new(),
                ..output()
            }],
            ..legacy()
        };
        let tx = build_tx(&spec).expect("empty is a legitimate script");
        assert!(tx.inputs[0].script_sig.as_bytes().is_empty());
        assert_eq!(tx.inputs[0].witness.items()[0], Vec::<u8>::new());
        assert!(tx.outputs[0].script_pubkey.as_bytes().is_empty());
    }

    #[test]
    fn a_bad_field_says_which_one() {
        let spec = TxSpec {
            inputs: vec![input(), InputSpec { vout: 2, ..input() }],
            ..legacy()
        };

        let bad_txid = TxSpec {
            inputs: vec![
                input(),
                InputSpec {
                    txid: "not-a-txid".to_string(),
                    ..input()
                },
            ],
            ..spec.clone()
        };
        assert!(matches!(
            build_tx(&bad_txid),
            Err(BuildFailure::Txid {
                at: Located { index: 1, .. },
                ..
            })
        ));

        let bad_script = TxSpec {
            inputs: vec![
                input(),
                InputSpec {
                    script_sig: "zz".to_string(),
                    ..input()
                },
            ],
            ..spec.clone()
        };
        assert!(matches!(
            build_tx(&bad_script),
            Err(BuildFailure::Field {
                at: Located {
                    subject: "input",
                    index: 1,
                    field: "scriptSig",
                    ..
                },
                ..
            })
        ));

        let bad_output = TxSpec {
            outputs: vec![
                output(),
                OutputSpec {
                    script_pubkey: "abc".to_string(),
                    ..output()
                },
            ],
            ..spec
        };
        assert!(matches!(
            build_tx(&bad_output),
            Err(BuildFailure::Field {
                at: Located {
                    subject: "output",
                    index: 1,
                    field: "scriptPubkey",
                    ..
                },
                ..
            })
        ));
    }

    #[test]
    fn the_domain_rules_come_through_untouched() {
        let no_inputs = TxSpec {
            inputs: Vec::new(),
            ..legacy()
        };
        assert_eq!(
            build_tx(&no_inputs),
            Err(BuildFailure::Rules(BuildError::NoInputs))
        );

        let segwit_without_witness = TxSpec {
            kind: TxKind::Segwit,
            ..legacy()
        };
        assert_eq!(
            build_tx(&segwit_without_witness),
            Err(BuildFailure::Rules(BuildError::SegwitWithoutWitness))
        );

        let duplicate = TxSpec {
            inputs: vec![input(), input()],
            ..legacy()
        };
        assert_eq!(
            build_tx(&duplicate),
            Err(BuildFailure::Rules(BuildError::DuplicateInput {
                index: 1,
                first: 0
            }))
        );
    }
}
