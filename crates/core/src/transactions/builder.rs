//! 5.1 — assembling a transaction from its parts.
//!
//! The inverse of [`tx`](super::tx), and deliberately *not* a second
//! serializer. [`Tx::encode`] already turns a transaction into consensus
//! bytes; writing those bytes again here would mean two places that have to
//! agree about marker, flag, varints and witness order, which is the kind of
//! duplication this crate spends its module docs avoiding.
//!
//! So [`TxBuilder`] is the door with the checks on it. It collects the fields,
//! refuses the combinations that produce bytes no node would accept, and hands
//! back a [`Tx`] — which already knows how to serialize itself, name its txid,
//! and break itself into wire fields.
//!
//! # What it does not do
//!
//! **It does not sign.** Every input's `script_sig` and `witness` are supplied
//! by the caller. Signing needs a sighash, and a sighash needs the value and
//! script of each output being spent — data a raw transaction does not carry
//! and this crate has no way to fetch. A builder that appeared to sign, using
//! only what is in front of it, would be producing signatures over the wrong
//! message. [`ecdsa::sign`](crate::crypto::ecdsa::sign) is there for whoever
//! computes the sighash.
//!
//! It also does not select coins, estimate fees or compute change. All three
//! need the prevouts and a fee policy; none is a property of the transaction
//! being built.

use std::collections::HashMap;
use std::fmt;

use super::script::Script;
use super::tx::{Input, OutPoint, Output, Tx, Witness};
use crate::general::Amount;
use crate::parse::name_table;

name_table! {
    /// Reads `legacy` or `segwit`, case-insensitively.
    ///
    /// The JSON spelling is the same two words but exactly lowercase, since
    /// that comes from `#[serde(rename_all = "lowercase")]` rather than from
    /// here — the same split [`Network`](crate::network::Network) has.
    TxKind => UnknownTxKind,
    kind: "transaction kind",
    expected: "legacy or segwit",
    {
        Legacy => "legacy";
        Segwit => "segwit";
    }
}

/// Which serialization a transaction is built in.
///
/// Not a property a caller can leave to chance, which is why
/// [`TxBuilder::new`] demands it. The two encodings are distinguishable on the
/// wire — segwit carries a marker, a flag and a witness section — and they
/// hash differently, so the same inputs and outputs under the two kinds are
/// two different transaction ids.
///
/// BIP144 ties the choice to the contents rather than leaving it free: a
/// transaction with no witness data *must* use the legacy form. [`TxBuilder`]
/// enforces both directions — see [`BuildError::SegwitWithoutWitness`] and
/// [`BuildError::WitnessOnLegacy`].
///
/// Exhaustive, unlike most enums here and for the same reason
/// [`Denomination`](crate::general::Denomination) is: BIP144 defines two
/// serializations and a third would not be a new variant, it would be a new
/// consensus format that changed the meaning of every existing `match`. A
/// caller may match both arms without a `_`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum TxKind {
    /// No marker, no flag, no witness section — everything before segwit, and
    /// everything spending only pre-segwit outputs since.
    Legacy,
    /// BIP144: a `00` marker, an `01` flag, and one witness stack per input
    /// after the outputs.
    Segwit,
}

impl From<&Tx> for TxKind {
    /// The kind a decoded transaction was serialized in. One fact, two
    /// spellings — `Tx` stores a bool because that is what the wire carries,
    /// and this is the named form. Written once here so no consumer writes the
    /// `if tx.segwit` themselves.
    fn from(tx: &Tx) -> Self {
        if tx.segwit {
            TxKind::Segwit
        } else {
            TxKind::Legacy
        }
    }
}

/// Why the parts do not make a transaction.
///
/// Every variant is a rule Bitcoin Core enforces, cited on the variant, and
/// each one names *which* input or output failed — a builder that says only
/// "invalid" leaves the caller to bisect their own request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// No inputs. Core's `CheckTransaction` calls this `bad-txns-vin-empty`,
    /// and [`Tx::decode`] refuses to read one back, so building it would
    /// produce bytes this crate's own decoder rejects.
    NoInputs,
    /// No outputs — `bad-txns-vout-empty`. A transaction that pays nothing
    /// destroys its entire input value as fee, and consensus refuses it
    /// rather than assuming that was meant.
    NoOutputs,
    /// The same output is spent twice — `bad-txns-inputs-duplicate`.
    DuplicateInput {
        /// The later of the two inputs.
        index: usize,
        /// The earlier one it repeats.
        first: usize,
    },
    /// An input spends the null outpoint, which only a coinbase may do
    /// (`bad-txns-prevout-null`).
    ///
    /// Building a coinbase is deliberately out of scope: it is valid only as a
    /// block's first transaction, its input carries a height and arbitrary
    /// data rather than a signature, and a segwit one must commit to the
    /// witness root. None of that is a property of the transaction alone.
    NullPrevout {
        /// Which input.
        index: usize,
    },
    /// An output's value is above 21 million BTC — `bad-txns-vout-toolarge`.
    ///
    /// [`Tx`] itself allows this, because a *decoder* must be able to show a
    /// malformed transaction that declares it. A builder is creating one, so
    /// the range is a precondition rather than a question.
    AmountOutOfRange {
        /// Which output.
        index: usize,
        /// The value it declared, in satoshis.
        sats: u64,
    },
    /// The outputs sum to more than 21 million BTC —
    /// `bad-txns-txouttotal-toolarge`. Each one can be in range while the
    /// total is not.
    TotalOutOfRange {
        /// The sum, in satoshis. `u128` because the point is that it does not
        /// fit in what a transaction may hold.
        sats: u128,
    },
    /// [`TxKind::Segwit`] was asked for, but no input carries witness data.
    ///
    /// BIP144: "If the witness is empty, the old serialization format should
    /// be used." Core enforces it when *reading* — a transaction with a marker
    /// and flag but no witness data fails deserialization with "Superfluous
    /// witness record" — so the bytes would be unspendable and unrelayable,
    /// which is worse than an error here.
    SegwitWithoutWitness,
    /// [`TxKind::Legacy`] was asked for, but an input carries witness data.
    ///
    /// The legacy encoding has nowhere to put it. Serializing anyway would
    /// silently drop the caller's evidence and produce a transaction that does
    /// not authorise what they asked for.
    WitnessOnLegacy {
        /// Which input.
        index: usize,
    },
    /// Larger than any block could carry — `bad-txns-oversize`.
    ///
    /// Core measures the **witness-stripped** serialization times four against
    /// `MAX_BLOCK_WEIGHT`, so the ceiling is on [`Tx::base_size`] and is a
    /// quarter of [`Tx::MAX_WEIGHT`] — 1,000,000 bytes — no matter how much
    /// witness data rides along. Measuring the witness-inclusive size against
    /// the full weight instead would be four times too permissive for a legacy
    /// transaction, where the two sizes are equal.
    TooLarge {
        /// The witness-stripped size, in bytes.
        base_size: usize,
        /// The largest that may be: `Tx::MAX_WEIGHT / 4`.
        max: usize,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BuildError::NoInputs => f.write_str("a transaction must spend at least one output"),
            BuildError::NoOutputs => f.write_str("a transaction must pay at least one output"),
            BuildError::DuplicateInput { index, first } => {
                write!(f, "input {index} spends the same outpoint as input {first}")
            }
            BuildError::NullPrevout { index } => write!(
                f,
                "input {index} spends the null outpoint, which only a coinbase may do"
            ),
            BuildError::AmountOutOfRange { index, sats } => write!(
                f,
                "output {index} pays {sats} satoshis, above the {} that will ever exist",
                Amount::MAX_MONEY.to_sat()
            ),
            BuildError::TotalOutOfRange { sats } => write!(
                f,
                "the outputs total {sats} satoshis, above the {} that will ever exist",
                Amount::MAX_MONEY.to_sat()
            ),
            BuildError::SegwitWithoutWitness => f.write_str(
                "a segwit transaction needs witness data on at least one input; \
                 with none, BIP144 requires the legacy encoding",
            ),
            BuildError::WitnessOnLegacy { index } => write!(
                f,
                "input {index} carries witness data, which the legacy encoding cannot hold"
            ),
            BuildError::TooLarge { base_size, max } => write!(
                f,
                "the transaction is {base_size} bytes before witnesses; the maximum is {max}"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Collects the parts of a transaction and checks them.
///
/// ```
/// use bitcoin_tools_core::general::Amount;
/// use bitcoin_tools_core::transactions::builder::{TxBuilder, TxKind};
/// use bitcoin_tools_core::transactions::script::Script;
/// use bitcoin_tools_core::transactions::tx::{OutPoint, Txid};
///
/// let previous: Txid =
///     "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7".parse()?;
///
/// let tx = TxBuilder::new(TxKind::Legacy)
///     .spend(OutPoint { txid: previous, vout: 1 })
///     .pay(
///         Amount::from_sat(54_697),
///         Script::from_hex("0014275b468073affad6c1b2833d026416ec07392b7f")?,
///     )
///     .build()?;
///
/// assert_eq!(tx.version, 2, "BIP68 relative locktimes, unless you say otherwise");
/// assert_eq!(tx.inputs[0].sequence, TxBuilder::SEQUENCE_FINAL);
/// assert!(!tx.segwit);
///
/// // `Tx` does the rest: the bytes, the id, the field-by-field breakdown.
/// let raw = tx.encode();
/// assert_eq!(bitcoin_tools_core::transactions::Tx::decode(&raw)?, tx);
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBuilder {
    kind: TxKind,
    version: u32,
    lock_time: u32,
    inputs: Vec<Input>,
    outputs: Vec<Output>,
}

impl TxBuilder {
    /// The version this starts at.
    ///
    /// Version 2, not 1: it is what enables BIP68 relative locktimes, it is
    /// what every wallet has produced since 2016, and a caller who needs
    /// something else says so with [`TxBuilder::version`].
    pub const DEFAULT_VERSION: u32 = 2;

    /// The sequence number that opts out of both BIP68 relative locktime and
    /// BIP125 replace-by-fee.
    ///
    /// The default for [`TxBuilder::spend`], because opting a caller *into*
    /// replaceability without being asked would change what their transaction
    /// means.
    pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

    /// Start a transaction of the given kind.
    #[must_use]
    pub const fn new(kind: TxKind) -> Self {
        TxBuilder {
            kind,
            version: Self::DEFAULT_VERSION,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        }
    }

    /// Set the version. See [`Tx::version`].
    #[must_use]
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set the locktime — the earliest height or time this may be mined.
    ///
    /// Note it has no effect unless at least one input's sequence is below
    /// [`TxBuilder::SEQUENCE_FINAL`]; that is consensus, not this builder.
    #[must_use]
    pub fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    /// Spend an outpoint, with an empty scriptSig and no witness.
    ///
    /// The shape an unsigned transaction has, and the one segwit inputs keep:
    /// a P2WPKH spend's scriptSig stays empty and its evidence lives in the
    /// witness. Use [`TxBuilder::input`] to supply either.
    #[must_use]
    pub fn spend(self, previous_output: OutPoint) -> Self {
        self.input(Input {
            previous_output,
            script_sig: Script::new(Vec::new()),
            sequence: Self::SEQUENCE_FINAL,
            witness: Witness::default(),
        })
    }

    /// Start from an existing transaction.
    ///
    /// The decode-change-rebuild shape, which is what a tool does most: read a
    /// transaction, alter one field, emit it again. Everything is taken from
    /// `tx`, including its kind, so a rebuild with no changes produces the same
    /// bytes — with one exception, and it is
    /// [`Tx::is_bip144_canonical`]'s: a transaction carrying a marker and flag
    /// but no witness data decodes here and will be refused by
    /// [`TxBuilder::build`], because Core refuses those bytes too.
    #[must_use]
    pub fn from_tx(tx: &Tx) -> Self {
        TxBuilder {
            kind: TxKind::from(tx),
            version: tx.version,
            lock_time: tx.lock_time,
            inputs: tx.inputs.clone(),
            outputs: tx.outputs.clone(),
        }
    }

    /// Add a fully specified input.
    #[must_use]
    pub fn input(mut self, input: Input) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add several inputs, in order.
    #[must_use]
    pub fn inputs(mut self, inputs: impl IntoIterator<Item = Input>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Pay an amount to a script.
    #[must_use]
    pub fn pay(self, value: Amount, script_pubkey: Script) -> Self {
        self.output(Output {
            value,
            script_pubkey,
        })
    }

    /// Add a fully specified output.
    #[must_use]
    pub fn output(mut self, output: Output) -> Self {
        self.outputs.push(output);
        self
    }

    /// Add several outputs, in order.
    #[must_use]
    pub fn outputs(mut self, outputs: impl IntoIterator<Item = Output>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    /// Check everything and produce the transaction.
    ///
    /// # Errors
    ///
    /// [`BuildError`], which names the offending input or output.
    pub fn build(self) -> Result<Tx, BuildError> {
        if self.inputs.is_empty() {
            return Err(BuildError::NoInputs);
        }
        if self.outputs.is_empty() {
            return Err(BuildError::NoOutputs);
        }

        let mut seen: HashMap<OutPoint, usize> = HashMap::with_capacity(self.inputs.len());
        for (index, input) in self.inputs.iter().enumerate() {
            let outpoint = input.previous_output;
            if outpoint.is_null() {
                return Err(BuildError::NullPrevout { index });
            }
            if let Some(&first) = seen.get(&outpoint) {
                return Err(BuildError::DuplicateInput { index, first });
            }
            seen.insert(outpoint, index);

            if self.kind == TxKind::Legacy && !input.witness.is_empty() {
                return Err(BuildError::WitnessOnLegacy { index });
            }
        }

        let mut total: u128 = 0;
        for (index, output) in self.outputs.iter().enumerate() {
            if !output.value.is_money_range() {
                return Err(BuildError::AmountOutOfRange {
                    index,
                    sats: output.value.to_sat(),
                });
            }
            total += u128::from(output.value.to_sat());
        }
        if total > u128::from(Amount::MAX_MONEY.to_sat()) {
            return Err(BuildError::TotalOutOfRange { sats: total });
        }

        let segwit = self.kind == TxKind::Segwit;
        let tx = Tx {
            version: self.version,
            inputs: self.inputs,
            outputs: self.outputs,
            lock_time: self.lock_time,
            segwit,
        };

        // BIP144 again, from the other side: the marker and flag may only
        // appear when there is something for them to announce.
        if segwit && !tx.has_witness() {
            return Err(BuildError::SegwitWithoutWitness);
        }

        // `bad-txns-oversize`, as Core states it: the witness-stripped size,
        // scaled, against the block weight limit. Counted rather than
        // serialized, so validating a large transaction does not build one.
        let base_size = tx.base_size();
        let max = Tx::MAX_WEIGHT / Tx::WITNESS_SCALE_FACTOR;
        if base_size > max {
            return Err(BuildError::TooLarge { base_size, max });
        }
        Ok(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;
    use crate::transactions::tx::Txid;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_wire([n; 32]),
            vout: u32::from(n),
        }
    }

    fn script() -> Script {
        Script::from_hex("0014275b468073affad6c1b2833d026416ec07392b7f").expect("valid hex")
    }

    fn legacy() -> TxBuilder {
        TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .pay(Amount::from_sat(1_000), script())
    }

    #[test]
    fn the_defaults_are_the_ones_a_caller_would_have_to_look_up() {
        let tx = legacy().build().expect("a complete transaction");
        assert_eq!(tx.version, 2, "BIP68 relative locktimes are enabled");
        assert_eq!(tx.lock_time, 0);
        assert_eq!(tx.inputs[0].sequence, 0xffff_ffff, "not replaceable");
        assert!(tx.inputs[0].script_sig.as_bytes().is_empty());
        assert!(!tx.segwit);
    }

    #[test]
    fn what_is_built_is_what_decodes_back() {
        let tx = legacy()
            .version(1)
            .lock_time(500_000)
            .spend(outpoint(2))
            .pay(Amount::from_sat(9), script())
            .build()
            .expect("a complete transaction");

        let raw = tx.encode();
        assert_eq!(Tx::decode(&raw), Ok(tx.clone()));
        assert_eq!(tx.version, 1);
        assert_eq!(tx.lock_time, 500_000);
        assert_eq!(tx.inputs.len(), 2);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.txid(), tx.wtxid(), "no witness, so the two ids agree");
    }

    #[test]
    fn a_segwit_build_carries_marker_flag_and_witness() {
        let witness = Witness::new(vec![vec![0x30; 71], vec![0x02; 33]]);
        let tx = TxBuilder::new(TxKind::Segwit)
            .input(Input {
                previous_output: outpoint(1),
                script_sig: Script::new(Vec::new()),
                sequence: TxBuilder::SEQUENCE_FINAL,
                witness,
            })
            .pay(Amount::from_sat(1_000), script())
            .build()
            .expect("a complete transaction");

        assert!(tx.segwit);
        let raw = hex::encode(&tx.encode());
        assert!(raw[8..12].starts_with("0001"), "marker and flag: {raw}");
        assert_ne!(
            tx.txid(),
            tx.wtxid(),
            "the witness is in one and not the other"
        );
        assert_eq!(Tx::decode(&tx.encode()), Ok(tx));
    }

    /// The rule that stops the builder producing bytes no node will read
    /// back. Core fails deserialization of these with "Superfluous witness
    /// record", so the transaction would be unspendable in a way nothing
    /// local would notice.
    #[test]
    fn segwit_without_witness_data_is_refused() {
        let empty = TxBuilder::new(TxKind::Segwit)
            .spend(outpoint(1))
            .pay(Amount::from_sat(1_000), script())
            .build();
        assert_eq!(empty, Err(BuildError::SegwitWithoutWitness));

        // One input with data is enough; a mixed transaction is ordinary.
        let mixed = TxBuilder::new(TxKind::Segwit)
            .spend(outpoint(1))
            .input(Input {
                previous_output: outpoint(2),
                script_sig: Script::new(Vec::new()),
                sequence: TxBuilder::SEQUENCE_FINAL,
                witness: Witness::new(vec![vec![0x01]]),
            })
            .pay(Amount::from_sat(1_000), script())
            .build();
        assert!(mixed.is_ok(), "{mixed:?}");
    }

    /// And the other direction: the legacy encoding has nowhere to put a
    /// witness, so serializing one would drop it silently.
    #[test]
    fn witness_data_on_a_legacy_build_is_refused() {
        let built = TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .input(Input {
                previous_output: outpoint(2),
                script_sig: Script::new(Vec::new()),
                sequence: TxBuilder::SEQUENCE_FINAL,
                witness: Witness::new(vec![vec![0x01]]),
            })
            .pay(Amount::from_sat(1_000), script())
            .build();
        assert_eq!(built, Err(BuildError::WitnessOnLegacy { index: 1 }));
    }

    #[test]
    fn a_transaction_needs_something_to_spend_and_something_to_pay() {
        let no_inputs = TxBuilder::new(TxKind::Legacy)
            .pay(Amount::from_sat(1), script())
            .build();
        assert_eq!(no_inputs, Err(BuildError::NoInputs));

        let no_outputs = TxBuilder::new(TxKind::Legacy).spend(outpoint(1)).build();
        assert_eq!(no_outputs, Err(BuildError::NoOutputs));
    }

    #[test]
    fn the_same_outpoint_cannot_be_spent_twice() {
        let built = legacy().spend(outpoint(1)).build();
        assert_eq!(
            built,
            Err(BuildError::DuplicateInput { index: 1, first: 0 })
        );

        // A different vout of the same transaction is a different outpoint.
        let other_vout = legacy()
            .spend(OutPoint {
                txid: Txid::from_wire([1; 32]),
                vout: 99,
            })
            .build();
        assert!(other_vout.is_ok());
    }

    #[test]
    fn the_coinbase_outpoint_is_refused() {
        let built = TxBuilder::new(TxKind::Legacy)
            .spend(OutPoint {
                txid: Txid::from_wire([0; 32]),
                vout: u32::MAX,
            })
            .pay(Amount::from_sat(1), script())
            .build();
        assert_eq!(built, Err(BuildError::NullPrevout { index: 0 }));

        // Only *both* halves make it null: a zero txid with a real vout is a
        // real (if unusual) outpoint, and vout 0xffffffff of a real txid is
        // too.
        assert!(
            TxBuilder::new(TxKind::Legacy)
                .spend(OutPoint {
                    txid: Txid::from_wire([0; 32]),
                    vout: 0
                })
                .pay(Amount::from_sat(1), script())
                .build()
                .is_ok()
        );
    }

    /// The decoder deliberately allows out-of-range values, because it has to
    /// be able to show a malformed transaction. A builder is on the other
    /// side of that line.
    #[test]
    fn values_are_range_checked_individually_and_in_total() {
        let too_big = TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .pay(Amount::from_sat(Amount::MAX_MONEY.to_sat() + 1), script())
            .build();
        assert_eq!(
            too_big,
            Err(BuildError::AmountOutOfRange {
                index: 0,
                sats: Amount::MAX_MONEY.to_sat() + 1
            })
        );

        // Two halves, each in range, summing past the cap.
        let half = Amount::from_sat(Amount::MAX_MONEY.to_sat() / 2 + 1);
        let total = TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .pay(half, script())
            .pay(half, script())
            .build();
        assert_eq!(
            total,
            Err(BuildError::TotalOutOfRange {
                sats: u128::from(half.to_sat()) * 2
            })
        );

        // Exactly the cap is allowed: it is a real quantity.
        assert!(
            TxBuilder::new(TxKind::Legacy)
                .spend(outpoint(1))
                .pay(Amount::MAX_MONEY, script())
                .build()
                .is_ok()
        );
    }

    /// `bad-txns-oversize`, at the boundary. The rule is on the
    /// *witness-stripped* size, so a legacy transaction hits it at a quarter
    /// of the weight limit — which is the case a witness-inclusive check would
    /// wave through.
    #[test]
    fn the_size_limit_is_the_stripped_one_scaled() {
        let max = Tx::MAX_WEIGHT / Tx::WITNESS_SCALE_FACTOR;

        // One output whose script brings the base size to exactly the cap.
        let overhead = TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .pay(Amount::from_sat(1), Script::new(Vec::new()))
            .build()
            .expect("a minimal transaction")
            .base_size();
        // Swapping the empty script for a big one trades its one-byte length
        // prefix for a five-byte one, since a length past 0xffff needs the
        // `fe` form. `assert_eq!(base_size(), max)` below is what proves this
        // arithmetic rather than the comment.
        let room = max - overhead - 4;

        let exactly = TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .pay(Amount::from_sat(1), Script::new(vec![0u8; room]))
            .build()
            .expect("exactly at the cap is a transaction");
        assert_eq!(exactly.base_size(), max);
        assert_eq!(exactly.weight(), Tx::MAX_WEIGHT);

        let one_more = TxBuilder::new(TxKind::Legacy)
            .spend(outpoint(1))
            .pay(Amount::from_sat(1), Script::new(vec![0u8; room + 1]))
            .build();
        assert_eq!(
            one_more,
            Err(BuildError::TooLarge {
                base_size: max + 1,
                max
            })
        );
    }

    /// The shape a tool actually uses: read a transaction, change one field,
    /// emit it again.
    #[test]
    fn a_transaction_rebuilds_from_itself() {
        let original = TxBuilder::new(TxKind::Segwit)
            .version(1)
            .lock_time(500_000)
            .input(Input {
                previous_output: outpoint(1),
                script_sig: Script::new(Vec::new()),
                sequence: 0xffff_fffd,
                witness: Witness::new(vec![vec![0x30; 71]]),
            })
            .pay(Amount::from_sat(1_000), script())
            .build()
            .expect("a complete transaction");

        let rebuilt = TxBuilder::from_tx(&original)
            .build()
            .expect("what decoded, rebuilds");
        assert_eq!(rebuilt, original);
        assert_eq!(rebuilt.encode(), original.encode());
        assert_eq!(TxKind::from(&original), TxKind::Segwit);

        // …and one field changed is one field changed.
        let bumped = TxBuilder::from_tx(&original)
            .lock_time(0)
            .build()
            .expect("still a transaction");
        assert_eq!(bumped.lock_time, 0);
        assert_ne!(bumped.txid(), original.txid());
    }

    #[test]
    fn the_kind_reads_back_from_the_names_a_caller_would_type() {
        assert_eq!("legacy".parse(), Ok(TxKind::Legacy));
        assert_eq!("SEGWIT".parse(), Ok(TxKind::Segwit));
        assert_eq!(TxKind::Segwit.as_str(), "segwit");
        assert!("taproot".parse::<TxKind>().is_err());
        assert!(
            "witness".parse::<TxKind>().is_err(),
            "no tool spells it that way, so neither does this"
        );
    }
}
