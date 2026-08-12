//! Bitcoin transactions: the consensus encoding, decoded.
//!
//! Two views live here, deliberately separate:
//!
//! * [`Tx`] — the *semantic* model. Numbers are numbers, scripts are
//!   [`Script`]s, and each input owns its witness.
//! * [`TxBreakdown`] — the *wire-field* view. Every field as the exact hex
//!   bytes it occupies in the serialization, in serialization order. This is
//!   the decomposition the vectors in `vectors/` use.
//!
//! Neither knows anything about HTTP, so a CLI, a batch job, or an axum
//! handler can all build on them.

use std::fmt;
use std::num::NonZeroUsize;

use super::script::Script;
use crate::bytes::{ReadError, Reader, write_varint};
use crate::general::Amount;
use crate::hashes::{Hash, HashParseError, hash256};
use crate::hex::{self, HexError};

/// A transaction id.
///
/// Thirty-two bytes in *internal* (wire) order, with a [`fmt::Display`] that
/// reverses — the order block explorers and RPC print. That one `Display` impl
/// is the entire statement of this type's byte-order convention; everything
/// else comes from [`struct@Hash`], which stores wire order and never guesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Txid(Hash<32>);

impl Txid {
    /// Wrap bytes as they appear inside a serialized transaction.
    #[must_use]
    pub const fn from_wire(bytes: [u8; 32]) -> Self {
        Txid(Hash::from_bytes(bytes))
    }

    /// The bytes as they appear inside a serialized transaction.
    #[must_use]
    pub const fn to_wire(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The underlying digest, for anything that is about thirty-two bytes
    /// rather than about a transaction — a merkle tree, say.
    ///
    /// **The value returned prints in wire order.** [`struct@Hash`]'s
    /// `Display` is the forward one and the reversal lives on `Txid` alone, so
    /// `txid.to_string()` and `txid.to_hash().to_string()` are the same bytes
    /// rendered opposite ways. Reach for
    /// [`Hash::to_hex_reversed`](crate::hashes::Hash::to_hex_reversed) if you
    /// want the explorer form from a bare hash.
    #[must_use]
    pub const fn to_hash(self) -> Hash<32> {
        self.0
    }

    /// Take a digest as a transaction id, in wire order.
    ///
    /// The inverse of [`Txid::to_hash`], so a caller who went down to the
    /// digest can come back without routing through raw bytes.
    #[must_use]
    pub const fn from_hash(hash: Hash<32>) -> Self {
        Txid(hash)
    }
}

impl fmt::Display for Txid {
    /// Reversed — the order block explorers and RPC use.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&self.0.to_hex_reversed())
    }
}

impl std::str::FromStr for Txid {
    type Err = HashParseError;

    /// Parses the **displayed** form, undoing the reversal that
    /// [`fmt::Display`] applies, so `txid.to_string().parse()` is the
    /// identity.
    ///
    /// This closes a trap: hex-decoding an explorer txid straight into
    /// [`Txid::from_wire`] yields a byte-reversed value that nothing
    /// downstream can detect. Byte order is a decision this type makes, not
    /// one it leaves to the caller.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Hash::from_hex_reversed(s).map(Txid)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Txid {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// The output being spent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct OutPoint {
    /// The transaction that created the output being spent.
    pub txid: Txid,
    /// Which of that transaction's outputs, counting from zero.
    pub vout: u32,
}

/// An input's witness: a stack of byte vectors, empty for non-segwit inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Witness(Vec<Vec<u8>>);

impl Witness {
    /// Build a witness from its stack items, bottom first.
    #[must_use]
    pub fn new(items: Vec<Vec<u8>>) -> Self {
        Witness(items)
    }

    /// The stack items, in the order they are serialized.
    #[must_use]
    pub fn items(&self) -> &[Vec<u8>] {
        &self.0
    }

    /// True for an input with no witness data — every input of a legacy
    /// transaction, and any non-witness input of a segwit one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many stack items there are.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// One input: what it spends, and the evidence it may.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Input {
    /// The output being spent.
    pub previous_output: OutPoint,
    /// The unlocking script. Empty for a native segwit input, which puts its
    /// evidence in the witness instead.
    pub script_sig: Script,
    /// BIP68 relative locktime and RBF signalling, or `0xffffffff` for
    /// neither.
    pub sequence: u32,
    /// One witness per input, always — empty when this input has none.
    /// A transaction can mix witness and non-witness inputs, so this cannot
    /// live on the transaction as a single optional field.
    pub witness: Witness,
}

/// One output: an amount and the conditions to claim it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Output {
    /// What this output pays.
    ///
    /// Not range-checked: the wire carries a `u64`, and a malformed
    /// transaction can declare more than will ever exist. Ask
    /// [`Amount::is_money_range`] if that matters to you — refusing it here
    /// would mean this type could not hold a transaction the decoder is
    /// expected to explain.
    pub value: Amount,
    /// The locking script — the conditions for spending this output.
    pub script_pubkey: Script,
}

/// A decoded transaction — the semantic view. For the byte layout, see
/// [`TxBreakdown`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct Tx {
    /// Transaction version. Consensus reads 2 as enabling BIP68 relative
    /// locktimes; nothing rejects other values outright.
    pub version: u32,
    /// What this transaction spends. Never empty in a valid transaction.
    pub inputs: Vec<Input>,
    /// What it pays.
    pub outputs: Vec<Output>,
    /// The earliest height or time this may be mined, or 0 for no constraint.
    pub lock_time: u32,
    /// Whether this transaction was serialized in segwit form (BIP144 marker
    /// and flag present). Kept from decoding so re-encoding is byte-exact: a
    /// transaction with all-empty witnesses is *supposed* to use the legacy
    /// form, but the two encodings are distinguishable and we preserve
    /// whichever one we were handed.
    pub segwit: bool,
}

/// Why bytes were not a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxDecodeError {
    /// No bytes at all.
    Empty,
    /// The input was not hex — only from [`Tx::from_hex`].
    Hex(HexError),
    /// The byte stream ran out, or declared a count that could not fit.
    Read(ReadError),
    /// A transaction must spend something.
    NoInputs,
    /// BIP144 says the byte after the marker must be non-zero.
    BadSegwitFlag {
        /// The byte found where `0x01` was required.
        flag: u8,
    },
    /// Decoded successfully but bytes were left over.
    TrailingBytes {
        /// Bytes the transaction actually used.
        consumed: usize,
        /// Bytes supplied.
        total: usize,
    },
}

impl fmt::Display for TxDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TxDecodeError::Empty => f.write_str("transaction is empty"),
            TxDecodeError::Hex(e) => write!(f, "{e}"),
            TxDecodeError::Read(e) => write!(f, "{e}"),
            TxDecodeError::NoInputs => f.write_str("transaction has no inputs"),
            TxDecodeError::BadSegwitFlag { flag } => {
                write!(f, "segwit flag must be 0x01, got {flag:#04x}")
            }
            TxDecodeError::TrailingBytes { consumed, total } => {
                write!(
                    f,
                    "{} trailing bytes after the transaction",
                    total - consumed
                )
            }
        }
    }
}

impl From<ReadError> for TxDecodeError {
    fn from(e: ReadError) -> Self {
        TxDecodeError::Read(e)
    }
}

impl From<HexError> for TxDecodeError {
    fn from(e: HexError) -> Self {
        TxDecodeError::Hex(e)
    }
}

impl std::error::Error for TxDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TxDecodeError::Hex(e) => Some(e),
            TxDecodeError::Read(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------- decoding

impl Tx {
    /// Largest transaction that could ever appear in a block.
    pub const MAX_SIZE: usize = 4_000_000;

    /// The smallest an input can serialize to: 32 txid + 4 vout
    /// + 1 script length + 4 sequence.
    const MIN_INPUT_SIZE: NonZeroUsize = NonZeroUsize::MIN.saturating_add(40);
    /// 8 value + 1 script length.
    const MIN_OUTPUT_SIZE: NonZeroUsize = NonZeroUsize::MIN.saturating_add(8);

    /// Decode a transaction written in hex, accepting `0x` and whitespace.
    ///
    /// # Errors
    ///
    /// [`TxDecodeError`] for bad hex or bytes that are not a transaction.
    pub fn from_hex(s: &str) -> Result<Self, TxDecodeError> {
        let bytes = hex::decode(hex::normalize(s))?;
        Tx::decode(&bytes)
    }

    /// Decode a full consensus-serialized transaction, BIP144 aware.
    ///
    /// # Errors
    ///
    /// [`TxDecodeError`] if the bytes are empty, run out, declare an
    /// impossible count, carry a bad segwit flag, or leave trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, TxDecodeError> {
        if bytes.is_empty() {
            return Err(TxDecodeError::Empty);
        }
        let mut r = Reader::new(bytes);
        let version = r.u32()?;

        // BIP144: a 0x00 here would be an input count of zero, which is
        // invalid in the legacy encoding, so it unambiguously means segwit.
        let segwit = bytes.len() > 5 && bytes[4] == 0x00;
        if segwit {
            r.take(1)?; // marker
            // Core rejects any flag with bits beyond bit 0 set. Accepting
            // e.g. 0x03 and then re-encoding it as 0x01 would break the
            // byte-exactness `Tx::segwit` promises, and would make the
            // breakdown report a flag byte the input never contained.
            let flag = r.u8()?;
            if flag != 0x01 {
                return Err(TxDecodeError::BadSegwitFlag { flag });
            }
        }

        let n_in = r.varint()?;
        if n_in == 0 {
            return Err(TxDecodeError::NoInputs);
        }
        let n_in = r.checked_count(n_in, Self::MIN_INPUT_SIZE)?;
        let mut inputs = Vec::with_capacity(n_in);
        for _ in 0..n_in {
            let txid = Txid::from_wire(r.take_array()?);
            let vout = r.u32()?;
            let script_sig = Script::new(r.take_varint_slice()?.to_vec());
            let sequence = r.u32()?;
            inputs.push(Input {
                previous_output: OutPoint { txid, vout },
                script_sig,
                sequence,
                witness: Witness::default(),
            });
        }

        let n_out = r.varint()?;
        let n_out = r.checked_count(n_out, Self::MIN_OUTPUT_SIZE)?;
        let mut outputs = Vec::with_capacity(n_out);
        for _ in 0..n_out {
            let value = Amount::from_sat(r.u64()?);
            let script_pubkey = Script::new(r.take_varint_slice()?.to_vec());
            outputs.push(Output {
                value,
                script_pubkey,
            });
        }

        if segwit {
            // Exactly one witness per input, in input order. The group is not
            // length-prefixed — the count comes from the number of inputs.
            for input in &mut inputs {
                let n_items = r.varint()?;
                let n_items = r.checked_count(n_items, NonZeroUsize::MIN)?;
                let mut items = Vec::with_capacity(n_items);
                for _ in 0..n_items {
                    items.push(r.take_varint_slice()?.to_vec());
                }
                input.witness = Witness::new(items);
            }
        }

        let lock_time = r.u32()?;
        if !r.is_empty() {
            return Err(TxDecodeError::TrailingBytes {
                consumed: r.position(),
                total: bytes.len(),
            });
        }

        Ok(Tx {
            version,
            inputs,
            outputs,
            lock_time,
            segwit,
        })
    }

    /// True if any input actually carries witness data.
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|i| !i.witness.is_empty())
    }

    /// Consensus serialization, including witnesses if this is a segwit tx.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.encode_inner(self.segwit)
    }

    /// Serialization with marker, flag, and witnesses stripped — the form the
    /// txid is computed over.
    #[must_use]
    pub fn encode_legacy(&self) -> Vec<u8> {
        self.encode_inner(false)
    }

    fn encode_inner(&self, with_witness: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if with_witness {
            out.push(0x00);
            out.push(0x01);
        }
        write_varint(&mut out, self.inputs.len() as u64);
        for i in &self.inputs {
            out.extend_from_slice(&i.previous_output.txid.to_wire());
            out.extend_from_slice(&i.previous_output.vout.to_le_bytes());
            write_varint(&mut out, i.script_sig.len() as u64);
            out.extend_from_slice(i.script_sig.as_bytes());
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.outputs.len() as u64);
        for o in &self.outputs {
            out.extend_from_slice(&o.value.to_sat().to_le_bytes());
            write_varint(&mut out, o.script_pubkey.len() as u64);
            out.extend_from_slice(o.script_pubkey.as_bytes());
        }
        if with_witness {
            for i in &self.inputs {
                write_varint(&mut out, i.witness.len() as u64);
                for item in i.witness.items() {
                    write_varint(&mut out, item.len() as u64);
                    out.extend_from_slice(item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// Hash of the witness-stripped serialization. Equal to [`Tx::wtxid`] for
    /// a transaction with no witness data.
    #[must_use]
    pub fn txid(&self) -> Txid {
        Txid::from_wire(hash256(&self.encode_legacy()))
    }

    /// Hash of the full serialization, witnesses included.
    #[must_use]
    pub fn wtxid(&self) -> Txid {
        Txid::from_wire(hash256(&self.encode()))
    }

    /// Total satoshis paid out. Fees need the prevouts, which a raw
    /// transaction does not carry.
    ///
    /// Returns `u128` rather than an [`Amount`], and that is not an oversight:
    /// a *malformed* transaction can declare output values that sum past
    /// `u64`, which no `Amount` can hold. Summing in `u64` would panic in
    /// debug and silently wrap in release, and returning `Option<Amount>`
    /// would answer "no total" for a transaction that has one — the number the
    /// bytes actually add up to is the useful answer.
    ///
    /// Use [`Amount::checked_add`] where a consensus-valid total is what you
    /// want and an overflow should stop you.
    #[must_use]
    pub fn total_output_value(&self) -> u128 {
        self.outputs
            .iter()
            .map(|o| u128::from(o.value.to_sat()))
            .sum()
    }
}

/// A varint rendered as the bytes it serializes to, hex-encoded.
fn varint_hex(n: u64) -> String {
    let mut v = Vec::new();
    write_varint(&mut v, n);
    hex::encode(&v)
}

// --------------------------------------------------------------- breakdown

/// Every field of a transaction as the literal hex bytes it occupies on the
/// wire, in serialization order.
///
/// This is the view that answers "what do these bytes mean" — the same
/// decomposition as the vectors in `vectors/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxBreakdown {
    /// The txid in **displayed** (reversed) order — the form an explorer
    /// shows. Note that [`InputBreakdown::txid`] is the opposite: a wire-order
    /// field copied out of the serialization.
    pub txid: String,
    /// Segwit transactions only.
    pub wtxid: Option<String>,
    /// The four version bytes, little-endian as serialized.
    pub version: String,
    /// Segwit transactions only.
    pub marker: Option<String>,
    /// Segwit transactions only.
    pub flag: Option<String>,
    /// The input count varint, as the bytes it occupies.
    pub input_count: String,
    /// One entry per input, in serialization order.
    pub inputs: Vec<InputBreakdown>,
    /// The output count varint, as the bytes it occupies.
    pub output_count: String,
    /// One entry per output, in serialization order.
    pub outputs: Vec<OutputBreakdown>,
    /// Segwit transactions only; one entry per input, in input order.
    pub witness: Option<Vec<WitnessBreakdown>>,
    /// The four locktime bytes, little-endian as serialized.
    pub locktime: String,
    /// The whole transaction, re-encoded — byte-identical to what came in.
    pub raw_tx: String,
}

/// One input's wire fields, each as the hex bytes it occupies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputBreakdown {
    /// The previous txid in **wire** order, i.e. the bytes as serialized.
    /// This is the reverse of [`TxBreakdown::txid`], which is the displayed
    /// form — the two fields share a name because the wire and the explorer
    /// do.
    pub txid: String,
    /// The output index, little-endian.
    pub vout: String,
    /// The scriptSig length varint.
    pub script_sig_size: String,
    /// The scriptSig's bytes, hex — not a decoded script.
    pub script_sig: String,
    /// The sequence number, little-endian.
    pub sequence: String,
}

/// One output's wire fields, each as the hex bytes it occupies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputBreakdown {
    /// The value in satoshis, little-endian over eight bytes.
    pub amount: String,
    /// The scriptPubKey length varint.
    pub script_pubkey_size: String,
    /// The scriptPubKey's bytes, hex — not a decoded script.
    pub script_pubkey: String,
}

/// One input's witness, as wire fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessBreakdown {
    /// The stack-item count varint.
    pub stack_items: String,
    /// The items, bottom of the stack first.
    pub items: Vec<WitnessItemBreakdown>,
}

/// One witness stack item, as wire fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessItemBreakdown {
    /// The item's length varint.
    pub size: String,
    /// The item's bytes, hex.
    pub item: String,
}

impl Tx {
    /// Split into labelled wire fields.
    #[must_use]
    pub fn breakdown(&self) -> TxBreakdown {
        TxBreakdown {
            txid: self.txid().to_string(),
            wtxid: self.segwit.then(|| self.wtxid().to_string()),
            version: hex::encode(&self.version.to_le_bytes()),
            marker: self.segwit.then(|| "00".to_string()),
            flag: self.segwit.then(|| "01".to_string()),
            input_count: varint_hex(self.inputs.len() as u64),
            inputs: self
                .inputs
                .iter()
                .map(|i| InputBreakdown {
                    txid: hex::encode(&i.previous_output.txid.to_wire()),
                    vout: hex::encode(&i.previous_output.vout.to_le_bytes()),
                    script_sig_size: varint_hex(i.script_sig.len() as u64),
                    script_sig: hex::encode(i.script_sig.as_bytes()),
                    sequence: hex::encode(&i.sequence.to_le_bytes()),
                })
                .collect(),
            output_count: varint_hex(self.outputs.len() as u64),
            outputs: self
                .outputs
                .iter()
                .map(|o| OutputBreakdown {
                    amount: hex::encode(&o.value.to_sat().to_le_bytes()),
                    script_pubkey_size: varint_hex(o.script_pubkey.len() as u64),
                    script_pubkey: hex::encode(o.script_pubkey.as_bytes()),
                })
                .collect(),
            witness: self.segwit.then(|| {
                self.inputs
                    .iter()
                    .map(|i| WitnessBreakdown {
                        stack_items: varint_hex(i.witness.len() as u64),
                        items: i
                            .witness
                            .items()
                            .iter()
                            .map(|it| WitnessItemBreakdown {
                                size: varint_hex(it.len() as u64),
                                item: hex::encode(it),
                            })
                            .collect(),
                    })
                    .collect()
            }),
            locktime: hex::encode(&self.lock_time.to_le_bytes()),
            raw_tx: hex::encode(&self.encode()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real mainnet P2WPKH spend (txid c434944f…, height 712000).
    const SEGWIT: &str = concat!(
        "020000000001018500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b70100000000",
        "ffffffff02a9d5000000000000160014275b468073affad6c1b2833d026416ec07392b7fcd3f080000000000",
        "1600144586309f5c6f8f0f362f38adfa51906c80ee2ba102483045022100dd86debb4e538b6ca1e866a1070d",
        "5537308636fffb98337a0a8e67833be89333022040494ea241027649a94756f4102cfdc2c25302a060f0c5d7",
        "d787dcc706df526b012102c9f4cfd5720c561f9d5e84cbcb58dc5ac4f22ac1e1adef91d0eebf643fecca5d00",
        "000000"
    );

    #[test]
    fn decodes_and_reencodes_a_segwit_tx() {
        let tx = Tx::from_hex(SEGWIT).unwrap();
        assert!(tx.segwit);
        assert_eq!(tx.version, 2);
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 2);
        assert_eq!(tx.inputs[0].witness.len(), 2);
        assert_eq!(tx.lock_time, 0);
        assert_eq!(hex::encode(&tx.encode()), SEGWIT);
    }

    #[test]
    fn txid_and_wtxid_differ_for_a_segwit_tx() {
        let tx = Tx::from_hex(SEGWIT).unwrap();
        assert_eq!(
            tx.txid().to_string(),
            "c434944f5aef48127e15d0198e2b1cd3592e94b2f0b3ae0f7b4ead83d504a250"
        );
        assert_eq!(
            tx.wtxid().to_string(),
            "4e3ab70959f6d3e8774228988b7af8dd49a316f35f543683510e5758ebdb8a17"
        );
        assert_ne!(tx.txid(), tx.wtxid());
    }

    #[test]
    fn txid_display_is_the_reverse_of_wire_order() {
        let tx = Tx::from_hex(SEGWIT).unwrap();
        assert_eq!(
            hex::encode(&tx.inputs[0].previous_output.txid.to_wire()),
            "8500bb8ff66dea2b8d7f054d06b0363c3d0b25dcf6f0c62967f98f953ae9a2b7"
        );
        assert_eq!(
            tx.inputs[0].previous_output.txid.to_string(),
            "b7a2e93a958ff96729c6f0f6dc250b3d3c36b0064d057f8d2bea6df68fbb0085"
        );
    }

    /// The trap `FromStr` exists to close: the displayed form is reversed, so
    /// parsing it must undo that, and `to_string().parse()` must be identity.
    #[test]
    fn txid_parses_back_from_its_displayed_form() {
        let tx = Tx::from_hex(SEGWIT).unwrap();
        let txid = tx.txid();
        assert_eq!(txid.to_string().parse::<Txid>().unwrap(), txid);
        // Parsing the displayed form yields wire order, not the bytes as read.
        let shown = "c434944f5aef48127e15d0198e2b1cd3592e94b2f0b3ae0f7b4ead83d504a250";
        assert_eq!(
            hex::encode(&shown.parse::<Txid>().unwrap().to_wire()),
            "50a204d583ad4e7b0faeb3f0b2942e59d31c2b8e19d0157e1248ef5a4f9434c4"
        );
        // Whitespace and `0x`, as everywhere else.
        assert_eq!(format!("  0x{shown} \n").parse::<Txid>().unwrap(), txid);
    }

    /// The one place in the crate where the same bytes print two ways. Stated
    /// here so the divergence is a documented property rather than something
    /// a caller meets in production.
    #[test]
    fn a_txid_and_its_bare_hash_print_opposite_ways() {
        let txid = Tx::from_hex(SEGWIT).unwrap().txid();
        let hash = txid.to_hash();

        assert_ne!(txid.to_string(), hash.to_string());
        assert_eq!(txid.to_string(), hash.to_hex_reversed());
        assert_eq!(hash.to_string(), hex::encode(&txid.to_wire()));
        // …and the trip down and back is lossless.
        assert_eq!(Txid::from_hash(hash), txid);
    }

    #[test]
    fn txid_rejects_anything_that_is_not_32_bytes() {
        assert_eq!(
            "aabb".parse::<Txid>(),
            Err(HashParseError::WrongLength {
                got: 2,
                expected: 32
            })
        );
        assert_eq!(
            "".parse::<Txid>(),
            Err(HashParseError::WrongLength {
                got: 0,
                expected: 32
            })
        );
        // 33 bytes — one too many, the boundary a length check gets wrong.
        assert_eq!(
            "00".repeat(33).parse::<Txid>(),
            Err(HashParseError::WrongLength {
                got: 33,
                expected: 32
            })
        );
        assert_eq!(
            "zz".repeat(32).parse::<Txid>(),
            Err(HashParseError::Hex(HexError::InvalidChar { offset: 0 }))
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert_eq!(Tx::decode(&[]), Err(TxDecodeError::Empty));
        assert!(matches!(
            Tx::decode(&[1, 0, 0, 0]),
            Err(TxDecodeError::Read(ReadError::UnexpectedEnd { .. }))
        ));
        // 0x00 after the version means segwit, so a zero flag is the error.
        assert_eq!(
            Tx::decode(&[1, 0, 0, 0, 0, 0]),
            Err(TxDecodeError::BadSegwitFlag { flag: 0 })
        );
        let mut extra = hex::decode(SEGWIT).unwrap();
        extra.push(0xff);
        assert!(matches!(
            Tx::decode(&extra),
            Err(TxDecodeError::TrailingBytes { .. })
        ));
    }

    /// The reason `Amount` does not enforce the 21-million cap. A transaction
    /// declaring more than will ever exist is invalid, but it is still bytes
    /// somebody handed a decoder, and refusing to represent it would make the
    /// tool useless exactly where it is most wanted.
    #[test]
    fn an_output_value_above_max_money_decodes_and_survives_re_encoding() {
        let mut tx = Tx::from_hex(SEGWIT).unwrap();
        tx.outputs[0].value = Amount::from_sat(u64::MAX);
        let bytes = tx.encode();

        let again = Tx::decode(&bytes).expect("an absurd value is still decodable");
        assert_eq!(again.outputs[0].value, Amount::from_sat(u64::MAX));
        assert!(!again.outputs[0].value.is_money_range());
        assert_eq!(again.encode(), bytes, "re-encoding changed the bytes");
        assert_eq!(again.breakdown().outputs[0].amount, "ffffffffffffffff");
        // The total is why `total_output_value` is `u128`: this sum is past
        // what any `Amount` could hold.
        assert!(again.total_output_value() > u128::from(u64::MAX));
    }

    #[test]
    fn implausible_counts_are_rejected_before_allocating() {
        // Version, then a varint claiming u64::MAX inputs.
        let bytes = [
            1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        assert!(matches!(
            Tx::decode(&bytes),
            Err(TxDecodeError::Read(ReadError::ImplausibleCount { .. }))
        ));
    }

    #[test]
    fn breakdown_matches_the_wire_fields() {
        let b = Tx::from_hex(SEGWIT).unwrap().breakdown();
        assert_eq!(b.version, "02000000");
        assert_eq!(b.marker.as_deref(), Some("00"));
        assert_eq!(b.flag.as_deref(), Some("01"));
        assert_eq!(b.input_count, "01");
        assert_eq!(b.output_count, "02");
        assert_eq!(b.locktime, "00000000");
        assert_eq!(b.raw_tx, SEGWIT);
        let w = b.witness.as_ref().unwrap();
        assert_eq!(w.len(), 1, "one witness entry per input");
        assert_eq!(w[0].stack_items, "02");
        assert_eq!(w[0].items[0].size, "48");
        assert_eq!(w[0].items[1].size, "21");
    }
}
