//! Bitcoin scripts: the bytes, the opcodes they decode to, and what shape
//! the whole thing is.

pub mod instruction;
pub mod opcodes;

pub use instruction::{DecodeError, Instruction, Instructions, Step};
pub use opcodes::{Category, Opcode, alias, all};

use std::fmt;

use crate::hex::{self, HexError};

/// The standard output script templates.
///
/// This classifies a scriptPubKey by its exact byte pattern, the same way
/// Bitcoin Core's `Solver` does — it is a shape test, not an execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScriptKind {
    /// `<pubkey> OP_CHECKSIG`
    P2PK,
    /// `OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG`
    P2PKH,
    /// `OP_m <pubkeys...> OP_n OP_CHECKMULTISIG`
    P2MS,
    /// `OP_HASH160 <20 bytes> OP_EQUAL`
    P2SH,
    /// `OP_0 <20 bytes>`
    P2WPKH,
    /// `OP_0 <32 bytes>`
    P2WSH,
    /// `OP_1 <32 bytes>`
    P2TR,
    /// `OP_RETURN ...`
    OpReturn,
    /// A witness program of a version this build does not know about.
    /// Anyone-can-spend today; a future soft fork may give it meaning.
    WitnessUnknown { version: u8 },
    /// Valid bytes, but no standard template matches.
    NonStandard,
}

impl fmt::Display for ScriptKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptKind::P2PK => f.write_str("P2PK"),
            ScriptKind::P2PKH => f.write_str("P2PKH"),
            ScriptKind::P2MS => f.write_str("P2MS"),
            ScriptKind::P2SH => f.write_str("P2SH"),
            ScriptKind::P2WPKH => f.write_str("P2WPKH"),
            ScriptKind::P2WSH => f.write_str("P2WSH"),
            ScriptKind::P2TR => f.write_str("P2TR"),
            ScriptKind::OpReturn => f.write_str("OP_RETURN"),
            ScriptKind::WitnessUnknown { version } => write!(f, "WITNESS_V{version}_UNKNOWN"),
            ScriptKind::NonStandard => f.write_str("NONSTANDARD"),
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ScriptKind {
    /// Delegates to `Display`, so the JSON spelling and the printed spelling
    /// are one definition rather than two that can drift apart.
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

/// The template-specific parts of a standard script, pulled out by name.
///
/// Serialized untagged: the caller already knows the [`ScriptKind`], so the
/// object carries only the fields, and a non-standard script yields `null`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(untagged, rename_all_fields = "camelCase"))]
#[non_exhaustive]
pub enum ScriptFields {
    P2Pk {
        pubkey: String,
    },
    P2Pkh {
        pubkey_hash: String,
    },
    P2Sh {
        script_hash: String,
    },
    P2Ms {
        required: u32,
        total: u32,
        pubkeys: Vec<String>,
    },
    Witness {
        witness_version: u8,
        witness_program: String,
    },
    OpReturn {
        /// Each data push after `OP_RETURN`, in order.
        data: Vec<String>,
    },
    NonStandard,
}

/// A Bitcoin script — a scriptPubKey, scriptSig, or witness script.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script(Vec<u8>);

/// One decoded instruction, owned so it can outlive the script it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedInstruction {
    pub offset: usize,
    pub opcode: Opcode,
    /// Bytes pushed by this instruction, if it is a push.
    pub data: Option<Vec<u8>>,
}

/// Everything the tools know about one script.
///
/// Owned and HTTP-free, so a transaction-level decoder can hold one of these
/// per input and output, and a future persistence layer can store one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptAnalysis {
    pub hex: String,
    pub size_bytes: usize,
    pub kind: ScriptKind,
    pub fields: ScriptFields,
    pub asm: String,
    pub has_disabled_opcode: bool,
    pub instructions: Vec<AnalyzedInstruction>,
    /// Set when the script is malformed; `instructions` then holds everything
    /// that decoded before the problem.
    pub error: Option<DecodeError>,
}

impl Script {
    /// Consensus limit on a single script, in bytes (`MAX_SCRIPT_SIZE`).
    /// Anything longer cannot appear on-chain.
    pub const MAX_SIZE: usize = 10_000;

    pub fn new(bytes: Vec<u8>) -> Self {
        Script(bytes)
    }

    /// Decode from hex. Leading and trailing whitespace and one `0x` prefix
    /// are accepted, matching [`Tx::from_hex`](crate::transactions::tx::Tx::from_hex)
    /// — the two entry points must not disagree about what hex is.
    pub fn from_hex(s: &str) -> Result<Self, HexError> {
        hex::decode(hex::normalize(s)).map(Script)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Decode into instructions. See [`Instructions`] for the error behaviour.
    pub fn instructions(&self) -> Instructions<'_> {
        Instructions::new(&self.0)
    }

    /// Decode fully, keeping whatever decoded before any error.
    pub fn disassemble(&self) -> (Vec<Step<'_>>, Option<DecodeError>) {
        let mut steps = Vec::new();
        for item in self.instructions() {
            match item {
                Ok(step) => steps.push(step),
                Err(e) => return (steps, Some(e)),
            }
        }
        (steps, None)
    }

    /// Human-readable disassembly, e.g.
    /// `OP_DUP OP_HASH160 OP_PUSHBYTES_20 89ab… OP_EQUALVERIFY OP_CHECKSIG`.
    pub fn to_asm(&self) -> String {
        let (steps, err) = self.disassemble();
        let mut parts: Vec<String> = steps.iter().map(|s| s.instruction.to_string()).collect();
        if let Some(e) = err {
            parts.push(format!("[{e}]"));
        }
        parts.join(" ")
    }

    /// True if the script would be rejected outright for containing an opcode
    /// that was removed from the language.
    ///
    /// This walks instructions rather than raw bytes: a pushed 20-byte hash
    /// will routinely contain a byte like `0x95` (`OP_MUL`) without that byte
    /// ever being an opcode.
    pub fn has_disabled_opcode(&self) -> bool {
        self.instructions().any(|step| {
            matches!(step, Ok(Step { instruction: Instruction::Op(op), .. })
                if op.category() == Category::Disabled)
        })
    }

    /// Classify as an output script template.
    pub fn kind(&self) -> ScriptKind {
        let b = &self.0;

        // Fixed-shape templates first — these are exact byte patterns.
        if b.len() == 25
            && b[0] == all::OP_DUP.to_u8()
            && b[1] == all::OP_HASH160.to_u8()
            && b[2] == 0x14
            && b[23] == all::OP_EQUALVERIFY.to_u8()
            && b[24] == all::OP_CHECKSIG.to_u8()
        {
            return ScriptKind::P2PKH;
        }
        if b.len() == 23
            && b[0] == all::OP_HASH160.to_u8()
            && b[1] == 0x14
            && b[22] == all::OP_EQUAL.to_u8()
        {
            return ScriptKind::P2SH;
        }
        if (b.len() == 35 && b[0] == 0x21 || b.len() == 67 && b[0] == 0x41)
            && b.last() == Some(&all::OP_CHECKSIG.to_u8())
        {
            return ScriptKind::P2PK;
        }
        if b.first() == Some(&all::OP_RETURN.to_u8()) {
            return ScriptKind::OpReturn;
        }
        if let Some((_, kind)) = self.witness_program() {
            return kind;
        }
        if self.is_bare_multisig() {
            return ScriptKind::P2MS;
        }
        ScriptKind::NonStandard
    }

    /// Decode and classify in one pass, into an owned, transport-free value.
    pub fn analyze(&self) -> ScriptAnalysis {
        let (steps, error) = self.disassemble();
        ScriptAnalysis {
            hex: self.to_string(),
            size_bytes: self.len(),
            kind: self.kind(),
            fields: self.fields(),
            asm: self.to_asm(),
            has_disabled_opcode: self.has_disabled_opcode(),
            instructions: steps
                .iter()
                .map(|s| AnalyzedInstruction {
                    offset: s.offset,
                    opcode: s.instruction.opcode(),
                    data: s.instruction.data().map(<[u8]>::to_vec),
                })
                .collect(),
            error,
        }
    }

    /// Pull out the parts that the script's template defines.
    ///
    /// Every index used here is already guaranteed by [`Script::kind`], which
    /// checked the exact length and byte pattern before returning.
    pub fn fields(&self) -> ScriptFields {
        let b = &self.0;
        match self.kind() {
            ScriptKind::P2PK => ScriptFields::P2Pk {
                pubkey: hex::encode(&b[1..b.len() - 1]),
            },
            ScriptKind::P2PKH => ScriptFields::P2Pkh {
                pubkey_hash: hex::encode(&b[3..23]),
            },
            ScriptKind::P2SH => ScriptFields::P2Sh {
                script_hash: hex::encode(&b[2..22]),
            },
            ScriptKind::P2WPKH
            | ScriptKind::P2WSH
            | ScriptKind::P2TR
            | ScriptKind::WitnessUnknown { .. } => {
                // `kind()` returned a witness kind, so this cannot be None —
                // but taking the version from the same function that decided
                // the kind is what keeps the two from ever disagreeing.
                let version = self.witness_program().map_or(0, |(v, _)| v);
                ScriptFields::Witness {
                    witness_version: version,
                    witness_program: hex::encode(&b[2..]),
                }
            }
            ScriptKind::P2MS => {
                let (steps, _) = self.disassemble();
                let num = |i: usize| u32::from(steps[i].instruction.opcode().to_u8() - 0x50);
                ScriptFields::P2Ms {
                    required: num(0),
                    total: num(steps.len() - 2),
                    pubkeys: steps[1..steps.len() - 2]
                        .iter()
                        .filter_map(|s| s.instruction.data().map(hex::encode))
                        .collect(),
                }
            }
            ScriptKind::OpReturn => {
                let (steps, _) = self.disassemble();
                ScriptFields::OpReturn {
                    // Skip OP_RETURN itself; keep whatever pushes decoded.
                    data: steps
                        .iter()
                        .skip(1)
                        .filter_map(|s| s.instruction.data().map(hex::encode))
                        .collect(),
                }
            }
            ScriptKind::NonStandard => ScriptFields::NonStandard,
        }
    }

    /// BIP141: a version byte (`OP_0`, or `OP_1`..`OP_16`) followed by a
    /// single direct push of 2..=40 bytes, and nothing else.
    ///
    /// Returns the version alongside the kind. `fields()` needs the version
    /// too, and having it recompute `b[0]` was the same rule written in two
    /// places that had to agree — `OP_0` decoding to 0 rather than to `0x00 -
    /// 0x50` is exactly the sort of thing one copy gets wrong.
    fn witness_program(&self) -> Option<(u8, ScriptKind)> {
        let b = &self.0;
        if b.len() < 4 || b.len() > 42 {
            return None;
        }
        let version = match b[0] {
            0x00 => 0,
            v @ 0x51..=0x60 => v - 0x50,
            _ => return None,
        };
        let push = b[1] as usize;
        if !(2..=40).contains(&push) || b.len() != push + 2 {
            return None;
        }
        let kind = match (version, push) {
            (0, 20) => ScriptKind::P2WPKH,
            (0, 32) => ScriptKind::P2WSH,
            (1, 32) => ScriptKind::P2TR,
            // A v0 program of any other length is invalid, not "unknown" —
            // but it is still shaped like a witness program, so report it.
            (v, _) => ScriptKind::WitnessUnknown { version: v },
        };
        Some((version, kind))
    }

    /// `OP_m <pubkey>{n} OP_n OP_CHECKMULTISIG`, for any `1 <= m <= n`.
    ///
    /// This is a shape test, matching Core's `Solver`, which accepts up to
    /// 20 keys. Relay policy separately caps *bare* multisig at n <= 3 —
    /// that is `IsStandard`, a different question from "what is this script",
    /// and answering it here would misreport a real on-chain 4-of-5 as
    /// non-standard bytes.
    fn is_bare_multisig(&self) -> bool {
        let (steps, err) = self.disassemble();
        if err.is_some() || steps.len() < 4 {
            return false;
        }
        let opnum = |op: Opcode| match op.to_u8() {
            v @ 0x51..=0x60 => Some(u32::from(v - 0x50)),
            _ => None,
        };
        let Some(m) = opnum(steps[0].instruction.opcode()) else {
            return false;
        };
        let Some(n) = opnum(steps[steps.len() - 2].instruction.opcode()) else {
            return false;
        };
        if steps[steps.len() - 1].instruction.opcode() != all::OP_CHECKMULTISIG {
            return false;
        }
        let keys = &steps[1..steps.len() - 2];
        m >= 1
            && m <= n
            && n as usize == keys.len()
            && keys
                .iter()
                .all(|s| matches!(s.instruction.data().map(<[u8]>::len), Some(33) | Some(65)))
    }
}

impl fmt::Display for Script {
    /// Hex, matching how scripts appear in raw transactions.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex::write(f, &self.0)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Script {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl From<Vec<u8>> for Script {
    fn from(v: Vec<u8>) -> Self {
        Script(v)
    }
}

#[cfg(test)]
mod tests {
    use super::instruction::Instruction;
    use super::*;

    fn s(hex: &str) -> Script {
        Script::from_hex(hex).expect("valid hex")
    }

    #[test]
    fn classifies_standard_outputs() {
        // Taken from the vectors in vectors/.
        assert_eq!(
            s("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac").kind(),
            ScriptKind::P2PKH
        );
        assert_eq!(
            s("a914d6763da611b0566f4436b86ba159de02a8f9190287").kind(),
            ScriptKind::P2SH
        );
        assert_eq!(
            s("0014275b468073affad6c1b2833d026416ec07392b7f").kind(),
            ScriptKind::P2WPKH
        );
        assert_eq!(
            s("0020d48fc06cefcd7e5ae5b3a933d4ebdb69b7fa7b539419d6c5a55344791240836a").kind(),
            ScriptKind::P2WSH
        );
        assert_eq!(
            s("512050a50a97836860d6a71463ac8e244751f2db62dd02348470f27158c927a439cc").kind(),
            ScriptKind::P2TR
        );
        assert_eq!(
            s("6a5d2a0108020303c00204f4e1fcf9a386e2e75105e0ef0708c0de810a0a010cc0a2330ecffca6037f8190e912").kind(),
            ScriptKind::OpReturn
        );
    }

    #[test]
    fn classifies_bare_multisig() {
        // 1-of-1, from witness script c6d7d885… in the segwit vectors.
        let ms = s("5121034d31a1a1622a3c3902370d0f47b531e2b16b1f90d13e86a707dfb4114603f19451ae");
        assert_eq!(ms.kind(), ScriptKind::P2MS);
    }

    #[test]
    fn disassembles_p2pkh() {
        let script = s("76a91465ed366110a6fe3132cc1f63d73d3bb5a658797f88ac");
        assert_eq!(
            script.to_asm(),
            "OP_DUP OP_HASH160 OP_PUSHBYTES_20 65ed366110a6fe3132cc1f63d73d3bb5a658797f \
             OP_EQUALVERIFY OP_CHECKSIG"
        );
        let (steps, err) = script.disassemble();
        assert!(err.is_none());
        assert_eq!(steps.len(), 5);
        assert_eq!(steps[2].offset, 2);
        assert_eq!(steps[2].instruction.data().unwrap().len(), 20);
    }

    #[test]
    fn empty_script_decodes_to_nothing() {
        let script = Script::new(vec![]);
        assert_eq!(script.instructions().count(), 0);
        assert_eq!(script.to_asm(), "");
        assert_eq!(script.kind(), ScriptKind::NonStandard);
    }

    #[test]
    fn op_0_is_an_opcode_not_a_push() {
        let script = s("00");
        let (steps, err) = script.disassemble();
        assert!(err.is_none());
        assert_eq!(steps[0].instruction, Instruction::Op(all::OP_0));
        assert!(steps[0].instruction.data().is_none());
    }

    #[test]
    fn pushdata1_and_2() {
        // OP_PUSHDATA1 0x02 aabb
        let one = s("4c02aabb");
        let (steps, err) = one.disassemble();
        assert!(err.is_none());
        assert_eq!(steps[0].instruction.data(), Some(&[0xaa, 0xbb][..]));
        // OP_PUSHDATA2 0x0002 (LE) then 2 bytes
        let two = s("4d0200aabb");
        let (steps, err) = two.disassemble();
        assert!(err.is_none());
        assert_eq!(steps[0].instruction.data(), Some(&[0xaa, 0xbb][..]));
    }

    #[test]
    fn truncated_push_keeps_earlier_instructions() {
        // OP_DUP, then a push claiming 5 bytes with only 2 present.
        let script = s("7605aabb");
        let (steps, err) = script.disassemble();
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0].instruction, Instruction::Op(all::OP_DUP));
        assert_eq!(
            err,
            Some(DecodeError::Truncated {
                offset: 1,
                declared: 5,
                available: 2
            })
        );
    }

    #[test]
    fn truncated_length_prefix() {
        let script = s("4d00");
        let (steps, err) = script.disassemble();
        assert!(steps.is_empty());
        assert!(matches!(
            err,
            Some(DecodeError::TruncatedLengthPrefix { offset: 0, .. })
        ));
    }

    #[test]
    fn iterator_stops_after_error() {
        let script = s("7605aabb");
        let mut it = script.instructions();
        assert!(it.next().unwrap().is_ok());
        assert!(it.next().unwrap().is_err());
        assert!(it.next().is_none());
    }

    #[test]
    fn detects_disabled_opcodes() {
        assert!(s("7e").has_disabled_opcode()); // OP_CAT
        assert!(!s("76a914000000000000000000000000000000000000000088ac").has_disabled_opcode());
    }

    #[test]
    fn disabled_opcode_bytes_inside_pushed_data_dont_count() {
        // A real mainnet P2PKH whose 20-byte hash contains 0x95 (OP_MUL).
        let script = s("76a914662b82ed826de20b0f0dbdcc4699ba95dd89666e88ac");
        assert_eq!(script.kind(), ScriptKind::P2PKH);
        assert!(!script.has_disabled_opcode());
        // …but the same byte as an actual opcode does count.
        assert!(s("7695").has_disabled_opcode());
    }

    #[test]
    fn hex_errors() {
        assert_eq!(Script::from_hex("abc"), Err(HexError::OddLength { len: 3 }));
        assert_eq!(
            Script::from_hex("zz"),
            Err(HexError::InvalidChar { offset: 0 })
        );
    }
}
