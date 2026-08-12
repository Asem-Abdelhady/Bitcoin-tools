//! Decoding a script's bytes into opcodes and pushed data.

use std::fmt;

use super::opcodes::{Category, Opcode};
use crate::bytes::Reader;

/// One decoded step of a script.
///
/// `OP_0` is *not* a `PushBytes` even though it pushes an empty value — it is
/// a one-byte opcode with no operand, so it decodes as `Op(OP_0)`. Only
/// 0x01..=0x4b and `OP_PUSHDATA1/2/4` carry data out of the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction<'a> {
    /// A data push, with the opcode that introduced it.
    Push {
        /// The push opcode — a direct `0x01..=0x4b`, or an `OP_PUSHDATA*`.
        opcode: Opcode,
        /// The bytes pushed, borrowed from the script.
        data: &'a [u8],
    },
    /// Any opcode that takes no operand from the byte stream.
    Op(Opcode),
}

impl Instruction<'_> {
    /// The opcode, whether or not it carries data.
    #[must_use]
    pub fn opcode(&self) -> Opcode {
        match self {
            Instruction::Push { opcode, .. } => *opcode,
            Instruction::Op(op) => *op,
        }
    }

    /// The pushed bytes, or `None` for an opcode that takes no operand.
    #[must_use]
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Instruction::Push { data, .. } => Some(data),
            Instruction::Op(_) => None,
        }
    }

    /// The opcode's broad grouping.
    #[must_use]
    pub fn category(&self) -> Category {
        self.opcode().category()
    }

    /// Append this instruction's wire bytes, re-creating the length prefix
    /// that the decoder consumed.
    ///
    /// Fallible because `Instruction::Push` is publicly constructible: nothing
    /// stops a caller pairing `OP_PUSHDATA1` with 300 bytes, and truncating
    /// that length into one byte would emit a script that re-decodes into
    /// something entirely different, with no error to show for it.
    ///
    /// # Errors
    ///
    /// [`EncodeError`] when the payload does not fit what the opcode can
    /// express. Nothing is appended to `out` when that happens.
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Instruction::Op(op) => out.push(op.to_u8()),
            Instruction::Push { opcode, data } => {
                let len = data.len();
                if let Some(expected) = opcode.push_len() {
                    // A direct push encodes its length *in* the opcode, so the
                    // payload must match exactly — there is no prefix to adjust.
                    if len != expected {
                        return Err(EncodeError::PushLenMismatch {
                            opcode: *opcode,
                            len,
                            expected,
                        });
                    }
                } else {
                    let max = opcode.push_max_len().ok_or(EncodeError::NotAPush {
                        opcode: *opcode,
                        len,
                    })?;
                    if len > max {
                        return Err(EncodeError::PushTooLong {
                            opcode: *opcode,
                            len,
                            max,
                        });
                    }
                }
                out.push(opcode.to_u8());
                match opcode.pushdata_width() {
                    Some(1) => out.push(len as u8),
                    Some(2) => out.extend_from_slice(&(len as u16).to_le_bytes()),
                    Some(4) => out.extend_from_slice(&(len as u32).to_le_bytes()),
                    // 0x01..=0x4b: the opcode *is* the length, and `push_len`
                    // already required `len` to equal it.
                    _ => {}
                }
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }
}

impl fmt::Display for Instruction<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // Name the push opcode, then its payload. Spelling out the opcode
            // keeps the rendering lossless: `OP_PUSHBYTES_20 aabb…` and
            // `OP_PUSHDATA1 aabb…` push identical data via different bytes.
            Instruction::Push { opcode, data } => {
                write!(f, "{opcode}")?;
                if !data.is_empty() {
                    f.write_str(" ")?;
                    crate::hex::write(f, data)?;
                }
                Ok(())
            }
            Instruction::Op(op) => write!(f, "{op}"),
        }
    }
}

/// Why a script stopped decoding.
///
/// Both variants mean the script is malformed, which is a thing that really
/// happens on-chain — a decoder has to report it rather than panic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "error", rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum DecodeError {
    /// A push wanted more bytes than the script had left.
    Truncated {
        /// Where the push started.
        offset: usize,
        /// How many bytes it declared.
        declared: usize,
        /// How many were left.
        available: usize,
    },
    /// An `OP_PUSHDATA1/2/4` length prefix itself ran off the end.
    TruncatedLengthPrefix {
        /// Where the instruction started.
        offset: usize,
        /// Which `OP_PUSHDATA*` ran out mid-prefix.
        opcode: Opcode,
    },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated {
                offset,
                declared,
                available,
            } => write!(
                f,
                "push at offset {offset} declared {declared} bytes but only {available} remain"
            ),
            DecodeError::TruncatedLengthPrefix { offset, opcode } => {
                write!(
                    f,
                    "{opcode} at offset {offset} has a truncated length prefix"
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why an instruction could not be turned back into bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// The payload is longer than this push opcode's prefix can express.
    PushTooLong {
        /// The push opcode.
        opcode: Opcode,
        /// The payload length offered.
        len: usize,
        /// The largest its prefix can express.
        max: usize,
    },
    /// A direct push (0x01..=0x4b) whose payload is not exactly the length
    /// its opcode names. Too short corrupts the stream just as badly as too
    /// long: the bytes that follow get eaten as payload.
    PushLenMismatch {
        /// The direct push opcode.
        opcode: Opcode,
        /// The payload length offered.
        len: usize,
        /// The length the opcode names, which is the only one it can carry.
        expected: usize,
    },
    /// A `Push` was built around an opcode that does not push data at all.
    NotAPush {
        /// The opcode, which pushes nothing.
        opcode: Opcode,
        /// How many bytes were paired with it anyway.
        len: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::PushTooLong { opcode, len, max } => {
                write!(f, "{opcode} can express at most {max} bytes, got {len}")
            }
            EncodeError::PushLenMismatch {
                opcode,
                len,
                expected,
            } => write!(f, "{opcode} must carry exactly {expected} bytes, got {len}"),
            EncodeError::NotAPush { opcode, len } => {
                write!(f, "{opcode} does not push data, but carries {len} bytes")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// A decoded instruction together with its byte offset in the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<'a> {
    /// Byte offset of this instruction within the script.
    pub offset: usize,
    /// What decoded at [`Step::offset`].
    pub instruction: Instruction<'a>,
}

/// Iterator over a script's instructions.
///
/// The `Result` is per item rather than around the whole iterator, so a
/// truncated push at the end does not throw away the instructions that
/// decoded cleanly before it. Once an error is yielded the iterator stops.
#[derive(Debug, Clone)]
pub struct Instructions<'a> {
    reader: Reader<'a>,
    done: bool,
}

impl<'a> Instructions<'a> {
    pub(super) fn new(script: &'a [u8]) -> Self {
        Instructions {
            reader: Reader::new(script),
            done: false,
        }
    }

    /// Read `n` bytes, describing any shortfall in terms of the *instruction*
    /// that wanted them rather than the byte offset the read started at.
    fn take(&mut self, n: usize, push_start: usize) -> Result<&'a [u8], DecodeError> {
        self.reader.take(n).map_err(|_| DecodeError::Truncated {
            offset: push_start,
            declared: n,
            available: self.reader.remaining(),
        })
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Step<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.reader.is_empty() {
            return None;
        }
        let start = self.reader.position();
        // Guarded by `is_empty` above; `ok()?` rather than `unwrap` keeps the
        // no-panic rule without pretending a read failure means "finished".
        debug_assert!(!self.reader.is_empty());
        let opcode = Opcode::from_u8(self.reader.u8().ok()?);

        // How many data bytes follow, if any.
        let len = if let Some(n) = opcode.push_len() {
            Some(n)
        } else if let Some(width) = opcode.pushdata_width() {
            match self.take(width, start) {
                Ok(bytes) => {
                    let mut buf = [0u8; 4];
                    buf[..width].copy_from_slice(bytes);
                    Some(u32::from_le_bytes(buf) as usize)
                }
                Err(_) => {
                    self.done = true;
                    return Some(Err(DecodeError::TruncatedLengthPrefix {
                        offset: start,
                        opcode,
                    }));
                }
            }
        } else {
            None
        };

        match len {
            Some(n) => match self.take(n, start) {
                Ok(data) => Some(Ok(Step {
                    offset: start,
                    instruction: Instruction::Push { opcode, data },
                })),
                Err(e) => {
                    self.done = true;
                    Some(Err(e))
                }
            },
            None => Some(Ok(Step {
                offset: start,
                instruction: Instruction::Op(opcode),
            })),
        }
    }
}

impl std::iter::FusedIterator for Instructions<'_> {}

#[cfg(test)]
mod tests {
    use super::super::opcodes::all;
    use super::*;

    fn encode(opcode: Opcode, len: usize) -> Result<Vec<u8>, EncodeError> {
        let data = vec![0u8; len];
        let mut out = Vec::new();
        Instruction::Push {
            opcode,
            data: &data,
        }
        .encode_into(&mut out)?;
        Ok(out)
    }

    #[test]
    fn each_push_width_encodes_up_to_its_maximum() {
        // One byte of prefix holds 0xff, two hold 0xffff.
        assert_eq!(encode(all::OP_PUSHDATA1, 0xff).unwrap().len(), 2 + 0xff);
        assert_eq!(encode(all::OP_PUSHDATA2, 0x1_00).unwrap().len(), 3 + 0x100);
        // A direct push carries exactly its own value.
        assert_eq!(encode(Opcode::from_u8(0x14), 20).unwrap().len(), 21);
    }

    #[test]
    fn a_payload_past_the_prefix_width_is_an_error_not_a_truncation() {
        assert_eq!(
            encode(all::OP_PUSHDATA1, 0x100),
            Err(EncodeError::PushTooLong {
                opcode: all::OP_PUSHDATA1,
                len: 0x100,
                max: 0xff,
            })
        );
        assert_eq!(
            encode(all::OP_PUSHDATA2, 0x1_0000),
            Err(EncodeError::PushTooLong {
                opcode: all::OP_PUSHDATA2,
                len: 0x1_0000,
                max: 0xffff,
            })
        );
    }

    /// The mirror of `a_payload_past_the_prefix_width_is_an_error`: for a
    /// direct push, too short corrupts the stream exactly as badly as too
    /// long, because the following bytes get consumed as payload.
    #[test]
    fn a_direct_push_must_match_its_opcode_exactly() {
        for len in [19usize, 21] {
            assert_eq!(
                encode(Opcode::from_u8(0x14), len),
                Err(EncodeError::PushLenMismatch {
                    opcode: Opcode::from_u8(0x14),
                    len,
                    expected: 20,
                }),
                "0x14 with {len} bytes must be rejected"
            );
        }
        assert!(encode(Opcode::from_u8(0x14), 20).is_ok());
    }

    /// Anything `encode_into` accepts must decode back to what went in.
    #[test]
    fn encode_decode_round_trips_for_every_push_opcode() {
        use super::super::Script;
        for byte in 0x01..=0x4bu8 {
            let opcode = Opcode::from_u8(byte);
            let data = vec![0xab; byte as usize];
            let mut out = Vec::new();
            Instruction::Push {
                opcode,
                data: &data,
            }
            .encode_into(&mut out)
            .expect("exact-length direct push encodes");

            let script = Script::new(out);
            let (steps, err) = script.disassemble();
            assert!(err.is_none(), "{opcode} did not re-decode");
            assert_eq!(steps.len(), 1, "{opcode} produced {} steps", steps.len());
            assert_eq!(steps[0].instruction.data(), Some(&data[..]), "{opcode}");
        }
    }

    #[test]
    fn a_push_around_a_non_push_opcode_is_rejected() {
        assert_eq!(
            encode(all::OP_DUP, 1),
            Err(EncodeError::NotAPush {
                opcode: all::OP_DUP,
                len: 1
            })
        );
    }

    /// The bug this guards: truncating the length silently produced bytes that
    /// re-decoded into completely different instructions with no error.
    #[test]
    fn oversized_push_never_emits_bytes() {
        let data = vec![0u8; 300];
        let mut out = vec![0xde, 0xad];
        let err = Instruction::Push {
            opcode: all::OP_PUSHDATA1,
            data: &data,
        }
        .encode_into(&mut out);
        assert!(err.is_err());
        assert_eq!(out, vec![0xde, 0xad], "nothing may be appended on failure");
    }
}
