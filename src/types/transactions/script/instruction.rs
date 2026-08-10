//! Decoding a script's bytes into opcodes and pushed data.

use core::fmt;

use serde::Serialize;

use super::opcodes::{Category, Opcode};

/// One decoded step of a script.
///
/// `OP_0` is *not* a `PushBytes` even though it pushes an empty value — it is
/// a one-byte opcode with no operand, so it decodes as `Op(OP_0)`. Only
/// 0x01..=0x4b and `OP_PUSHDATA1/2/4` carry data out of the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Instruction<'a> {
    /// A data push, with the opcode that introduced it.
    Push { opcode: Opcode, data: &'a [u8] },
    /// Any opcode that takes no operand from the byte stream.
    Op(Opcode),
}

impl Instruction<'_> {
    pub fn opcode(&self) -> Opcode {
        match self {
            Instruction::Push { opcode, .. } => *opcode,
            Instruction::Op(op) => *op,
        }
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Instruction::Push { data, .. } => Some(data),
            Instruction::Op(_) => None,
        }
    }

    pub fn category(&self) -> Category {
        self.opcode().category()
    }

    /// Append this instruction's wire bytes, re-creating the length prefix
    /// that the decoder consumed.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Instruction::Op(op) => out.push(op.to_u8()),
            Instruction::Push { opcode, data } => {
                out.push(opcode.to_u8());
                match opcode.to_u8() {
                    0x4c => out.push(data.len() as u8),
                    0x4d => out.extend_from_slice(&(data.len() as u16).to_le_bytes()),
                    0x4e => out.extend_from_slice(&(data.len() as u32).to_le_bytes()),
                    _ => {} // 0x01..=0x4b: the opcode *is* the length
                }
                out.extend_from_slice(data);
            }
        }
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
                    for b in *data {
                        write!(f, "{b:02x}")?;
                    }
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "kebab-case")]
pub enum DecodeError {
    /// A push wanted more bytes than the script had left.
    Truncated {
        offset: usize,
        declared: usize,
        available: usize,
    },
    /// An `OP_PUSHDATA1/2/4` length prefix itself ran off the end.
    TruncatedLengthPrefix { offset: usize, opcode: Opcode },
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

/// A decoded instruction together with its byte offset in the script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<'a> {
    pub offset: usize,
    pub instruction: Instruction<'a>,
}

/// Iterator over a script's instructions.
///
/// The `Result` is per item rather than around the whole iterator, so a
/// truncated push at the end does not throw away the instructions that
/// decoded cleanly before it. Once an error is yielded the iterator stops.
pub struct Instructions<'a> {
    script: &'a [u8],
    offset: usize,
    done: bool,
}

impl<'a> Instructions<'a> {
    pub(super) fn new(script: &'a [u8]) -> Self {
        Instructions {
            script,
            offset: 0,
            done: false,
        }
    }

    /// Read `n` bytes, or fail with how many were actually there.
    fn take(&mut self, n: usize, push_start: usize) -> Result<&'a [u8], DecodeError> {
        let available = self.script.len() - self.offset;
        if n > available {
            return Err(DecodeError::Truncated {
                offset: push_start,
                declared: n,
                available,
            });
        }
        let out = &self.script[self.offset..self.offset + n];
        self.offset += n;
        Ok(out)
    }
}

impl<'a> Iterator for Instructions<'a> {
    type Item = Result<Step<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.offset >= self.script.len() {
            return None;
        }
        let start = self.offset;
        let opcode = Opcode::from_u8(self.script[self.offset]);
        self.offset += 1;

        // How many data bytes follow, if any.
        let len = if let Some(n) = opcode.push_len() {
            Some(n)
        } else if opcode.is_pushdata() {
            let width = match opcode.to_u8() {
                0x4c => 1,
                0x4d => 2,
                _ => 4,
            };
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
