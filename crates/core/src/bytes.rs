//! Reading and writing Bitcoin's byte encodings.
//!
//! Every consensus structure — transactions, scripts, block headers, PSBTs —
//! is a little-endian byte stream with varint-prefixed lengths. This is the
//! one primitive that walks them. Like [`hex`](crate::hex), it lives at the
//! root of `core` because it is a primitive, not a feature.
//!
//! ```
//! use bitcoin_tools_core::bytes::Reader;
//!
//! let mut r = Reader::new(&[0x02, 0x00, 0x00, 0x00, 0xfd, 0x01, 0x02]);
//! assert_eq!(r.u32().unwrap(), 2);
//! assert_eq!(r.varint().unwrap(), 0x0201);
//! assert!(r.is_empty());
//! ```

use std::fmt;
use std::num::NonZeroUsize;

/// Why a read failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadError {
    /// Ran off the end of the buffer.
    UnexpectedEnd {
        /// Where the read started.
        offset: usize,
        /// How many bytes it wanted.
        needed: usize,
        /// How many were left.
        available: usize,
    },
    /// A length or count that cannot possibly fit in what is left. Rejected
    /// before allocating, so an 8-byte varint cannot ask for gigabytes.
    ImplausibleCount {
        /// The count the stream declared.
        count: u64,
        /// Bytes left, which the count could not fit in even at one byte each.
        remaining: usize,
    },
    /// A compact-size integer written in more bytes than it needs.
    ///
    /// Core's `ReadCompactSize` rejects these. Accepting them would mean
    /// re-encoding produces different bytes than came in, which for a tools
    /// library is worse than refusing: the caller would be shown a field they
    /// never sent.
    NonCanonicalVarint {
        /// Where the varint started.
        offset: usize,
        /// The value it encoded.
        value: u64,
        /// Bytes it was written in.
        used: usize,
        /// Bytes it needed — always fewer than `used`, or this is not an error.
        minimal: usize,
    },
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadError::UnexpectedEnd {
                offset,
                needed,
                available,
            } => write!(
                f,
                "unexpected end at offset {offset}: needed {needed} bytes, {available} remain"
            ),
            ReadError::ImplausibleCount { count, remaining } => write!(
                f,
                "count of {count} cannot fit in the {remaining} remaining bytes"
            ),
            ReadError::NonCanonicalVarint {
                offset,
                value,
                used,
                minimal,
            } => write!(
                f,
                "non-canonical varint at offset {offset}: {value} written in \
                 {used} bytes, needs {minimal}"
            ),
        }
    }
}

impl std::error::Error for ReadError {}

/// A cursor over a byte buffer that never panics and never reads past the end.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading at the front of `buf`.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes consumed so far — the offset the next read starts at.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// True when everything has been consumed.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The bytes not yet consumed, without consuming them.
    #[must_use]
    pub const fn rest(&self) -> &'a [u8] {
        self.buf.split_at(self.pos).1
    }

    /// Consume exactly `n` bytes.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if fewer than `n` remain. A failed read
    /// consumes nothing, so the cursor is still usable afterwards.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], ReadError> {
        let available = self.remaining();
        if n > available {
            return Err(ReadError::UnexpectedEnd {
                offset: self.pos,
                needed: n,
                available,
            });
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    /// Read a fixed-size array. Exists so callers never write
    /// `take(N)?.try_into().unwrap()` — the length is proven by the type.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if fewer than `N` bytes remain.
    pub fn take_array<const N: usize>(&mut self) -> Result<[u8; N], ReadError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    /// Read one byte.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if too few bytes remain.
    pub fn u8(&mut self) -> Result<u8, ReadError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if too few bytes remain.
    pub fn u16(&mut self) -> Result<u16, ReadError> {
        Ok(u16::from_le_bytes(self.take_array()?))
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if too few bytes remain.
    pub fn u32(&mut self) -> Result<u32, ReadError> {
        Ok(u32::from_le_bytes(self.take_array()?))
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if too few bytes remain.
    pub fn u64(&mut self) -> Result<u64, ReadError> {
        Ok(u64::from_le_bytes(self.take_array()?))
    }

    /// Bitcoin's compact-size integer, canonical encodings only.
    ///
    /// A value written in a wider prefix than it needs — `fd 01 00` for 1 —
    /// is rejected, matching Core's `ReadCompactSize`. Accepting it would let
    /// a decoder round-trip to different bytes than it was given.
    ///
    /// # Errors
    ///
    /// [`ReadError::UnexpectedEnd`] if the stream is short, or
    /// [`ReadError::NonCanonicalVarint`] if it is written too wide.
    pub fn varint(&mut self) -> Result<u64, ReadError> {
        let offset = self.pos;
        let (value, used) = match self.u8()? {
            n if n < 0xFD => (u64::from(n), 1),
            0xFD => (u64::from(self.u16()?), 3),
            0xFE => (u64::from(self.u32()?), 5),
            _ => (self.u64()?, 9),
        };
        let minimal = varint_len(value);
        if used != minimal {
            return Err(ReadError::NonCanonicalVarint {
                offset,
                value,
                used,
                minimal,
            });
        }
        Ok(value)
    }

    /// Validate a count before allocating for it.
    ///
    /// A count is only believable if the smallest possible element of that
    /// kind, repeated `count` times, still fits in what is left. Use
    /// [`NonZeroUsize::MIN`] for a plain byte length.
    ///
    /// `min_each` is non-zero by type: a zero would make every count "fit",
    /// which is the one input that defeats the whole check.
    ///
    /// # Errors
    ///
    /// [`ReadError::ImplausibleCount`] if the count cannot fit.
    pub fn checked_count(&self, count: u64, min_each: NonZeroUsize) -> Result<usize, ReadError> {
        let remaining = self.remaining();
        let fits = count
            .checked_mul(min_each.get() as u64)
            .is_some_and(|need| need <= remaining as u64);
        if !fits {
            return Err(ReadError::ImplausibleCount { count, remaining });
        }
        Ok(count as usize)
    }

    /// Read a varint length, check it against the buffer, then take that many
    /// bytes — the pattern behind every script and witness item.
    ///
    /// # Errors
    ///
    /// Any [`ReadError`] the three steps can produce.
    pub fn take_varint_slice(&mut self) -> Result<&'a [u8], ReadError> {
        let len = self.varint()?;
        let len = self.checked_count(len, NonZeroUsize::MIN)?;
        self.take(len)
    }
}

/// Append `n` as a compact-size integer.
pub fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xFC => out.push(n as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// How many bytes `write_varint` will append. Needed to size a buffer or to
/// compute a transaction's weight without serialising it.
#[must_use]
pub const fn varint_len(n: u64) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_little_endian_integers() {
        let mut r = Reader::new(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(r.u16().unwrap(), 0x0201);
        assert_eq!(r.position(), 2);
        assert_eq!(r.u32().unwrap(), 0x0605_0403);
        assert_eq!(r.remaining(), 2);
    }

    #[test]
    fn varints_round_trip_at_every_width_boundary() {
        for n in [
            0u64,
            0xFC,
            0xFD,
            0xFFFF,
            0x1_0000,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
        ] {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            assert_eq!(v.len(), varint_len(n), "varint_len disagrees for {n}");
            let mut r = Reader::new(&v);
            assert_eq!(r.varint().unwrap(), n, "round trip failed for {n}");
            assert!(r.is_empty(), "left {} bytes for {n}", r.remaining());
        }
    }

    #[test]
    fn running_off_the_end_reports_where_and_how_much() {
        let mut r = Reader::new(&[0xaa, 0xbb]);
        assert_eq!(r.u8().unwrap(), 0xaa);
        assert_eq!(
            r.u32(),
            Err(ReadError::UnexpectedEnd {
                offset: 1,
                needed: 4,
                available: 1
            })
        );
        // A failed read consumes nothing.
        assert_eq!(r.position(), 1);
        assert_eq!(r.u8().unwrap(), 0xbb);
    }

    const ONE: NonZeroUsize = NonZeroUsize::MIN;

    #[test]
    fn implausible_counts_are_rejected_before_allocating() {
        let r = Reader::new(&[0u8; 10]);
        let min_input = NonZeroUsize::new(41).unwrap();
        assert_eq!(
            r.checked_count(u64::MAX, min_input),
            Err(ReadError::ImplausibleCount {
                count: u64::MAX,
                remaining: 10
            })
        );
        // The multiplication must saturate into a rejection, not wrap into a
        // false positive. `min_each` is non-zero by type, so the degenerate
        // "everything fits" case is unrepresentable rather than merely untested.
        assert!(r.checked_count(u64::MAX, ONE).is_err());
        assert_eq!(r.checked_count(10, ONE).unwrap(), 10);
        assert!(r.checked_count(11, ONE).is_err());
    }

    #[test]
    fn non_canonical_varints_are_rejected() {
        // 1 encoded in three bytes instead of one.
        assert_eq!(
            Reader::new(&[0xfd, 0x01, 0x00]).varint(),
            Err(ReadError::NonCanonicalVarint {
                offset: 0,
                value: 1,
                used: 3,
                minimal: 1
            })
        );
        // …and in nine.
        assert!(matches!(
            Reader::new(&[0xff, 1, 0, 0, 0, 0, 0, 0, 0]).varint(),
            Err(ReadError::NonCanonicalVarint { minimal: 1, .. })
        ));
        // 0xFD is the smallest value that legitimately needs three bytes.
        assert_eq!(Reader::new(&[0xfd, 0xfd, 0x00]).varint().unwrap(), 0xFD);
        assert!(Reader::new(&[0xfd, 0xfc, 0x00]).varint().is_err());
        // Every canonical encoding still round-trips.
        for n in [0u64, 0xFC, 0xFD, 0xFFFF, 0x1_0000, u64::MAX] {
            let mut v = Vec::new();
            write_varint(&mut v, n);
            assert_eq!(Reader::new(&v).varint().unwrap(), n);
        }
    }

    #[test]
    fn take_array_is_length_proven() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert_eq!(r.take_array::<2>().unwrap(), [1, 2]);
        assert!(r.take_array::<2>().is_err());
    }

    #[test]
    fn varint_prefixed_slices() {
        let mut r = Reader::new(&[0x03, 0xaa, 0xbb, 0xcc, 0x00]);
        assert_eq!(r.take_varint_slice().unwrap(), &[0xaa, 0xbb, 0xcc]);
        assert_eq!(r.take_varint_slice().unwrap(), &[] as &[u8]);
        assert!(r.is_empty());

        // A length longer than the buffer is caught by checked_count.
        let mut r = Reader::new(&[0x09, 0xaa]);
        assert!(matches!(
            r.take_varint_slice(),
            Err(ReadError::ImplausibleCount { count: 9, .. })
        ));
    }

    #[test]
    fn rest_does_not_consume() {
        let mut r = Reader::new(&[1, 2, 3]);
        r.u8().unwrap();
        assert_eq!(r.rest(), &[2, 3]);
        assert_eq!(r.position(), 1);
    }
}
