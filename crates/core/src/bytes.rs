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
//!
//! # There is no `Writer`
//!
//! [`Reader`] has no counterpart, and 5.1 is why. The plan used to say a
//! `bytes::Writer` had to exist before the transaction builder could, because
//! the builder would write bytes.
//! [`TxBuilder`](crate::transactions::TxBuilder) does not: `Tx::encode` was
//! already the serializer, so the builder assembles a
//! [`Tx`](crate::transactions::Tx) and validates it. The one thing it needed
//! from this module was arithmetic — [`varint_len`], to measure a transaction
//! without building one — and that was already here.
//!
//! What remains is three hand-rolled encoders, and they do not want the same
//! tool: `Tx::encode` grows a `Vec` with varint-prefixed fields, while a block
//! header and an extended key each fill a fixed array at known offsets. An
//! appending `Writer` would serve one of the three. Whatever is eventually
//! written here has to cover both shapes, or it is not the shared thing it
//! claims to be — and until something needs it, three short encoders that each
//! read plainly are not obviously worse than one abstraction that reads for
//! none of them.

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
/// Repack fixed-width bit groups into groups of a different width, most
/// significant bit first, zero-padding the last one.
///
/// # Why this is a primitive
///
/// Two formats in this crate need it and they are three layers apart: bech32
/// carries eight-bit bytes as five-bit groups, and BIP39 carries them as
/// eleven-bit word indices. `8`, `5` and `11` share no factors, so neither is
/// a reshape — every length has a remainder, and the remainder is where the
/// bugs are. Written per format that is the same accumulate-and-emit loop
/// twice, in `encoding` and in `hd`, with two chances to get the bit order
/// backwards.
///
/// `from` and `to` are clamped to `1..=16`, and values wider than `from` bits
/// are masked rather than rejected: the callers hold that invariant already —
/// bech32's alphabet cannot produce a group above 31, and an eleven-bit read
/// cannot produce one above 2047 — and [`unpack_bits`] is where a value from
/// *outside* is checked.
#[must_use]
pub fn pack_bits(values: impl IntoIterator<Item = u16>, from: u32, to: u32) -> Vec<u16> {
    let (mut out, bits, leftover) = regroup(values, from, to);
    if bits > 0 {
        out.push(leftover);
    }
    out
}

/// The inverse of [`pack_bits`], rejecting bits the output cannot account for.
///
/// # Returns
///
/// `None` if a value does not fit `from` bits, if the leftover run is `from`
/// bits or longer — a whole input group that produced no output — or if the
/// leftover bits are not zero. The last two are what BIP173 requires be
/// rejected: both mean the input carries information the output cannot
/// represent, which would give one value several spellings.
#[must_use]
pub fn unpack_bits(values: &[u16], from: u32, to: u32) -> Option<Vec<u16>> {
    let from = from.clamp(1, 16);
    if values.iter().any(|&v| u32::from(v) >> from != 0) {
        return None;
    }
    let (unpacked, bits, leftover) = regroup(values.iter().copied(), from, to);
    if bits >= from || leftover != 0 {
        return None;
    }
    Some(unpacked)
}

/// The one loop. Returns the *whole* groups, then how many bits were left over
/// and what they hold — which is what [`pack_bits`] appends as padding and
/// what [`unpack_bits`] refuses to discard.
fn regroup(values: impl IntoIterator<Item = u16>, from: u32, to: u32) -> (Vec<u16>, u32, u16) {
    // Clamped rather than asserted: this is a primitive whose callers all pass
    // literals, and a panic here would be the only one on a public path.
    let from = from.clamp(1, 16);
    let to = to.clamp(1, 16);
    // At most `to - 1` bits are carried between iterations, so the accumulator
    // never holds more than `from + to - 1`.
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    let in_mask = (1u32 << from) - 1;
    let out_mask = (1u32 << to) - 1;
    let mut out = Vec::new();

    for value in values {
        accumulator = accumulator << from | u32::from(value) & in_mask;
        bits += from;
        while bits >= to {
            bits -= to;
            // Masked to `to` bits, which is at most 16.
            out.push(((accumulator >> bits) & out_mask) as u16);
        }
    }

    // Only the low `bits` bits of the accumulator are still meaningful; the
    // rest were emitted above and are stale. Masking before the shift is also
    // what keeps it inside a u32.
    let tail = accumulator & ((1u32 << bits) - 1);
    (out, bits, (tail << (to - bits)) as u16 & out_mask as u16)
}

/// Append `n` as a compact-size varint, in its minimal form.
///
/// Minimal is the only form this crate writes, matching
/// [`Reader::varint`], which is the only form it reads: a value written wider
/// than it needs is rejected on the way in, so producing one would mean this
/// crate could not read its own output.
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

    /// Both width pairs this crate uses, at every length. 8↔5 is bech32's and
    /// 8↔11 is BIP39's, and neither divides the other, so almost every length
    /// has a remainder — which is the half that gets written wrong.
    #[test]
    fn bit_groups_round_trip_at_both_widths() {
        for (from, to) in [(8u32, 5u32), (8, 11), (5, 8), (11, 8)] {
            for len in 0..=40usize {
                let values: Vec<u16> = (0..len)
                    .map(|i| u16::try_from(i).unwrap_or(0).wrapping_mul(37) & ((1 << from) - 1))
                    .collect();
                let packed = pack_bits(values.iter().copied(), from, to);
                assert!(
                    packed.iter().all(|&g| u32::from(g) >> to == 0),
                    "{from}->{to} produced a group too wide"
                );
                assert_eq!(
                    packed.len(),
                    (len * from as usize).div_ceil(to as usize),
                    "{from}->{to} at {len}"
                );

                // Unpacking gives the values back, and then whatever whole
                // groups the padding was long enough to fill — which are
                // zeros, because that is what the padding is. Anything else
                // would mean a bit had moved.
                let back = unpack_bits(&packed, to, from)
                    .unwrap_or_else(|| panic!("{from}->{to} at {len}: rejected its own output"));
                let padding = packed.len() * to as usize - len * from as usize;
                assert_eq!(
                    back.len(),
                    len + padding / from as usize,
                    "{from}->{to} at {len}: {padding} bits of padding"
                );
                assert_eq!(&back[..len], &values[..], "{from}->{to} at {len}");
                assert!(
                    back[len..].iter().all(|&v| v == 0),
                    "{from}->{to} at {len}: padding came back as data"
                );
            }
        }
    }

    /// Padding bits that are not zero mean the input carries information no
    /// output group accounts for — the case BIP173 names, where one witness
    /// program would otherwise have several spellings.
    #[test]
    fn leftover_bits_are_refused_rather_than_dropped() {
        // Ten bits is one byte and two of padding. Zero padding is what the
        // packer wrote…
        assert_eq!(unpack_bits(&[0, 0], 5, 8), Some(vec![0]));
        assert_eq!(unpack_bits(&[1, 0], 5, 8), Some(vec![8]));
        // …and anything else is not.
        assert_eq!(unpack_bits(&[0, 1], 5, 8), None);
        // Five leftover bits are a whole group that produced nothing.
        assert_eq!(unpack_bits(&[0], 5, 8), None);
        assert_eq!(unpack_bits(&[1], 5, 8), None);
        // A value that does not fit the width it claims.
        assert_eq!(unpack_bits(&[32], 5, 8), None);
        assert_eq!(unpack_bits(&[2048], 11, 8), None);
        // Nothing in, nothing out, and nothing left over.
        assert_eq!(unpack_bits(&[], 5, 8), Some(vec![]));
        assert!(pack_bits(std::iter::empty(), 8, 5).is_empty());
    }

    /// Widths are clamped rather than asserted, so a caller cannot panic this
    /// primitive from outside — the crate's no-panic rule reaches here too.
    #[test]
    fn nonsense_widths_are_clamped_not_panicked_on() {
        assert_eq!(
            pack_bits([1u16].into_iter(), 0, 5),
            pack_bits([1u16].into_iter(), 1, 5)
        );
        assert_eq!(
            pack_bits([1u16].into_iter(), 99, 99),
            pack_bits([1u16].into_iter(), 16, 16)
        );
        assert_eq!(unpack_bits(&[1], 0, 0), unpack_bits(&[1], 1, 1));
    }

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
