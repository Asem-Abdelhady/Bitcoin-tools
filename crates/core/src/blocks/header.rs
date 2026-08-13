//! § 6 — the eighty bytes every block is chained by.
//!
//! Two views, the same split [`transactions`](crate::transactions) makes:
//! [`BlockHeader`] is the semantic model, and [`HeaderBreakdown`] is the wire
//! layout — each field as the literal hex bytes it occupies, in serialization
//! order.

use std::fmt;

use super::merkle::MerkleRoot;
use super::target::{CompactTarget, CompactTargetError, Target};
use crate::bytes::Reader;
use crate::hashes::hash::reversed_hash;
use crate::hashes::hash256;
use crate::hex::{self, HexError};

reversed_hash! {
    /// A block hash.
    ///
    /// Thirty-two bytes in *internal* (wire) order, displayed reversed — which
    /// is why a block hash appears to start with zeros when the header's own
    /// bytes end with them. [`Target::is_met_by`] takes the wire form, because
    /// that is the order the consensus rule reads the number in.
    ///
    /// ```
    /// use bitcoin_tools_core::blocks::BlockHash;
    ///
    /// let genesis: BlockHash =
    ///     "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f".parse()?;
    ///
    /// // The zeros are at the *end* of the bytes a header actually carries.
    /// assert_eq!(genesis.to_wire()[28..], [0, 0, 0, 0]);
    /// # Ok::<_, bitcoin_tools_core::hashes::HashParseError>(())
    /// ```
    BlockHash, subject: "block", in: "block header"
}

/// Why bytes were not a block header.
///
/// Only two ways, and that is the point: a header is fixed-width and has no
/// counts, lengths or nested structures, so once there are eighty bytes there
/// is a header. Whether the header describes a *valid* block — whether the
/// work is there, whether the timestamp is sane — is a question about the
/// values, not about the parse, and [`BlockHeader`] answers those by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HeaderDecodeError {
    /// The input was not hex — only from [`BlockHeader::from_hex`].
    Hex(HexError),
    /// Not eighty bytes. Too few and too many are the same mistake: a header
    /// is not a prefix of something longer, and silently ignoring a tail would
    /// hash the eighty bytes the caller did not mean.
    WrongLength {
        /// Bytes supplied.
        got: usize,
        /// Bytes a header is, always.
        expected: usize,
    },
}

impl fmt::Display for HeaderDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderDecodeError::Hex(e) => write!(f, "{e}"),
            HeaderDecodeError::WrongLength { got, expected } => {
                write!(f, "a block header is {expected} bytes, got {got}")
            }
        }
    }
}

impl std::error::Error for HeaderDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            HeaderDecodeError::Hex(e) => Some(e),
            HeaderDecodeError::WrongLength { .. } => None,
        }
    }
}

impl From<HexError> for HeaderDecodeError {
    fn from(e: HexError) -> Self {
        HeaderDecodeError::Hex(e)
    }
}

/// A block header: eighty bytes, six fields, and the whole of the chain.
///
/// ```
/// use bitcoin_tools_core::blocks::BlockHeader;
///
/// let genesis = BlockHeader::from_hex(concat!(
///     "0100000000000000000000000000000000000000000000000000000000000000",
///     "000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa",
///     "4b1e5e4a29ab5f49ffff001d1dac2b7c",
/// ))?;
///
/// assert_eq!(
///     genesis.block_hash().to_string(),
///     "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
/// );
/// assert_eq!(genesis.time, 1_231_006_505);
/// assert_eq!(genesis.bits.difficulty(), 1.0);
/// assert!(genesis.meets_target());
/// # Ok::<_, bitcoin_tools_core::blocks::HeaderDecodeError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct BlockHeader {
    /// Block version, which stopped being a version number: BIP9 reads the low
    /// bits as soft-fork signals and BIP320 lets miners roll sixteen more as
    /// extra nonce space, so a modern value like `0x2000_0000` is a bitfield.
    ///
    /// Core declares the field `int32_t` and this crate reads it unsigned, as
    /// it reads a transaction's version. The two agree on every header that
    /// has ever existed, since BIP9 fixes the top three bits at `001`.
    pub version: u32,
    /// The header this one extends. Zero in the genesis block, which is the
    /// only header with nothing behind it.
    pub prev_block: BlockHash,
    /// What the block's transactions hash to — see
    /// [`merkle::root`](super::merkle::root), which recomputes it.
    pub merkle_root: MerkleRoot,
    /// The miner's claimed time, in seconds since the Unix epoch.
    ///
    /// Claimed, not measured: consensus only requires it to be above the
    /// median of the last eleven blocks and no more than two hours ahead of
    /// network time, so headers out of order in time are normal and legal.
    /// Unsigned, and so good until 2106 rather than 2038.
    pub time: u32,
    /// The target this block's hash had to come under, in the compact
    /// encoding. [`CompactTarget`] is what makes it a number rather than four
    /// bytes.
    pub bits: CompactTarget,
    /// The field miners vary to search for a hash under the target. Exhausted
    /// long ago — modern miners roll [`BlockHeader::version`] and the coinbase
    /// as well, which is why a valid block can have any nonce at all.
    pub nonce: u32,
}

impl BlockHeader {
    /// A header is exactly this many bytes, in every block, forever.
    pub const SIZE: usize = 80;

    /// Decode a header written in hex, accepting `0x` and whitespace.
    ///
    /// # Errors
    ///
    /// [`HeaderDecodeError`] for bad hex or the wrong number of bytes.
    pub fn from_hex(s: &str) -> Result<Self, HeaderDecodeError> {
        Self::decode(&hex::decode_lenient(s)?)
    }

    /// Decode the eighty consensus-serialized bytes.
    ///
    /// # Errors
    ///
    /// [`HeaderDecodeError::WrongLength`] for anything but eighty bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, HeaderDecodeError> {
        let mut r = Reader::new(bytes);
        // Every field is fixed-width, so a short read and a long buffer are
        // the same complaint — one that names the width rather than the
        // offset a cursor stopped at.
        let wrong_length = || HeaderDecodeError::WrongLength {
            got: bytes.len(),
            expected: Self::SIZE,
        };
        let header = BlockHeader {
            version: r.u32().map_err(|_| wrong_length())?,
            prev_block: BlockHash::from_wire(r.take_array().map_err(|_| wrong_length())?),
            merkle_root: MerkleRoot::from_wire(r.take_array().map_err(|_| wrong_length())?),
            time: r.u32().map_err(|_| wrong_length())?,
            bits: CompactTarget::from_consensus(r.u32().map_err(|_| wrong_length())?),
            nonce: r.u32().map_err(|_| wrong_length())?,
        };
        if !r.is_empty() {
            return Err(wrong_length());
        }
        Ok(header)
    }

    /// Consensus serialization — the exact bytes that were decoded, and the
    /// bytes the block hash is taken over.
    #[must_use]
    pub fn encode(&self) -> [u8; Self::SIZE] {
        let mut out = [0u8; Self::SIZE];
        out[..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_block.to_wire());
        out[36..68].copy_from_slice(&self.merkle_root.to_wire());
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_consensus().to_le_bytes());
        out[76..].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// 6.1 — HASH256 of the eighty bytes.
    ///
    /// The whole of the block's identity: a block *is* its header as far as
    /// the chain is concerned, and the transactions are attached to it by the
    /// merkle root.
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        BlockHash::from_wire(hash256(&self.encode()))
    }

    /// The threshold [`BlockHeader::bits`] encodes.
    ///
    /// # Errors
    ///
    /// [`CompactTargetError`] if the four bytes are not a representable
    /// target — which no real header is, but any eighty bytes can be.
    pub fn target(&self) -> Result<Target, CompactTargetError> {
        self.bits.target()
    }

    /// Whether this header's hash comes in under the target this header
    /// itself states.
    ///
    /// That is the whole claim, and it is narrower than "the proof of work is
    /// valid". A node checking this header would also reject a target of zero
    /// and a target *easier* than the network's own limit — mainnet's is
    /// [`CompactTarget::DIFFICULTY_ONE`] — so a header claiming
    /// `bits = 0x2000ffff` passes here and would be rejected everywhere. That
    /// bound is a property of the network rather than of the header, and
    /// whether `bits` is the value the retargeting rules require at this
    /// height needs the previous 2,015 headers. Neither is something eighty
    /// bytes can answer, so neither is answered here.
    ///
    /// False for a header whose `bits` do not encode a target at all, since a
    /// threshold that cannot be represented cannot be met.
    #[must_use]
    pub fn meets_target(&self) -> bool {
        self.target()
            .is_ok_and(|target| target.is_met_by(&self.block_hash().to_hash()))
    }

    /// Split into labelled wire fields.
    #[must_use]
    pub fn breakdown(&self) -> HeaderBreakdown {
        let raw = self.encode();
        HeaderBreakdown {
            block_hash: self.block_hash().to_string(),
            version: hex::encode(&self.version.to_le_bytes()),
            prev_block: hex::encode(&self.prev_block.to_wire()),
            merkle_root: hex::encode(&self.merkle_root.to_wire()),
            time: hex::encode(&self.time.to_le_bytes()),
            bits: hex::encode(&self.bits.to_consensus().to_le_bytes()),
            nonce: hex::encode(&self.nonce.to_le_bytes()),
            raw_header: hex::encode(&raw),
        }
    }
}

/// Every field of a header as the literal hex bytes it occupies, in
/// serialization order.
///
/// The [`TxBreakdown`](crate::transactions::tx::TxBreakdown) of § 6: the view
/// that answers "what do these eighty bytes mean", byte by byte.
///
/// Not `Serialize`, matching `TxBreakdown`. A breakdown is already all
/// strings, so deriving it would be free — and that is the trap: it would
/// publish a field-for-field JSON shape as part of this crate's semver
/// contract, on the type most likely to gain a field. A consumer that wants
/// one owns the mapping, which is what the server in this workspace does. The
/// *semantic* types ([`BlockHeader`], [`Tx`](crate::transactions::Tx)) are
/// `Serialize`, because there the shape is the domain's rather than a
/// rendering choice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderBreakdown {
    /// The block hash in **displayed** (reversed) order — the form an explorer
    /// shows. Note [`HeaderBreakdown::prev_block`] is the opposite: a
    /// wire-order field copied out of the serialization.
    pub block_hash: String,
    /// The four version bytes, little-endian as serialized.
    pub version: String,
    /// The previous block hash in **wire** order, i.e. the bytes as
    /// serialized — the reverse of how the same hash is displayed.
    pub prev_block: String,
    /// The merkle root in **wire** order, as serialized.
    pub merkle_root: String,
    /// The four timestamp bytes, little-endian.
    pub time: String,
    /// The four `bits` bytes, little-endian — so `ffff001d` for the target
    /// [`CompactTarget`] spells `1d00ffff`.
    pub bits: String,
    /// The four nonce bytes, little-endian.
    pub nonce: String,
    /// The whole header, re-encoded — byte-identical to what came in.
    pub raw_header: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Block 100,000.
    const HEADER: &str = concat!(
        "0100000050120119172a610421a6c3011dd330d9",
        "df07b63616c2cc1f1cd00200000000006657a925",
        "2aacd5c0b2940996ecff952228c3067cc38d4885",
        "efb5a4ac4247e9f337221b4d4c86041b0f2b5710",
    );

    fn header() -> BlockHeader {
        BlockHeader::from_hex(HEADER).expect("a real mainnet header")
    }

    #[test]
    fn the_fields_are_read_in_the_right_order() {
        let header = header();
        assert_eq!(header.version, 1);
        assert_eq!(
            header.prev_block.to_string(),
            "000000000002d01c1fccc21636b607dfd930d31d01c3a62104612a1719011250",
            "the previous hash displays reversed, like every other block hash"
        );
        assert_eq!(
            header.merkle_root.to_string(),
            "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766",
        );
        assert_eq!(header.time, 1_293_623_863);
        assert_eq!(header.bits.to_string(), "1b04864c");
        assert_eq!(header.nonce, 274_148_111);
    }

    #[test]
    fn re_encoding_is_byte_exact() {
        assert_eq!(hex::encode(&header().encode()), HEADER);
        assert_eq!(header().breakdown().raw_header, HEADER);
    }

    #[test]
    fn the_hash_covers_the_header_and_meets_its_target() {
        let header = header();
        assert_eq!(
            header.block_hash().to_string(),
            "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
        );
        assert!(header.meets_target());

        // Move one bit of the nonce and both stop being true — the hash is
        // over all eighty bytes, and the work is over the hash.
        let mut tweaked = header;
        tweaked.nonce ^= 1;
        assert_ne!(tweaked.block_hash(), header.block_hash());
        assert!(!tweaked.meets_target());
    }

    #[test]
    fn a_header_is_eighty_bytes_or_it_is_not_a_header() {
        let bytes = hex::decode(HEADER).expect("valid hex");
        let too_few = BlockHeader::decode(&bytes[..79]);
        let too_many = BlockHeader::decode(&[bytes.clone(), vec![0]].concat());

        assert_eq!(
            too_few,
            Err(HeaderDecodeError::WrongLength {
                got: 79,
                expected: 80
            })
        );
        assert_eq!(
            too_many,
            Err(HeaderDecodeError::WrongLength {
                got: 81,
                expected: 80
            }),
            "a header is not a prefix: trailing bytes are a wrong length, \
             not something to ignore"
        );
        assert!(matches!(
            BlockHeader::from_hex("zz"),
            Err(HeaderDecodeError::Hex(_))
        ));
    }

    #[test]
    fn a_header_whose_bits_encode_nothing_still_decodes() {
        // 0xffffffff as `bits`: an overflowing target, and eighty perfectly
        // well-formed bytes. Parsing is about the layout; the values are
        // questions the caller asks by name.
        let mut header = header();
        header.bits = CompactTarget::from_consensus(0xffff_ffff);

        let round_tripped = BlockHeader::decode(&header.encode()).expect("still eighty bytes");
        assert_eq!(round_tripped, header);
        assert!(header.target().is_err());
        assert!(
            !header.meets_target(),
            "an unrepresentable threshold cannot be met"
        );
    }

    #[test]
    fn the_breakdown_shows_the_bytes_not_the_values() {
        let breakdown = header().breakdown();
        assert_eq!(
            breakdown.version, "01000000",
            "little-endian, as serialized"
        );
        assert_eq!(
            breakdown.bits, "4c86041b",
            "the same field CompactTarget spells 1b04864c"
        );
        assert_eq!(
            breakdown.block_hash,
            "000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506",
            "the hash is the one field shown the way an explorer shows it"
        );
        assert!(
            breakdown.prev_block.ends_with("00000000"),
            "…and the prev hash is the one field shown the way the wire has it"
        );
        assert_eq!(
            breakdown.raw_header.len(),
            BlockHeader::SIZE * 2,
            "the fields tile the header exactly"
        );
    }
}
