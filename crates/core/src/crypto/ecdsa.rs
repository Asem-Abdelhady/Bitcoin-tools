//! ECDSA over secp256k1: sign a hash, verify a signature.
//!
//! Takes the curve types from [`secp`](super::secp) and knows nothing about
//! keys, addresses or transactions. That is the layering — [`keys`](crate::keys)
//! is L3 and wraps this — and it is also the honest description: a signature
//! check is arithmetic about a point on a curve, not about how someone chose to
//! serialize that point.
//!
//! # What is signed is a hash, always
//!
//! Every function here takes 32 bytes and treats them as a number. Nothing
//! hashes anything for you, and that is deliberate: Bitcoin never signs a
//! message: it signs a *sighash*, computed from the transaction, the input
//! index, the prevout script and the sighash flags — and getting that
//! computation wrong is how coins are lost. A convenience wrapper that took
//! arbitrary bytes and hashed them would look like it was doing that job.
//!
//! # Two encodings
//!
//! A signature is a pair of scalars, `(r, s)`. Bitcoin's scripts carry them
//! DER-encoded (BIP66 requires strictly so), while most other protocols use the
//! fixed 64-byte concatenation. Both are here, and both name the same
//! signature — [`Signature`] stores the pair, not the bytes it arrived in.

use crate::parse::display_serialize;
use std::fmt;

use super::secp::{Point, SCALAR_SIZE, SecretScalar, context, verify_context};
use crate::hex::{self, HexError};

use secp256k1::Message;
use secp256k1::ecdsa::Signature as BackendSig;

/// Bytes in the fixed-width encoding: `r` then `s`, 32 each.
pub const COMPACT_SIZE: usize = 2 * SCALAR_SIZE;

/// Bytes a DER signature can reach: a sequence header, then two integers that
/// each need a leading zero when their top bit is set.
///
/// A scriptSig push is one byte longer than this, because it appends the
/// sighash flag — that byte belongs to the script, not to the signature, so it
/// is not handled here.
pub const MAX_DER_SIZE: usize = 72;

/// Bytes of message hash. Not a message: see the module docs.
pub const MESSAGE_SIZE: usize = 32;

/// Why bytes were not an ECDSA signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureError {
    /// The input was not hex — only from [`Signature::from_hex`].
    Hex(HexError),
    /// Not a strict DER encoding of two integers, as BIP66 requires.
    ///
    /// Everything mined since BIP66 activated in July 2015 satisfies this.
    /// Earlier blocks contain signatures that are merely *near* DER — an extra
    /// leading zero, a length in the wrong form — and this crate does not
    /// parse those. Doing so needs a separate lax parser, which is additive if
    /// a caller ever needs to walk pre-2015 scripts, and which must never be
    /// what a verifier reaches for by default.
    Der,
    /// Not sixty-four bytes — only from [`Signature::from_compact_slice`].
    WrongLength {
        /// Bytes supplied, where [`COMPACT_SIZE`] were required.
        got: usize,
    },
    /// `r` or `s` is zero, or is not below the group order. A signature is a
    /// pair of scalars, and neither of those values is one.
    ///
    /// This is not only a range check on what arrived. libsecp256k1's DER
    /// integer parser treats an out-of-range or negative integer by setting
    /// that half of the signature to **zero** and reporting success — see
    /// `secp256k1_der_parse_integer` — so a caller who trusted the backend
    /// would be handed an `r` the input never contained, and would go on to
    /// print it. Refusing is the only answer that cannot be silently wrong,
    /// which is the same reason [`Point::from_sec1`](super::secp::Point::from_sec1)
    /// refuses the hybrid encodings.
    NotAScalar,
}

impl fmt::Display for SignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignatureError::Hex(e) => write!(f, "{e}"),
            SignatureError::Der => f.write_str("not a strict DER encoding of an ECDSA signature"),
            SignatureError::WrongLength { got } => {
                write!(f, "a compact signature is {COMPACT_SIZE} bytes, got {got}")
            }
            SignatureError::NotAScalar => {
                f.write_str("r and s must each be non-zero and below the group order")
            }
        }
    }
}

impl std::error::Error for SignatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SignatureError::Hex(e) => Some(e),
            _ => None,
        }
    }
}

impl From<HexError> for SignatureError {
    fn from(e: HexError) -> Self {
        SignatureError::Hex(e)
    }
}

/// An ECDSA signature: the pair `(r, s)`.
///
/// Stores the pair rather than the bytes it was read from, so
/// [`Signature::to_der`] is the canonical encoding of that pair and not
/// necessarily the input echoed back. For a *decoder* that distinction usually
/// matters — it is why [`Tx`](crate::transactions::Tx) keeps its segwit flag —
/// but here it is the point: a signature that only round-trips because it was
/// stored verbatim would let a non-canonical encoding through the door.
///
/// ```
/// use bitcoin_tools_core::crypto::ecdsa::{self, Signature};
/// use bitcoin_tools_core::crypto::secp::SecretScalar;
///
/// let key = SecretScalar::from_be_bytes(&[1; 32])?;
/// let hash = [0xab; 32];
///
/// let signature = ecdsa::sign(&hash, &key);
/// assert!(ecdsa::verify(&hash, &signature, &key.public_point()));
///
/// // Both encodings name the same signature.
/// let der = Signature::from_der(&signature.to_der())?;
/// let compact = Signature::from_compact(&signature.to_compact())?;
/// assert_eq!(der, compact);
/// # Ok::<_, Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Signature(BackendSig);

impl Signature {
    /// The one door both parsers come through.
    ///
    /// Neither backend parser guarantees what its own type implies. The
    /// compact one accepts a zero half outright, and the DER one *substitutes*
    /// zero for any integer that is negative or at or above the group order
    /// (`secp256k1_der_parse_integer`), reporting success either way. A zero
    /// `r` or `s` can never verify, so nothing is lost by refusing it — and
    /// what is gained is that this type cannot hold a scalar its input did not
    /// contain.
    fn checked(signature: BackendSig) -> Result<Self, SignatureError> {
        let compact = signature.serialize_compact();
        let is_zero = |half: &[u8]| half.iter().all(|&byte| byte == 0);
        if is_zero(&compact[..SCALAR_SIZE]) || is_zero(&compact[SCALAR_SIZE..]) {
            return Err(SignatureError::NotAScalar);
        }
        Ok(Signature(signature))
    }

    /// Read the fixed 64-byte form: `r` then `s`, big-endian.
    ///
    /// # Errors
    ///
    /// [`SignatureError::NotAScalar`] if either half is zero or not below the
    /// group order.
    pub fn from_compact(bytes: &[u8; COMPACT_SIZE]) -> Result<Self, SignatureError> {
        BackendSig::from_compact(bytes)
            .map_err(|_| SignatureError::NotAScalar)
            .and_then(Signature::checked)
    }

    /// Read the fixed 64-byte form from a slice.
    ///
    /// The same thing as [`Signature::from_compact`], for the callers who do
    /// not already hold an array — which is most of them, since hex decodes to
    /// a `Vec`.
    ///
    /// # Errors
    ///
    /// [`SignatureError::WrongLength`] if the slice is not [`COMPACT_SIZE`]
    /// bytes, or [`SignatureError::NotAScalar`] as for
    /// [`Signature::from_compact`].
    pub fn from_compact_slice(bytes: &[u8]) -> Result<Self, SignatureError> {
        let array = <&[u8; COMPACT_SIZE]>::try_from(bytes)
            .map_err(|_| SignatureError::WrongLength { got: bytes.len() })?;
        Signature::from_compact(array)
    }

    /// The fixed 64-byte form: `r` then `s`, big-endian.
    #[must_use]
    pub fn to_compact(&self) -> [u8; COMPACT_SIZE] {
        self.0.serialize_compact()
    }

    /// Read a strict DER signature — the encoding Bitcoin scripts carry.
    ///
    /// Strict, as BIP66 requires: minimal integer lengths, no trailing bytes,
    /// no BER indefinite forms. A lax parser would accept encodings that
    /// consensus stopped accepting in 2015.
    ///
    /// The bytes must be the signature alone. A scriptSig push carries the
    /// sighash flag as a final byte, and that byte is the script's, not this
    /// type's, so split it off first — and split it off in a way that survives
    /// an empty push, since those are ordinary (the `OP_0` dummy every
    /// `CHECKMULTISIG` carries, and the placeholders in a partially signed
    /// input):
    ///
    /// ```
    /// # use bitcoin_tools_core::crypto::ecdsa::Signature;
    /// # fn read(push: &[u8]) -> Option<(Signature, u8)> {
    /// let (&sighash_flag, der) = push.split_last()?;
    /// let signature = Signature::from_der(der).ok()?;
    /// # Some((signature, sighash_flag))
    /// # }
    /// # assert!(read(&[]).is_none());
    /// ```
    ///
    /// # Errors
    ///
    /// [`SignatureError::Der`] if the encoding is not strict DER, or
    /// [`SignatureError::NotAScalar`] if `r` or `s` is zero, negative or not
    /// below the group order — which the backend would otherwise accept as a
    /// zero.
    pub fn from_der(bytes: &[u8]) -> Result<Self, SignatureError> {
        BackendSig::from_der(bytes)
            .map_err(|_| SignatureError::Der)
            .and_then(Signature::checked)
    }

    /// Read a strict DER signature written in hex, accepting `0x` and
    /// whitespace.
    ///
    /// DER only, matching [`fmt::Display`]. Sixty-four bytes of compact hex is
    /// well-formed input that this refuses with [`SignatureError::Der`] —
    /// decode it and use [`Signature::from_compact_slice`] instead.
    ///
    /// # Errors
    ///
    /// [`SignatureError`] for bad hex or bytes that are not strict DER.
    pub fn from_hex(s: &str) -> Result<Self, SignatureError> {
        Self::from_der(&hex::decode_lenient(s)?)
    }

    /// The canonical strict-DER encoding, at most [`MAX_DER_SIZE`] bytes.
    #[must_use]
    pub fn to_der(&self) -> Vec<u8> {
        self.0.serialize_der().to_vec()
    }

    /// The pair `(r, s)`, 32 bytes each, big-endian.
    ///
    /// Named as [`Point::coordinates`](super::secp::Point::coordinates) is,
    /// and there for the same reason: both halves usually get shown together,
    /// and asking for them one at a time re-serializes the signature twice.
    #[must_use]
    pub fn parts(&self) -> ([u8; SCALAR_SIZE], [u8; SCALAR_SIZE]) {
        let compact = self.to_compact();
        let mut r = [0u8; SCALAR_SIZE];
        let mut s = [0u8; SCALAR_SIZE];
        r.copy_from_slice(&compact[..SCALAR_SIZE]);
        s.copy_from_slice(&compact[SCALAR_SIZE..]);
        (r, s)
    }

    /// `r`, big-endian.
    #[must_use]
    pub fn r(&self) -> [u8; SCALAR_SIZE] {
        self.parts().0
    }

    /// `s`, big-endian.
    #[must_use]
    pub fn s(&self) -> [u8; SCALAR_SIZE] {
        self.parts().1
    }

    /// Whether `s` is in the lower half of its range.
    ///
    /// `(r, s)` and `(r, n - s)` are both valid signatures of the same message
    /// by the same key, so anyone relaying a transaction could flip one into
    /// the other and change its txid without touching what it authorises.
    /// That is transaction malleability, and [`sign`] only ever produces the
    /// low form.
    ///
    /// It has never been a *consensus* rule, for segwit or anything else.
    /// BIP62 proposed it and was withdrawn; BIP146 was never activated. What
    /// exists is standardness: Bitcoin Core has enforced `SCRIPT_VERIFY_LOW_S`
    /// since 0.11.1 as part of `STANDARD_SCRIPT_VERIFY_FLAGS`, and never as
    /// part of the mandatory set. So a high-`s` signature is valid, is
    /// spendable, sits in mined blocks — and will not be relayed.
    ///
    /// Which is why this is a question about *policy*, deliberately separate
    /// from [`verify`], which answers whether the arithmetic holds. A
    /// signature can be perfectly valid and non-standard, and the two facts
    /// have different consequences.
    #[must_use]
    pub fn is_low_s(&self) -> bool {
        *self == self.normalize_s()
    }

    /// The same signature with `s` in the lower half of its range.
    ///
    /// Returns `self` unchanged when [`Signature::is_low_s`] already holds.
    /// Note this changes the bytes and *not* the meaning: both forms verify
    /// against the same key and message.
    #[must_use]
    pub fn normalize_s(&self) -> Self {
        let mut normalized = self.0;
        normalized.normalize_s();
        Signature(normalized)
    }
}

/// The strict-DER encoding, in hex — the form a scriptSig shows, less its
/// sighash byte.
impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `serialize_der` returns a stack buffer that derefs to a slice and
        // never escapes this impl, so `Display` — and `to_string`, and the
        // serde path through `collect_str` — do not allocate for it.
        hex::write(f, &self.0.serialize_der())
    }
}

impl std::str::FromStr for Signature {
    type Err = SignatureError;

    /// Strict DER in hex, matching [`fmt::Display`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Signature::from_hex(s)
    }
}

display_serialize!(Signature);

/// sign a 32-byte hash.
///
/// # The nonce is derived, not drawn
///
/// This is RFC 6979: the per-signature nonce is an HMAC-SHA256 chain over the
/// key and the hash, so signing is a pure function and takes no RNG. That is
/// not a convenience. ECDSA leaks the private key outright if one nonce is
/// ever reused across two signatures, and it leaks it to arithmetic anyone can
/// do — which is how the 2010 PlayStation 3 keys and the 2013 Android wallet
/// thefts both happened. A deterministic nonce cannot repeat unless the
/// message does, and if the message repeats the signature does too, which
/// gives an attacker nothing new.
///
/// It also makes signing *testable*: the published vectors in
/// `bitcoin-tools-vectors` pin exact signatures, which is impossible for a
/// randomised signer.
///
/// The output always has low `s` — see [`Signature::is_low_s`].
///
/// # Not low-`r` grinding
///
/// Bitcoin Core's wallet re-signs with extra entropy until `r` has a leading
/// zero byte, saving one byte of transaction size. That is a fee optimisation
/// a wallet chooses, not a property of ECDSA, and it produces a signature the
/// RFC 6979 vectors do not predict. Additive if a wallet ever wants it.
#[must_use]
pub fn sign(message_hash: &[u8; MESSAGE_SIZE], key: &SecretScalar) -> Signature {
    let message = Message::from_digest(*message_hash);
    Signature(context().sign_ecdsa(message, key.as_backend()))
}

/// does this signature verify against this key and this hash?
///
/// # High `s` verifies here
///
/// `(r, s)` and `(r, n - s)` are the same signature mathematically, and this
/// function answers the mathematical question, so it normalises `s` before
/// checking. libsecp256k1's own verifier refuses the high form outright, which
/// is a *policy* answer — a good one for a node, and the wrong one for a
/// library asked "is this signature valid": 72 of the 168 valid signatures in
/// Google's Wycheproof suite have high `s`, and every one of them was produced
/// by a correct signer.
///
/// Bitcoin Core does the same thing here for the same reason. `CPubKey::Verify`
/// calls `secp256k1_ecdsa_signature_normalize` before
/// `secp256k1_ecdsa_verify`, noting that libsecp256k1 requires lower-`s`
/// signatures "which have not historically been enforced in Bitcoin" — high-`s`
/// signatures are consensus-valid and sit in mined blocks. Ask
/// [`Signature::is_low_s`] for the policy question, which in Core is a
/// standardness flag rather than part of `CHECKSIG`.
///
/// Returns a `bool` rather than a `Result` because there is exactly one
/// answer: a signature that does not verify has no sub-reason a caller could
/// act on. Bytes that are not a signature at all fail earlier, at
/// [`Signature::from_der`], which does report why.
#[must_use]
pub fn verify(message_hash: &[u8; MESSAGE_SIZE], signature: &Signature, key: &Point) -> bool {
    let message = Message::from_digest(*message_hash);
    verify_context()
        .verify_ecdsa(message, &signature.normalize_s().0, key.as_backend())
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::secp::GROUP_ORDER;

    fn scalar(byte: u8) -> SecretScalar {
        SecretScalar::from_be_bytes(&[byte; SCALAR_SIZE]).expect("a valid scalar")
    }

    #[test]
    fn a_signature_verifies_against_its_own_key_and_hash() {
        let key = scalar(0x11);
        let hash = [0x42; MESSAGE_SIZE];
        let signature = sign(&hash, &key);

        assert!(verify(&hash, &signature, &key.public_point()));

        // …and against nothing else: a different hash, or a different key.
        let mut other_hash = hash;
        other_hash[31] ^= 0x01;
        assert!(!verify(&other_hash, &signature, &key.public_point()));
        assert!(!verify(&hash, &signature, &scalar(0x22).public_point()));
    }

    /// The property that makes signing testable, and the one that keeps a
    /// nonce from ever repeating.
    #[test]
    fn signing_is_deterministic() {
        let (key, hash) = (scalar(0x11), [0x42; MESSAGE_SIZE]);
        assert_eq!(sign(&hash, &key), sign(&hash, &key));

        // A one-bit change in the hash changes the whole signature, including
        // `r` — which is the nonce's public half, and must not be reused.
        let mut other = hash;
        other[0] ^= 0x01;
        assert_ne!(sign(&hash, &key).r(), sign(&other, &key).r());
    }

    #[test]
    fn both_encodings_name_the_same_signature() {
        let signature = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));

        assert_eq!(
            Signature::from_compact(&signature.to_compact()),
            Ok(signature)
        );
        assert_eq!(Signature::from_der(&signature.to_der()), Ok(signature));
        assert_eq!(signature.to_string().parse(), Ok(signature));

        // The compact form is exactly r ‖ s.
        let compact = signature.to_compact();
        assert_eq!(compact[..SCALAR_SIZE], signature.r());
        assert_eq!(compact[SCALAR_SIZE..], signature.s());
        assert!(signature.to_der().len() <= MAX_DER_SIZE);
    }

    /// BIP66's rule. These are the encodings that were legal before 2015 and
    /// are not now, so accepting one would be accepting a signature no node
    /// would relay.
    #[test]
    fn der_parsing_is_strict() {
        let signature = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));
        let der = signature.to_der();

        // A trailing byte — which is what a scriptSig push looks like, since
        // it appends the sighash flag. Accepting it would make the sighash
        // byte invisible.
        let mut trailing = der.clone();
        trailing.push(0x01);
        assert_eq!(Signature::from_der(&trailing), Err(SignatureError::Der));

        // A truncated sequence, a wrong sequence tag, and empty input.
        assert_eq!(
            Signature::from_der(&der[..der.len() - 1]),
            Err(SignatureError::Der)
        );
        let mut wrong_tag = der.clone();
        wrong_tag[0] = 0x31;
        assert_eq!(Signature::from_der(&wrong_tag), Err(SignatureError::Der));
        assert_eq!(Signature::from_der(&[]), Err(SignatureError::Der));

        // A non-minimal integer: pad `r` with a leading zero it does not need.
        let mut padded = vec![0x30, 0x00];
        let r_len = der[3];
        padded.push(0x02);
        padded.push(r_len + 1);
        padded.push(0x00);
        padded.extend_from_slice(&der[4..4 + usize::from(r_len)]);
        padded.extend_from_slice(&der[4 + usize::from(r_len)..]);
        let body = padded.len() - 2;
        padded[1] = body as u8;
        assert_eq!(Signature::from_der(&padded), Err(SignatureError::Der));

        assert!(matches!(
            Signature::from_hex("zz"),
            Err(SignatureError::Hex(_))
        ));
    }

    /// The one that would be silently wrong. libsecp256k1's DER integer
    /// parser answers "success" for an integer at or above the group order and
    /// hands back **zero** in its place, so without a check of our own,
    /// `from_der` would return a signature whose `r` the caller never wrote.
    #[test]
    fn an_out_of_range_der_integer_is_refused_not_zeroed() {
        let valid = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));

        // r = n, which is one past the largest scalar. Its top bit is set, so
        // DER needs the leading zero byte — this is a well-formed encoding of
        // a number that is not a scalar, which is exactly the case at issue.
        let mut der = vec![0x30, 0x00, 0x02, 0x21, 0x00];
        der.extend_from_slice(&GROUP_ORDER);
        der.push(0x02);
        der.push(0x20);
        der.extend_from_slice(&valid.s());
        let body = der.len() - 2;
        der[1] = body as u8;

        // The backend alone would say yes, with r rewritten to zero.
        assert!(
            secp256k1::ecdsa::Signature::from_der(&der).is_ok(),
            "if this ever starts failing, the check below has become the \
             backend's job and this test should say so"
        );
        assert_eq!(Signature::from_der(&der), Err(SignatureError::NotAScalar));
    }

    /// Neither half of the pair may be zero or at the group order — those are
    /// the two values that are not scalars.
    #[test]
    fn the_compact_form_checks_both_scalars() {
        let signature = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));
        let good = signature.to_compact();

        let mut zero_r = good;
        zero_r[..SCALAR_SIZE].fill(0);
        assert_eq!(
            Signature::from_compact(&zero_r),
            Err(SignatureError::NotAScalar)
        );

        let mut zero_s = good;
        zero_s[SCALAR_SIZE..].fill(0);
        assert_eq!(
            Signature::from_compact(&zero_s),
            Err(SignatureError::NotAScalar)
        );

        let mut order_s = good;
        order_s[SCALAR_SIZE..].copy_from_slice(&GROUP_ORDER);
        assert_eq!(
            Signature::from_compact(&order_s),
            Err(SignatureError::NotAScalar)
        );
    }

    /// The malleability the low-`s` rule exists to remove: `n - s` is a second
    /// spelling of the same signature, it verifies just as well, and only one
    /// of the two is standard.
    #[test]
    fn a_high_s_signature_is_the_same_signature() {
        let (key, hash) = (scalar(0x11), [0x42; MESSAGE_SIZE]);
        let low = sign(&hash, &key);
        assert!(low.is_low_s(), "sign only ever produces the low form");

        // Flip s to n - s by hand, which is what a relaying node could do.
        let mut flipped = low.to_compact();
        flipped[SCALAR_SIZE..].copy_from_slice(&subtract_be(&GROUP_ORDER, &low.s()));
        let high = Signature::from_compact(&flipped).expect("n - s is a scalar");

        assert_ne!(high, low, "different bytes");
        assert!(!high.is_low_s());
        assert_eq!(high.normalize_s(), low, "…and the same signature");
        assert!(
            verify(&hash, &high, &key.public_point()),
            "a high-s signature is valid arithmetic, and this asks about the \
             arithmetic"
        );
    }

    /// `a - b` over 32 big-endian bytes, borrowing all the way down. Ten lines
    /// beats a bignum dependency for the one subtraction a test needs, and
    /// doing it in `u128` halves would be wrong: `n - s` borrows across the
    /// middle whenever `s` exceeds the low half of `n`.
    fn subtract_be(a: &[u8; SCALAR_SIZE], b: &[u8; SCALAR_SIZE]) -> [u8; SCALAR_SIZE] {
        let mut out = [0u8; SCALAR_SIZE];
        let mut borrow = 0i16;
        for i in (0..SCALAR_SIZE).rev() {
            let digit = i16::from(a[i]) - i16::from(b[i]) - borrow;
            borrow = i16::from(digit < 0);
            out[i] = (digit + 256 * borrow) as u8;
        }
        assert_eq!(borrow, 0, "a - b underflowed");
        out
    }

    /// `serde` is a default feature and the JSON spelling is a contract, so it
    /// is asserted rather than assumed to follow `Display`.
    #[cfg(feature = "serde")]
    #[test]
    fn serde_is_the_der_hex_string() {
        let signature = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));
        assert_eq!(
            serde_json::to_string(&signature).expect("a string"),
            format!("\"{signature}\"")
        );
    }

    #[test]
    fn a_compact_slice_is_measured_before_it_is_read() {
        let signature = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));
        let compact = signature.to_compact();

        assert_eq!(Signature::from_compact_slice(&compact), Ok(signature));
        assert_eq!(
            Signature::from_compact_slice(&compact[..63]),
            Err(SignatureError::WrongLength { got: 63 })
        );
        assert_eq!(
            Signature::from_compact_slice(&[]),
            Err(SignatureError::WrongLength { got: 0 })
        );

        // The compact hex of a real signature is not DER, and `from_hex` says
        // so rather than pretending.
        assert_eq!(
            Signature::from_hex(&hex::encode(&compact)),
            Err(SignatureError::Der)
        );
    }

    #[test]
    fn display_is_the_canonical_der() {
        let signature = sign(&[0x42; MESSAGE_SIZE], &scalar(0x11));
        assert_eq!(signature.to_string(), hex::encode(&signature.to_der()));
        assert_eq!(signature.to_string().parse(), Ok(signature));
    }
}
