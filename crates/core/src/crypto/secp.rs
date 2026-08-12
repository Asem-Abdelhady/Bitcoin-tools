//! The one place this crate touches secp256k1.
//!
//! Everything here is curve arithmetic and nothing here is Bitcoin. A scalar
//! is a number below the group order; a point is a point. How a point gets
//! serialized into 33 bytes with an `02`/`03` prefix, and which network's
//! address it turns into, is [`keys`](crate::keys)' business one layer up.
//!
//! # What this module does not do
//!
//! Secrets are kept off `Debug`, off `Display` and out of serde, but they are
//! **not zeroed on drop**. [`SecretScalar::to_be_bytes`] hands out a copy, and
//! neither it nor the buffer inside is wiped. Doing that properly means a
//! `zeroize` dependency and `Drop` impls, and it only buys anything against an
//! attacker reading freed memory — a threat this crate, which decodes data a
//! user pasted, is not otherwise defending against. It is a deliberate
//! omission rather than an oversight, and the decision to revisit belongs with
//! whoever adds signing.
//!
//! Keeping the backend behind this module is what makes it replaceable: the
//! `secp256k1` crate wraps Bitcoin Core's libsecp256k1, which is constant-time
//! and is what actually validates the chain, but it is C, so a wasm build
//! would need a pure-Rust backend swapped in here and nowhere else.

use std::fmt;
use std::sync::OnceLock;

use secp256k1::{PublicKey as BackendPublic, Secp256k1, SecretKey as BackendSecret, SignOnly};

/// Bytes in a secret scalar, and in each coordinate of a point.
pub const SCALAR_SIZE: usize = 32;

/// Bytes in a compressed SEC1 point: a parity prefix and `x`.
pub const COMPRESSED_SIZE: usize = 1 + SCALAR_SIZE;

/// Bytes in an uncompressed SEC1 point: an `04` prefix, `x`, and `y`.
pub const UNCOMPRESSED_SIZE: usize = 1 + 2 * SCALAR_SIZE;

/// The order of the secp256k1 group, big-endian.
///
/// A valid secret is in `1..n`. Both ends matter and neither is caught by "is
/// it 32 bytes": zero has no inverse and is not a key, and anything at or
/// above `n` is congruent to a smaller scalar, so accepting it would let two
/// different 32-byte strings be the same key.
pub const GROUP_ORDER: [u8; SCALAR_SIZE] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// Why a 32-byte string is not a valid secret scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScalarError {
    /// Zero is not a key. It has no multiplicative inverse, and `0 * G` is the
    /// point at infinity rather than a public key.
    Zero,
    /// At or above [`GROUP_ORDER`]. Such a value is congruent to `x - n`, so
    /// allowing it would give one key two spellings.
    NotBelowGroupOrder,
}

impl fmt::Display for ScalarError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScalarError::Zero => f.write_str("a secret scalar cannot be zero"),
            ScalarError::NotBelowGroupOrder => {
                f.write_str("a secret scalar must be below the secp256k1 group order")
            }
        }
    }
}

impl std::error::Error for ScalarError {}

/// A secret scalar: a number in `1..n`, checked on the way in.
///
/// Deliberately not `Copy`, `Display` or `Debug`-revealing — see the manual
/// [`fmt::Debug`] impl. Making a secret easy to print by accident is how
/// secrets end up in logs.
#[derive(Clone)]
pub struct SecretScalar(BackendSecret);

impl SecretScalar {
    /// Validate 32 big-endian bytes as a scalar.
    ///
    /// # Errors
    ///
    /// [`ScalarError`] if the value is zero or not below [`GROUP_ORDER`].
    pub fn from_be_bytes(bytes: &[u8; SCALAR_SIZE]) -> Result<Self, ScalarError> {
        // The backend rejects both out-of-range cases, but collapses them into
        // one error. Distinguishing them is worth the two comparisons: "your
        // key is zero" and "your key is too large" are different mistakes.
        if bytes.iter().all(|&b| b == 0) {
            return Err(ScalarError::Zero);
        }
        if bytes[..] >= GROUP_ORDER[..] {
            return Err(ScalarError::NotBelowGroupOrder);
        }
        BackendSecret::from_byte_array(*bytes)
            .map(SecretScalar)
            .map_err(|_| ScalarError::NotBelowGroupOrder)
    }

    /// The scalar as 32 big-endian bytes.
    #[must_use]
    pub fn to_be_bytes(&self) -> [u8; SCALAR_SIZE] {
        self.0.secret_bytes()
    }

    /// The point `self * G`.
    #[must_use]
    pub fn public_point(&self) -> Point {
        Point(BackendPublic::from_secret_key(context(), &self.0))
    }
}

/// The one libsecp256k1 context, built on first use.
///
/// Built once rather than per call for two reasons, the second of which is the
/// durable one. It is an allocation and a callback setup each time — not a
/// table build, since `secp256k1-sys` vendors the precomputed multiples of `G`
/// as static data. More importantly, if anything anywhere in the dependency
/// graph enables `secp256k1/rand`, cargo's feature unification turns context
/// construction into a *randomized* one, and this crate would then be
/// re-randomizing on every single key derivation without having asked for it.
///
/// `signing_only` rather than `new`: deriving a point is all this crate asks
/// for today, and stating the narrower capability means a future verification
/// path has to say so rather than inheriting it.
fn context() -> &'static Secp256k1<SignOnly> {
    static CTX: OnceLock<Secp256k1<SignOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::signing_only)
}

/// Prints nothing about the value. A secret that shows up in a log because
/// some struct three layers up derived `Debug` is a real way keys get lost.
impl fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretScalar(<redacted>)")
    }
}

impl PartialEq for SecretScalar {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for SecretScalar {}

/// A point on the curve — a public key before anyone has decided how to
/// serialize it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Point(BackendPublic);

impl Point {
    /// Read a point from its SEC1 encoding: 33 bytes prefixed `02`/`03`, or 65
    /// prefixed `04`.
    ///
    /// The hybrid encodings — prefix `06` and `07`, which carry `y` in full
    /// *and* its parity — are rejected rather than accepted. The backend
    /// parses them, but this type cannot reproduce them: it would hand back
    /// `04…` bytes, so a caller hashing the result would get the hash of bytes
    /// they never supplied, and therefore the wrong address.
    ///
    /// # Errors
    ///
    /// [`PointError::UnsupportedPrefix`] for a hybrid or unrecognised prefix,
    /// [`PointError::NotOnCurve`] for the wrong length or an `x` with no `y`.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, PointError> {
        match bytes.first() {
            // 0x02 and 0x03 compressed, 0x04 uncompressed — the three this
            // type can serialize back.
            Some(0x02..=0x04) => {}
            Some(&prefix) => return Err(PointError::UnsupportedPrefix { prefix }),
            None => return Err(PointError::NotOnCurve),
        }
        BackendPublic::from_slice(bytes)
            .map(Point)
            .map_err(|_| PointError::NotOnCurve)
    }

    /// 33 bytes: `02` or `03` by the parity of `y`, then `x`.
    ///
    /// The prefix is what makes this recoverable — for a given `x` there are
    /// two `y` values, one even and one odd, so one bit names which.
    #[must_use]
    pub fn to_compressed(self) -> [u8; COMPRESSED_SIZE] {
        self.0.serialize()
    }

    /// 65 bytes: `04`, then `x`, then `y`, both in full.
    #[must_use]
    pub fn to_uncompressed(self) -> [u8; UNCOMPRESSED_SIZE] {
        self.0.serialize_uncompressed()
    }

    /// The `x` coordinate alone, 32 bytes — BIP340's encoding, used by
    /// taproot, where `y` is defined to be the even one.
    #[must_use]
    pub fn to_x_only(self) -> [u8; SCALAR_SIZE] {
        let mut x = [0u8; SCALAR_SIZE];
        x.copy_from_slice(&self.to_compressed()[1..]);
        x
    }

    /// Both coordinates, as a tools library should be able to show them.
    #[must_use]
    pub fn coordinates(self) -> ([u8; SCALAR_SIZE], [u8; SCALAR_SIZE]) {
        let full = self.to_uncompressed();
        let mut x = [0u8; SCALAR_SIZE];
        let mut y = [0u8; SCALAR_SIZE];
        x.copy_from_slice(&full[1..33]);
        y.copy_from_slice(&full[33..]);
        (x, y)
    }
}

/// A byte string was not a point on the curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PointError {
    /// Not a valid SEC1 encoding of a curve point: wrong length, or an `x` for
    /// which no `y` exists.
    NotOnCurve,
    /// A prefix byte this crate does not serialize. `06`/`07` are the hybrid
    /// forms — real, and parseable, but not reproducible from what this type
    /// stores, so accepting one would change the bytes under the caller.
    UnsupportedPrefix {
        /// The prefix byte that was refused.
        prefix: u8,
    },
}

impl fmt::Display for PointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PointError::NotOnCurve => f.write_str("not a point on the secp256k1 curve"),
            PointError::UnsupportedPrefix { prefix } => write!(
                f,
                "{prefix:#04x} is not a public key prefix this crate can reproduce"
            ),
        }
    }
}

impl std::error::Error for PointError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    fn scalar(hex_str: &str) -> Result<SecretScalar, ScalarError> {
        let bytes = hex::decode(hex_str).unwrap();
        let mut array = [0u8; SCALAR_SIZE];
        array.copy_from_slice(&bytes);
        SecretScalar::from_be_bytes(&array)
    }

    /// `1 * G` is the generator, whose coordinates are the most published
    /// numbers in the protocol.
    #[test]
    fn one_times_g_is_the_generator() {
        let one = scalar("0000000000000000000000000000000000000000000000000000000000000001")
            .expect("1 is a valid scalar");
        let point = one.public_point();

        assert_eq!(
            hex::encode(&point.to_compressed()),
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(
            hex::encode(&point.to_uncompressed()),
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\
             483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
        assert_eq!(
            hex::encode(&point.to_x_only()),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );

        let (x, y) = point.coordinates();
        assert_eq!(
            hex::encode(&x),
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
        );
        assert_eq!(
            hex::encode(&y),
            "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
        );
    }

    /// The prefix names the parity of `y`, so it must follow the point rather
    /// than being a constant.
    #[test]
    fn the_compressed_prefix_tracks_the_parity_of_y() {
        for i in 1..=8u8 {
            let mut bytes = [0u8; SCALAR_SIZE];
            bytes[31] = i;
            let point = SecretScalar::from_be_bytes(&bytes).unwrap().public_point();
            let (_, y) = point.coordinates();
            let expected = if y[31] % 2 == 0 { 0x02 } else { 0x03 };
            assert_eq!(
                point.to_compressed()[0],
                expected,
                "{i} * G: prefix disagrees with the parity of y"
            );
            // Uncompressed always starts 0x04, whatever the parity.
            assert_eq!(point.to_uncompressed()[0], 0x04);
        }
    }

    #[test]
    fn rejects_the_two_scalars_that_are_not_keys() {
        assert_eq!(
            scalar("0000000000000000000000000000000000000000000000000000000000000000"),
            Err(ScalarError::Zero)
        );
        // Exactly the group order, and one above it.
        assert_eq!(
            scalar("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
            Err(ScalarError::NotBelowGroupOrder)
        );
        assert_eq!(
            scalar("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"),
            Err(ScalarError::NotBelowGroupOrder)
        );
        assert_eq!(
            scalar("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            Err(ScalarError::NotBelowGroupOrder)
        );
        // One below the order is the largest valid key.
        assert!(scalar("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140").is_ok());
    }

    #[test]
    fn scalars_round_trip_through_bytes() {
        let text = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let s = scalar(text).unwrap();
        assert_eq!(hex::encode(&s.to_be_bytes()), text);
    }

    #[test]
    fn points_round_trip_through_both_encodings() {
        let s = scalar("0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d").unwrap();
        let point = s.public_point();
        assert_eq!(Point::from_sec1(&point.to_compressed()).unwrap(), point);
        assert_eq!(Point::from_sec1(&point.to_uncompressed()).unwrap(), point);
    }

    #[test]
    fn rejects_bytes_that_are_not_a_point() {
        // An `x` above the field prime, so no point can have it. (Small `x`
        // values are a bad test: `x = 1` gives `y² = 8`, which does have a
        // root, so `021111…01` is a perfectly good public key.)
        let mut too_large = [0xffu8; 33];
        too_large[0] = 0x02;
        assert_eq!(Point::from_sec1(&too_large), Err(PointError::NotOnCurve));

        // Empty, an unknown prefix, and lengths that disagree with their
        // prefix.
        assert_eq!(Point::from_sec1(&[]), Err(PointError::NotOnCurve));
        assert_eq!(
            Point::from_sec1(&[0x05; 33]),
            Err(PointError::UnsupportedPrefix { prefix: 0x05 })
        );
        assert_eq!(Point::from_sec1(&[0x04; 33]), Err(PointError::NotOnCurve));
        assert_eq!(Point::from_sec1(&[0x02; 65]), Err(PointError::NotOnCurve));

        // An uncompressed encoding whose `y` does not satisfy the curve
        // equation for its `x`: take a real point and flip the last byte.
        let real = scalar("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
            .public_point();
        let mut tampered = real.to_uncompressed();
        tampered[64] ^= 0x01;
        assert_eq!(Point::from_sec1(&tampered), Err(PointError::NotOnCurve));
    }

    /// The hybrid encodings are real, and the backend parses them — but this
    /// type would hand back `04…`, so a caller hashing the result would hash
    /// bytes they never supplied and land on a different address. Rejecting is
    /// the only answer that cannot be silently wrong.
    #[test]
    fn hybrid_encodings_are_refused_rather_than_renormalised() {
        let point = scalar("0000000000000000000000000000000000000000000000000000000000000001")
            .unwrap()
            .public_point();
        let (_, y) = point.coordinates();

        for prefix in [0x06u8, 0x07] {
            let mut hybrid = point.to_uncompressed();
            hybrid[0] = prefix;
            assert_eq!(
                Point::from_sec1(&hybrid),
                Err(PointError::UnsupportedPrefix { prefix }),
                "{prefix:#04x} must not be quietly rewritten to 0x04"
            );
        }
        // The parity byte 0x06/0x07 encodes is the one the compressed form
        // carries, which is why the backend can read them at all.
        let expected_parity = if y[31] % 2 == 0 { 0x06 } else { 0x07 };
        let mut hybrid = point.to_uncompressed();
        hybrid[0] = expected_parity;
        assert!(Point::from_sec1(&hybrid).is_err());
    }

    /// A secret must not be printable by accident.
    #[test]
    fn debug_does_not_leak_the_secret() {
        let text = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d";
        let s = scalar(text).unwrap();
        let shown = format!("{s:?}");
        assert!(!shown.contains("0c28"), "Debug leaked the scalar: {shown}");
        assert_eq!(shown, "SecretScalar(<redacted>)");
    }
}
