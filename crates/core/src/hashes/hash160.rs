//! § 2.2 — HASH160, RIPEMD-160 of SHA-256.

use ripemd::{Digest, Ripemd160};

use super::sha256::sha256;

/// `RIPEMD160(SHA256(bytes))`.
///
/// The hash that shortens a key or a script to twenty bytes, which is most of
/// why a Bitcoin address is as short as it is. P2PKH and P2WPKH hash a public
/// key with it; P2SH hashes a redeem script.
///
/// Two functions rather than one because the second round is not about
/// strength: SHA-256 supplies that, and RIPEMD-160 truncates the result to a
/// size worth typing. The composition is what everything downstream expects,
/// so it is named once here rather than spelled out per caller.
///
/// **P2WSH is the exception people trip on.** A witness v0 script commitment
/// is a single `SHA256`, thirty-two bytes, not this — a 32-byte witness
/// program and a 20-byte one differ by which hash made them. See
/// [`sha256`](super::sha256()).
///
/// The result is in **internal (wire) order**, like every hash in this module.
/// A hash160 is not conventionally displayed reversed the way a txid is, but
/// stating the order is what keeps a caller from having to guess.
#[must_use]
pub fn hash160(bytes: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(bytes)).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// The worked example from the Bitcoin wiki's "Technical background of
    /// version 1 Bitcoin addresses", which publishes the intermediate SHA-256
    /// as well as the final hash — so this pins the composition and not just
    /// the answer. An implementation that applied the rounds in the other
    /// order, or skipped one, disagrees at a step this test can name.
    const PUBKEY: &str = "0450863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352\
                          2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6";
    const SHA256_OF_PUBKEY: &str =
        "600ffe422b4e00731a59557a5cca46cc183944191006324a447bdb2d98d4b408";
    const HASH160_OF_PUBKEY: &str = "010966776006953d5567439e5e39f86a0d273bee";

    #[test]
    fn matches_the_published_worked_example() {
        let pubkey = hex::decode(PUBKEY).unwrap();
        assert_eq!(hex::encode(&sha256(&pubkey)), SHA256_OF_PUBKEY);
        assert_eq!(hex::encode(&hash160(&pubkey)), HASH160_OF_PUBKEY);
    }

    /// Dropping the SHA-256 round still produces twenty plausible-looking
    /// bytes, so the difference is worth asserting rather than eyeballing.
    /// That the *composition* is right is settled by the vector above, which
    /// pins the published intermediate.
    #[test]
    fn is_not_bare_ripemd160_of_the_input() {
        let pubkey = hex::decode(PUBKEY).unwrap();
        let bare: [u8; 20] = Ripemd160::digest(&pubkey).into();
        assert_ne!(hash160(&pubkey), bare);
    }

    #[test]
    fn is_twenty_bytes_whatever_goes_in() {
        for input in [&b""[..], b"a", b"abc", &[0xff; 1000][..]] {
            assert_eq!(hash160(input).len(), 20);
        }
        // The empty input still has an answer — a hash is total.
        assert_eq!(
            hex::encode(&hash160(b"")),
            "b472a266d0bd89c13706a4132ccfb16f7c3b9fcb"
        );
    }
}
