//! § 2.3 — SHA-256.

use sha2::{Digest, Sha256};

/// SHA-256 of `bytes`.
///
/// A single round, which Bitcoin uses in fewer places than the double form but
/// in load-bearing ones: the P2WSH witness program commits to its script with
/// exactly this, BIP143 sighash midstates are built from it, and BIP340 tagged
/// hashes are `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
///
/// Where a *double* round is wanted — transaction ids, block hashes, merkle
/// nodes, Base58Check — reach for [`hash256`](super::hash256()) rather than
/// composing this twice by hand.
///
/// ```
/// use bitcoin_tools_core::{hashes::sha256, hex};
///
/// // A P2WSH scriptPubKey commits to its witness script with one round —
/// // 32 bytes, where the 20-byte programs of P2PKH and P2WPKH use HASH160.
/// assert_eq!(sha256(b"abc").len(), 32);
/// assert_eq!(
///     hex::encode(&sha256(b"abc")),
///     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
/// );
/// ```
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn matches_the_published_vectors() {
        // FIPS 180-2 / NIST examples.
        assert_eq!(
            hex::encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(&sha256(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }
}
