//! § 2.1 — HASH256, Bitcoin's double SHA-256.

use super::sha256::sha256;

/// `SHA256(SHA256(bytes))`.
///
/// The hash behind transaction ids, block hashes, merkle nodes and the
/// four-byte Base58Check checksum. Satoshi used two rounds as a hedge against
/// length-extension attacks on the single round.
///
/// The result is in **internal (wire) order**. Bitcoin displays these
/// reversed; that is the displaying type's job, not this function's — see
/// [`hex::write_rev`](crate::hex::write_rev).
///
/// ```
/// use bitcoin_tools_core::{hashes::hash256, hex};
///
/// let digest = hash256(b"abc");
/// // What the function returns is wire order…
/// assert_eq!(
///     hex::encode(&digest),
///     "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
/// );
/// // …and an explorer would print the same bytes the other way round.
/// assert_eq!(
///     hex::encode_rev(&digest),
///     "58636c3ec08c12d55aedda056d602d5bcca72d8df6a69b519b72d32dc2428b4f"
/// );
/// ```
#[must_use]
pub fn hash256(bytes: &[u8]) -> [u8; 32] {
    sha256(&sha256(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn is_sha256_applied_twice() {
        assert_eq!(hash256(b"hello"), sha256(&sha256(b"hello")));
    }

    #[test]
    fn reproduces_the_genesis_coinbase_txid() {
        // The genesis block's single transaction. Its txid is the most
        // widely published HASH256 output there is, which makes it a better
        // vector than anything restated from the implementation.
        let raw = hex::decode(
            "01000000010000000000000000000000000000000000000000000000000000000000\
             000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32\
             303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e6420\
             6261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678\
             afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f\
             4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000",
        )
        .unwrap();

        let mut displayed = String::new();
        hex::write_rev(&mut displayed, &hash256(&raw)).unwrap();
        assert_eq!(
            displayed,
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
    }
}
