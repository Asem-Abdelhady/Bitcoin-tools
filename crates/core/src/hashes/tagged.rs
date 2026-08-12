//! BIP340 tagged hashes.

use super::sha256::sha256;

/// `SHA256(SHA256(tag) || SHA256(tag) || msg)`.
///
/// The point is domain separation. Taproot hashes several different things
/// with SHA-256 — a tweak, a leaf, a branch, a signature challenge — and
/// without a tag a value valid in one role could be replayed in another.
/// Prefixing with the tag's *hash*, twice, is what makes the prefix a fixed
/// 64 bytes: exactly one SHA-256 block, so an implementation can precompute
/// the midstate. This one does not bother, because it is called once per
/// address rather than once per signature check.
///
/// The tag is the spelling from the BIP — `"TapTweak"`, `"TapLeaf"`,
/// `"TapBranch"`, `"BIP0340/challenge"` — and is part of the protocol, so it
/// is passed in rather than guessed at.
///
/// ```
/// use bitcoin_tools_core::{hashes::{sha256, tagged_sha256}, hex};
///
/// // The definition, spelled out: two copies of the tag's hash, then the
/// // message.
/// let tag = sha256(b"TapTweak");
/// let mut expanded = Vec::new();
/// expanded.extend_from_slice(&tag);
/// expanded.extend_from_slice(&tag);
/// expanded.extend_from_slice(b"hello");
/// assert_eq!(tagged_sha256("TapTweak", b"hello"), sha256(&expanded));
/// ```
#[must_use]
pub fn tagged_sha256(tag: &str, msg: &[u8]) -> [u8; 32] {
    let tag_hash = sha256(tag.as_bytes());
    let mut buf = Vec::with_capacity(2 * tag_hash.len() + msg.len());
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(msg);
    sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// The tag is what separates the domains, so two tags over one message
    /// must not collide — and neither may equal the untagged hash.
    #[test]
    fn the_tag_separates_the_domains() {
        let leaf = tagged_sha256("TapLeaf", b"x");
        let branch = tagged_sha256("TapBranch", b"x");
        assert_ne!(leaf, branch);
        assert_ne!(leaf, sha256(b"x"));
    }

    /// The prefix is two 32-byte hashes, so an empty message still hashes 64
    /// bytes. Pinned against a value computed from the definition, so a
    /// transcription slip in the doubling is caught.
    #[test]
    fn hashes_the_tag_twice() {
        let tag = sha256(b"TapTweak");
        let mut expanded = tag.to_vec();
        expanded.extend_from_slice(&tag);
        assert_eq!(tagged_sha256("TapTweak", b""), sha256(&expanded));
        assert_eq!(hex::encode(&tagged_sha256("TapTweak", b"")).len(), 64);
    }
}
