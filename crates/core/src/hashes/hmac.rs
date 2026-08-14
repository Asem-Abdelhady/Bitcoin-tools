//! HMAC-SHA512 and PBKDF2 — the two constructions BIP32 and BIP39 need.
//!
//! Neither is a Bitcoin invention and neither is interesting on its own. They
//! are here because BIP32 defines every step of key derivation as an
//! HMAC-SHA512, and BIP39 defines a seed as 2048 rounds of PBKDF2 over one.
//!
//! Written rather than taken from `hmac` and `pbkdf2`, for the same reason
//! [`base58`](crate::encoding::base58) is written rather than taken from
//! `bs58`: those crates are generic over RustCrypto's `digest` traits, and
//! pinning two more crates to the exact `digest` major version `sha2` uses —
//! see the note about `ripemd` in the README — buys nothing here. HMAC is
//! twenty lines of specification and the PBKDF2 this crate needs is ten more.
//! Both are pinned to published vectors below.

use sha2::{Digest, Sha512};

/// Bytes of output from SHA-512, and so from [`hmac_sha512`].
pub const SHA512_SIZE: usize = 64;

/// SHA-512's internal block size, which is the width HMAC pads its key to.
const BLOCK_SIZE: usize = 128;

/// HMAC-SHA512 of `data` under `key`.
///
/// `HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))`, where `K'` is the key
/// padded to the hash's block size — or, if the key is longer than a block,
/// the hash of the key padded the same way.
///
/// The key length is unrestricted, which matters: BIP32 keys the outer
/// derivation with the fixed string `"Bitcoin seed"` and every step below it
/// with a 32-byte chain code, and both go through here unchanged.
///
/// ```
/// use bitcoin_tools_core::{hashes::hmac_sha512, hex};
///
/// // RFC 4231 test case 1.
/// let mac = hmac_sha512(&[0x0b; 20], b"Hi There");
/// assert!(hex::encode(&mac).starts_with("87aa7cdea5ef619d4ff0b4241a1d6cb0"));
/// ```
#[must_use]
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; SHA512_SIZE] {
    // A key longer than a block is replaced by its own hash. Note this makes
    // those two keys equivalent — that is HMAC's rule, not a shortcut here.
    let mut padded = [0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let digest: [u8; SHA512_SIZE] = Sha512::digest(key).into();
        padded[..SHA512_SIZE].copy_from_slice(&digest);
    } else {
        padded[..key.len()].copy_from_slice(key);
    }

    let mut inner = Sha512::new();
    let mut outer = Sha512::new();
    // One pass over the padded key, feeding both halves of the construction.
    let mut ipad = [0u8; BLOCK_SIZE];
    let mut opad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        ipad[i] = padded[i] ^ 0x36;
        opad[i] = padded[i] ^ 0x5c;
    }
    inner.update(ipad);
    inner.update(data);
    outer.update(opad);
    outer.update(inner.finalize());
    outer.finalize().into()
}

/// PBKDF2-HMAC-SHA512, producing exactly one hash block.
///
/// # The output length is fixed at [`SHA512_SIZE`]
///
/// PBKDF2 in general produces any length by concatenating blocks `T(1)`,
/// `T(2)`, … and truncating. BIP39 asks for 512 bits, which is exactly one
/// SHA-512 block, so the block loop would have exactly one iteration for the
/// only caller this crate has. Writing it as one block makes the function
/// total — no length argument to get wrong, no `Vec`, no error — and adding
/// the outer loop later is additive.
///
/// `rounds` is `u32` and *not* checked for zero: zero rounds returns
/// `PRF(password, salt || 0x00000001)`, which is the first `U` value and is
/// exactly what the definition degenerates to. It is a bad choice for a KDF,
/// but it is not this function's place to refuse; BIP39's 2048 is a constant
/// in [`Mnemonic::to_seed`](crate::hd::Mnemonic::to_seed), where the number
/// actually belongs.
#[must_use]
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], rounds: u32) -> [u8; SHA512_SIZE] {
    // U(1) = PRF(P, S || INT_32_BE(1)). The block index is 1 because there is
    // one block; a general implementation would loop it.
    let mut salted = Vec::with_capacity(salt.len() + 4);
    salted.extend_from_slice(salt);
    salted.extend_from_slice(&1u32.to_be_bytes());

    let mut u = hmac_sha512(password, &salted);
    let mut out = u;
    // T = U(1) ^ U(2) ^ … ^ U(c), where U(i) = PRF(P, U(i-1)).
    for _ in 1..rounds {
        u = hmac_sha512(password, &u);
        for (acc, byte) in out.iter_mut().zip(u.iter()) {
            *acc ^= byte;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    /// RFC 4231, the published HMAC-SHA-512 vectors. Case 2 is the one worth
    /// having: a short key and a short message, where an implementation that
    /// padded wrongly still produces plausible bytes.
    #[test]
    fn matches_the_rfc_4231_vectors() {
        for (key, data, expected) in [
            (
                vec![0x0b; 20],
                b"Hi There".to_vec(),
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                 daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?".to_vec(),
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
            ),
            (
                vec![0xaa; 20],
                vec![0xdd; 50],
                "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39\
                 bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb",
            ),
            // A key longer than the 128-byte block, so the "hash the key
            // first" branch is covered rather than assumed.
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
                "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
                 6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
            ),
        ] {
            assert_eq!(
                hex::encode(&hmac_sha512(&key, &data)),
                expected.replace(char::is_whitespace, "")
            );
        }
    }

    /// A key exactly one block long, and one byte longer. The two must differ,
    /// because the second is hashed before padding and the first is not — an
    /// off-by-one in that comparison is invisible against any single vector.
    #[test]
    fn the_block_size_boundary_is_where_hashing_the_key_starts() {
        let at = hmac_sha512(&[0x42; BLOCK_SIZE], b"m");
        let over = hmac_sha512(&[0x42; BLOCK_SIZE + 1], b"m");
        assert_ne!(at, over);
        // …and a key past the boundary equals its own hash used as the key.
        let long = [0x42u8; BLOCK_SIZE + 1];
        let digest: [u8; SHA512_SIZE] = Sha512::digest(long).into();
        assert_eq!(over, hmac_sha512(&digest, b"m"));
    }

    /// The published PBKDF2-HMAC-SHA512 vectors, truncated to the one block
    /// this function produces.
    #[test]
    fn matches_the_published_pbkdf2_vectors() {
        for (password, salt, rounds, expected) in [
            (
                "password",
                "salt",
                1u32,
                "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252",
            ),
            (
                "password",
                "salt",
                2,
                "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c",
            ),
            (
                "password",
                "salt",
                4096,
                "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5",
            ),
        ] {
            let out = pbkdf2_hmac_sha512(password.as_bytes(), salt.as_bytes(), rounds);
            assert_eq!(hex::encode(&out[..32]), expected, "{rounds} rounds");
        }
    }

    /// Every round has to fold into the answer, or a KDF is a single HMAC
    /// wearing a cost parameter.
    #[test]
    fn each_round_changes_the_result() {
        let mut seen = std::collections::HashSet::new();
        for rounds in 1..8u32 {
            assert!(
                seen.insert(pbkdf2_hmac_sha512(b"p", b"s", rounds)),
                "{rounds} rounds produced a repeat"
            );
        }
        // Zero rounds is the degenerate case the doc names: the loop body
        // never runs, leaving U(1).
        assert_eq!(
            pbkdf2_hmac_sha512(b"p", b"s", 0),
            pbkdf2_hmac_sha512(b"p", b"s", 1)
        );
    }
}
