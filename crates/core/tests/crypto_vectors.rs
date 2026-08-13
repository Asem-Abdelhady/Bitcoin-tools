//! § 7 against published vectors, which are its acceptance criteria.
//!
//! Two suites, and the second is the one that matters:
//!
//! - **RFC 6979** — seven key/message pairs whose signatures are fully
//!   determined. Signing is a pure function of the key and the hash, so a
//!   correct signer reproduces these byte for byte; a signer with a broken
//!   nonce still produces signatures that verify, and fails here.
//! - **Wycheproof** — Google's ECDSA suite, 476 cases over 109 keys, of which
//!   **308 must be refused**. Malformed DER, BER lengths, integers at the
//!   group order, edge-case hashes, and signatures that are simply wrong. A
//!   verifier that returns `true` unconditionally passes the first suite's
//!   verification half and fails 308 cases here.
//!
//! Every expectation comes from `bitcoin-tools-vectors`, never from a value
//! restated here.

use bitcoin_tools_core::crypto::ecdsa::{self, Signature};
use bitcoin_tools_core::crypto::secp::{Point, SecretScalar};
use bitcoin_tools_core::hashes::sha256;
use bitcoin_tools_core::hex;
use bitcoin_tools_vectors::{self as vectors, field};

/// Thirty-two bytes of hex, or a failure naming the vector.
fn bytes32(vector: &serde_json::Value, name: &str, at: &str) -> [u8; 32] {
    let decoded =
        hex::decode(field(vector, name, at)).unwrap_or_else(|e| panic!("{at}.{name}: {e}"));
    <[u8; 32]>::try_from(&decoded[..]).unwrap_or_else(|_| panic!("{at}.{name} is not 32 bytes"))
}

/// The signature a key and a hash determine, in both encodings, and the fact
/// that it verifies.
#[test]
fn rfc6979_signing_vectors() {
    let set = vectors::ecdsa();
    assert_eq!(set.len(), 7);

    for (i, vector) in set.iter().enumerate() {
        let at = format!("ecdsa[{i}]");
        let key = SecretScalar::from_be_bytes(&bytes32(vector, "privateKey", &at))
            .unwrap_or_else(|e| panic!("{at}: {e}"));

        // The hash is the vector's, but it is also checked rather than
        // trusted: SHA-256 of the message text has to be what the vector says
        // was signed, or the signature below would be about something else.
        let hash = bytes32(vector, "messageHash", &at);
        assert_eq!(
            sha256(field(vector, "message", &at).as_bytes()),
            hash,
            "{at}: the message and its hash disagree"
        );

        let signature = ecdsa::sign(&hash, &key);
        assert_eq!(
            hex::encode(&signature.to_compact()),
            field(vector, "compact", &at),
            "{at}: RFC 6979 fixes this signature exactly"
        );
        assert_eq!(hex::encode(&signature.r()), field(vector, "r", &at), "{at}");
        assert_eq!(hex::encode(&signature.s()), field(vector, "s", &at), "{at}");
        assert_eq!(
            hex::encode(&signature.to_der()),
            field(vector, "der", &at),
            "{at}"
        );

        // The public key the vector names is the one this secret derives, and
        // the signature verifies against it.
        let public = key.public_point();
        assert_eq!(
            hex::encode(&public.to_compressed()),
            field(vector, "publicKey", &at),
            "{at}"
        );
        assert!(ecdsa::verify(&hash, &signature, &public), "{at}");

        // Bitcoin's malleability rule: signing never produces the high form.
        assert!(signature.is_low_s(), "{at}");

        // Both parsers reach the same value.
        assert_eq!(
            Signature::from_hex(field(vector, "der", &at)),
            Ok(signature),
            "{at}"
        );
        let compact =
            hex::decode(field(vector, "compact", &at)).unwrap_or_else(|e| panic!("{at}: {e}"));
        assert_eq!(
            Signature::from_compact_slice(&compact),
            Ok(signature),
            "{at}"
        );
    }
}

/// The refusals. Each case is a public key, a message, a DER signature and a
/// verdict; a case counts as verified only if parsing *and* verification
/// succeed, which is where a lax DER parser shows up.
#[test]
fn wycheproof_verification_vectors() {
    let document = vectors::wycheproof_ecdsa();
    let groups = document["testGroups"].as_array().expect("test groups");
    let (mut accepted, mut refused) = (0u32, 0u32);

    for group in groups {
        let key = field(&group["publicKey"], "uncompressed", "a wycheproof group");
        let key = Point::from_sec1(&hex::decode(key).expect("valid hex"))
            .expect("wycheproof keys are points on the curve");

        for test in group["tests"].as_array().expect("tests") {
            let id = test["tcId"].as_u64().unwrap_or_default();
            let at = format!("wycheproof[{id}]");
            let expected = field(test, "result", &at) == "valid";

            // `msg` is the *message*; the suite signs its SHA-256. An empty
            // message is a real case here, and hashes like any other.
            let message =
                hex::decode(field(test, "msg", &at)).unwrap_or_else(|e| panic!("{at}: {e}"));
            let hash = sha256(&message);

            let verified = match hex::decode(field(test, "sig", &at)) {
                Ok(der) => match Signature::from_der(&der) {
                    Ok(signature) => ecdsa::verify(&hash, &signature, &key),
                    Err(_) => false,
                },
                Err(_) => false,
            };

            assert_eq!(
                verified,
                expected,
                "{at} ({}): expected {}, got {verified}",
                test["comment"].as_str().unwrap_or_default(),
                if expected { "valid" } else { "invalid" },
            );
            if expected {
                accepted += 1;
            } else {
                refused += 1;
            }
        }
    }

    assert_eq!(
        (accepted, refused),
        (168, 308),
        "the refusals are the half worth having"
    );
}

/// The suite's valid half is not all low-`s`, and that is the point of
/// verifying the arithmetic rather than the policy: 72 of its 168 valid
/// signatures would be refused by a verifier that folded Bitcoin's
/// malleability rule into `verify`.
#[test]
fn wycheproof_valid_signatures_include_the_high_s_form() {
    let document = vectors::wycheproof_ecdsa();
    let groups = document["testGroups"].as_array().expect("test groups");
    let (mut low, mut high) = (0u32, 0u32);

    for group in groups {
        for test in group["tests"].as_array().expect("tests") {
            if test["result"].as_str() != Some("valid") {
                continue;
            }
            let der = hex::decode(test["sig"].as_str().unwrap_or_default()).expect("valid hex");
            let signature = Signature::from_der(&der).expect("a valid case parses");
            if signature.is_low_s() {
                low += 1;
            } else {
                high += 1;
            }
        }
    }

    assert_eq!((low, high), (96, 72));
}
