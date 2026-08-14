//! HD wallets against the official vectors, which are their acceptance
//! criteria.
//!
//! Four suites, each testing something the others cannot:
//!
//! - **BIP39** — entropy ⇄ sentence ⇄ seed, over all 24 English vectors.
//! - **BIP32 valid** — 17 derivations across four seeds, both key types, in
//!   both directions.
//! - **BIP32 invalid** — 16 extended keys that must be *rejected*. A decoder
//!   that accepts everything passes the first two suites and fails this one,
//!   which is why it is the half worth having.
//! - **BIP49/84/86** — one mnemonic through three account layouts, ending at
//!   the addresses each standard publishes.
//!
//! Every expectation comes from `bitcoin-tools-vectors`, never from a value
//! restated here.

use bitcoin_tools_core::hd::{DerivationPath, Mnemonic, Purpose, Xpriv, Xpub};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::keys::{Address, PrivateKey, PublicKey};
use bitcoin_tools_core::network::Network;
use bitcoin_tools_vectors as vectors;
use bitcoin_tools_vectors::field;

/// BIP39 in both directions: entropy renders as the published sentence, and
/// the sentence reads back as the entropy. The seed is the one value that
/// cannot be checked by round-tripping, so it is checked against the vector.
#[test]
fn bip39_english_vectors() {
    let set = vectors::bip39();
    assert_eq!(set.len(), 24);

    for (i, vector) in set.iter().enumerate() {
        let at = format!("bip39[{i}]");
        let entropy = hex::decode(field(vector, "entropy", &at)).expect("valid hex");
        let sentence = field(vector, "mnemonic", &at);
        let passphrase = field(vector, "passphrase", &at);

        let from_entropy = Mnemonic::from_entropy(&entropy)
            .unwrap_or_else(|e| panic!("{at}: entropy rejected: {e}"));
        assert_eq!(from_entropy.to_phrase(), sentence, "{at}");

        let parsed =
            Mnemonic::parse(sentence).unwrap_or_else(|e| panic!("{at}: sentence rejected: {e}"));
        assert_eq!(parsed.entropy(), &entropy[..], "{at}");
        assert_eq!(parsed, from_entropy, "{at}");

        let seed = from_entropy.to_seed(passphrase);
        assert_eq!(hex::encode(&seed), field(vector, "seed", &at), "{at}");

        // …and the master key that seed produces, which is where BIP39 hands
        // over to BIP32.
        let master = Xpriv::new_master(&seed, Network::Mainnet)
            .unwrap_or_else(|e| panic!("{at}: master key: {e}"));
        assert_eq!(master.to_base58(), field(vector, "xprv", &at), "{at}");
    }
}

/// The four seeded BIP32 vectors, every chain, both key types.
///
/// Each chain is checked four ways: derived privately and serialized, derived
/// privately and converted to public, parsed back from both strings, and —
/// from the last hardened step onwards — derived from the *public* parent,
/// which is the property the whole standard exists for.
#[test]
fn bip32_derivation_vectors() {
    let set = vectors::bip32();
    let mut chains_checked = 0;
    let mut public_derivations = 0;

    for (i, vector) in set.iter().enumerate() {
        let at = format!("bip32[{i}]");
        let seed = hex::decode(field(vector, "seed", &at)).expect("valid hex");
        let master = Xpriv::new_master(&seed, Network::Mainnet)
            .unwrap_or_else(|e| panic!("{at}: master key: {e}"));

        for chain in vector["chains"].as_array().expect("chains is an array") {
            let path_text = field(chain, "path", &at);
            let at = format!("{at} {path_text}");
            let path: DerivationPath = path_text
                .parse()
                .unwrap_or_else(|e| panic!("{at}: path did not parse: {e}"));

            let xprv = master
                .derive_path(&path)
                .unwrap_or_else(|e| panic!("{at}: derivation failed: {e}"));
            let xpub = xprv.to_xpub();

            let expected_prv = field(chain, "xprv", &at);
            let expected_pub = field(chain, "xpub", &at);
            assert_eq!(xprv.to_base58(), expected_prv, "{at}");
            assert_eq!(xpub.to_string(), expected_pub, "{at}");

            // Reading the published strings back must give the same keys —
            // which also pins depth, parent fingerprint and child number,
            // since those are part of what was serialized.
            assert_eq!(Xpriv::parse(expected_prv).expect("parses"), xprv, "{at}");
            assert_eq!(Xpub::parse(expected_pub).expect("parses"), xpub, "{at}");
            assert_eq!(
                usize::from(xprv.depth()),
                path.depth(),
                "{at}: depth disagrees with the path"
            );

            // Everything after the last hardened step is derivable from a
            // public parent, and must land on the same key. Splitting there
            // rather than skipping any path with a hardened step is what makes
            // this cover the published set: all four vectors harden early, so
            // the "no hardened step anywhere" test would only ever exercise
            // `m` and `m/0`.
            let steps = path.as_slice();
            let split = steps
                .iter()
                .rposition(|step| step.is_hardened())
                .map_or(0, |last| last + 1);
            if split < steps.len() {
                let hardened_part =
                    DerivationPath::from_steps(&steps[..split]).expect("a prefix of a valid path");
                let normal_part =
                    DerivationPath::from_steps(&steps[split..]).expect("a suffix of a valid path");
                let from_public = master
                    .derive_path(&hardened_part)
                    .expect("the hardened prefix derives privately")
                    .to_xpub()
                    .derive_path(&normal_part)
                    .unwrap_or_else(|e| panic!("{at}: public derivation failed: {e}"));
                assert_eq!(from_public, xpub, "{at}");
                public_derivations += 1;
            }

            chains_checked += 1;
        }
    }

    assert_eq!(chains_checked, 17, "the published set is 17 derivations");
    assert_eq!(
        public_derivations, 6,
        "the published set has 6 chains with a non-hardened tail"
    );
}

/// The sixteen keys BIP32 says must be rejected.
///
/// Each is asserted to fail, and the reason string from the BIP is carried
/// through into the failure message — so a decoder that rejects the right
/// keys for the wrong reasons is at least visible.
#[test]
fn bip32_invalid_keys_are_rejected() {
    let set = vectors::bip32_invalid();
    assert_eq!(set.len(), 16);

    for (i, vector) in set.iter().enumerate() {
        let at = format!("bip32_invalid[{i}]");
        let key = field(vector, "key", &at);
        let reason = field(vector, "reason", &at);

        // Neither reading is allowed to succeed. Which of the two the BIP
        // meant is not stated per vector, and it does not matter: a string
        // that parses as *either* type has been accepted.
        let as_private = Xpriv::parse(key);
        let as_public = Xpub::parse(key);
        assert!(
            as_private.is_err(),
            "{at} ({reason}) parsed as an xprv: {as_private:?}"
        );
        assert!(
            as_public.is_err(),
            "{at} ({reason}) parsed as an xpub: {as_public:?}"
        );
    }
}

/// BIP49, BIP84 and BIP86 end to end: mnemonic, seed, master key, path, key,
/// address — the whole of what a wallet does when it shows you an address.
#[test]
fn account_vectors_for_every_purpose() {
    let set = vectors::accounts();
    let mut addresses_checked = 0;

    for (i, group) in set.iter().enumerate() {
        let at = format!("accounts[{i}]");
        let number = group["bip"].as_u64().unwrap_or_else(|| panic!("{at}: bip"));
        let purpose = Purpose::from_number(u32::try_from(number).expect("a small number"))
            .unwrap_or_else(|| panic!("{at}: {number} is not a purpose"));
        let network: Network = field(group, "network", &at)
            .parse()
            .unwrap_or_else(|e| panic!("{at}: network: {e}"));

        let mnemonic = Mnemonic::parse(field(group, "mnemonic", &at))
            .unwrap_or_else(|e| panic!("{at}: mnemonic: {e}"));
        let seed = mnemonic.to_seed(field(group, "passphrase", &at));
        let master =
            Xpriv::new_master(&seed, network).unwrap_or_else(|e| panic!("{at}: master key: {e}"));

        // The root and account keys, where the standard publishes them.
        // BIP49 and BIP84 write theirs in SLIP-132 (`uprv`, `zprv`), which
        // this crate deliberately does not read — see `hd/mod.rs`. Their
        // addresses below are the stronger assertion anyway.
        if let Some(expected) = group["rootXprv"].as_str() {
            assert_eq!(master.to_base58(), expected, "{at}: root xprv");
        }
        if let Some(expected) = group["rootXpub"].as_str() {
            assert_eq!(master.to_xpub().to_string(), expected, "{at}: root xpub");
        }

        let account_path: DerivationPath = field(group, "accountPath", &at)
            .parse()
            .unwrap_or_else(|e| panic!("{at}: account path: {e}"));
        assert_eq!(
            account_path,
            purpose
                .account_path(network, 0)
                .unwrap_or_else(|| panic!("{at}: account 0 is in range")),
            "{at}: the published account path is not the one this crate builds"
        );

        let account = master
            .derive_path(&account_path)
            .unwrap_or_else(|e| panic!("{at}: account: {e}"));
        if let Some(expected) = group["accountXprv"].as_str() {
            assert_eq!(account.to_base58(), expected, "{at}: account xprv");
        }
        if let Some(expected) = group["accountXpub"].as_str() {
            assert_eq!(
                account.to_xpub().to_string(),
                expected,
                "{at}: account xpub"
            );
        }

        for entry in group["addresses"].as_array().expect("an array") {
            let path_text = field(entry, "path", &at);
            let at = format!("{at} {path_text}");
            let path: DerivationPath = path_text
                .parse()
                .unwrap_or_else(|e| panic!("{at}: path: {e}"));

            let xprv = master
                .derive_path(&path)
                .unwrap_or_else(|e| panic!("{at}: derivation: {e}"));
            let key = xprv.private_key();
            let public = key.public_key();

            if let Some(expected) = entry["xprv"].as_str() {
                assert_eq!(xprv.to_base58(), expected, "{at}");
            }
            if let Some(expected) = entry["xpub"].as_str() {
                assert_eq!(xprv.to_xpub().to_string(), expected, "{at}");
            }
            if let Some(expected) = entry["wif"].as_str() {
                assert_eq!(key.to_wif(), expected, "{at}");
                // …and the WIF reads back as the same key, network and all.
                let reparsed = PrivateKey::from_wif(expected).expect("a valid WIF");
                assert_eq!(reparsed.to_be_bytes(), key.to_be_bytes(), "{at}");
            }
            if let Some(expected) = entry["privateKey"].as_str() {
                assert_eq!(hex::encode(&key.to_be_bytes()), expected, "{at}");
            }
            if let Some(expected) = entry["publicKey"].as_str() {
                assert_eq!(hex::encode(&public.to_bytes()), expected, "{at}");
                // The published key is the one this derivation produced, so
                // reading it back must give the same address below.
                assert_eq!(
                    PublicKey::from_hex(expected).expect("a valid key"),
                    public,
                    "{at}"
                );
            }
            if let Some(expected) = entry["pubkeyHash"].as_str() {
                assert_eq!(public.pubkey_hash().to_hex(), expected, "{at}");
            }
            if let Some(expected) = entry["redeemScript"].as_str() {
                let redeem = public
                    .p2wpkh_redeem_script()
                    .unwrap_or_else(|e| panic!("{at}: redeem script: {e}"));
                assert_eq!(hex::encode(&redeem), expected, "{at}");
            }
            if let Some(expected) = entry["internalKey"].as_str() {
                assert_eq!(hex::encode(&public.to_x_only()), expected, "{at}");
            }
            if let Some(expected) = entry["outputKey"].as_str() {
                let output = public
                    .taproot_output_key()
                    .unwrap_or_else(|e| panic!("{at}: taproot tweak: {e}"));
                assert_eq!(hex::encode(&output), expected, "{at}");
            }

            // The address, by the purpose rather than by hand — which is what
            // makes this a test of `Purpose` and not of four constructors.
            let address = purpose
                .address(&public, network)
                .unwrap_or_else(|e| panic!("{at}: address: {e}"));
            let expected = field(entry, "address", &at);
            assert_eq!(address.to_string(), expected, "{at}");
            assert_eq!(address.kind(), Some(purpose.address_kind()), "{at}");

            // …and it reads back, which pins the checksum in whichever
            // encoding this purpose uses.
            let reparsed: Address = expected
                .parse()
                .unwrap_or_else(|e| panic!("{at}: address did not parse back: {e}"));
            assert_eq!(reparsed, address, "{at}");

            if let Some(expected) = entry["scriptPubkey"].as_str() {
                assert_eq!(hex::encode(&address.script_pubkey()), expected, "{at}");
            }
            if let Some(expected) = entry["scriptHash"].as_str() {
                let base58 = address
                    .as_base58()
                    .unwrap_or_else(|| panic!("{at}: a script hash means a base58 address"));
                assert_eq!(base58.hash().to_hex(), expected, "{at}");
            }

            addresses_checked += 1;
        }
    }

    assert_eq!(
        addresses_checked, 7,
        "the three standards publish 7 addresses between them"
    );
}
