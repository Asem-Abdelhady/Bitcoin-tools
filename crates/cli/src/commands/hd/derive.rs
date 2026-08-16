//! `hd derive` — walk a path from a seed.

use std::fmt;
use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use bitcoin_tools_core::hd::path::MAX_INDEX;
use bitcoin_tools_core::hd::xkey::MAX_SEED_SIZE;
use bitcoin_tools_core::hd::{Bip32Error, ChildNumber, DerivationPath, Purpose, Xpriv};
use bitcoin_tools_core::hex;
use bitcoin_tools_core::network::Network;

use crate::commands::address::AddressesView;
use crate::commands::hd::ExtendedKeyView;
use crate::commands::keys::default_network;
use crate::input::{self, InputError};
use crate::output::{Context, Fields, Output};

/// The noun this command's errors use.
const SUBJECT: &str = "seed";

/// How many children one request may ask for.
///
/// The same cap the HTTP API sets. It is a policy rather than a limit of the
/// algorithm — deriving is cheap — but a hundred keys is already more output
/// than anyone reads, and each one carries a private key.
const MAX_COUNT: u32 = 100;

/// How many children a request with no opinion gets.
const fn default_count() -> u32 {
    1
}

/// What `hd derive` accepts.
///
/// The seed names a file, for the reason [the group note](super) gives. The path
/// is not a secret and is an ordinary flag — but it is *required*, because there
/// is no sensible default branch: `m` and `m/84'/0'/0'/0` are different wallets.
#[derive(Debug, clap::Args)]
#[command(
    override_usage = "bitcoin-tools hd derive --seed-file <FILE> --path <PATH> \
                            [--count <N>] [--start-index <N>]\n\
                          \x20      bitcoin-tools hd derive --input <FILE>"
)]
pub struct Args {
    /// A file holding the seed as 32–128 hex digits, or `-` for stdin.
    ///
    /// There is deliberately no flag that takes the seed itself — it is the
    /// whole wallet.
    #[arg(long, value_name = "FILE", required_unless_present = "input")]
    seed_file: Option<PathBuf>,

    /// The branch to derive, as a BIP32 path: `m/84h/0h/0h/0`.
    ///
    /// An apostrophe or `h` marks a hardened step. In most shells `h` is the one
    /// that does not need quoting.
    #[arg(long, value_name = "PATH", required_unless_present = "input")]
    path: Option<String>,

    /// How many children of that branch to derive. Defaults to 1, capped at 100.
    // Ranged at parse time so a wrong *argument* exits 2. The cap is checked
    // again in `run`, because a request file can carry a count too.
    #[arg(long, value_name = "N", default_value_t = default_count(),
          value_parser = clap::value_parser!(u32).range(0..=i64::from(MAX_COUNT)))]
    count: u32,

    /// Which child index to start from. Defaults to 0.
    ///
    /// Pages through an account: `--start-index 20 --count 20` is the second
    /// twenty addresses of the same branch.
    #[arg(long, value_name = "N", default_value_t = 0)]
    start_index: u32,

    /// Which network the keys and addresses are for.
    #[arg(long, value_name = "NETWORK", default_value_t = default_network())]
    network: Network,

    /// Read the request from a JSON file, or `-` for stdin.
    ///
    /// The file holds {"seed", "path", "count"?, "startIndex"?, "network"?} —
    /// the HTTP API's request body.
    #[arg(long, value_name = "FILE",
          conflicts_with_all = ["seed_file", "path", "count", "start_index", "network"])]
    input: Option<PathBuf>,
}

/// The resolved request, and the shape `--input` reads.
///
/// Hand-writes `Debug`: it holds the seed.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    seed: String,
    path: String,
    #[serde(default = "default_count")]
    count: u32,
    #[serde(default)]
    start_index: u32,
    #[serde(default = "default_network")]
    network: Network,
}

impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Request")
            .field("seed", &"<redacted>")
            .field("path", &self.path)
            .field("count", &self.count)
            .field("start_index", &self.start_index)
            .field("network", &self.network)
            .finish()
    }
}

/// A derived child's private key, in the two forms a wallet takes.
///
/// # This type hand-writes its `Debug`
///
/// Both fields are the same secret.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedPrivateKeyView {
    hex: String,
    wif: String,
}

impl fmt::Debug for DerivedPrivateKeyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DerivedPrivateKeyView(<redacted>)")
    }
}

/// One derived child, with everything it produces.
///
/// Derives `Debug`: the secret is behind [`DerivedPrivateKeyView`], whose own
/// impl redacts it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DerivedKeyView {
    index: u32,
    path: String,
    private_key: DerivedPrivateKeyView,
    public_key: String,
    pubkey_hash: String,
    /// *The* address for this layout, when the path names a purpose — a BIP84
    /// path means the P2WPKH one and nothing else. `null` for a path whose first
    /// step is not one of the four.
    address: Option<String>,
    /// Every address this key produces, whatever the path says.
    addresses: AddressesView,
}

/// A branch and its children.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeriveResponse {
    network: Network,
    /// BIP44, 49, 84 or 86, inferred from the path's first step. `null` when it
    /// is not one of them.
    purpose: Option<Purpose>,
    branch: ExtendedKeyView,
    keys: Vec<DerivedKeyView>,
}

impl Output for DeriveResponse {
    fn render(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut fields = Fields::new();
        fields.row("network", self.network).maybe(
            0,
            "purpose",
            // `Purpose` has a serde spelling and a `Display`, and they agree;
            // this goes through `Display` because it is the one available
            // without a round trip through JSON.
            self.purpose.map(|p| p.to_string()),
        );

        fields.blank().heading(0, "branch");
        self.branch.render(&mut fields, 1);

        for key in &self.keys {
            fields
                .blank()
                .heading(0, &key.path)
                .nested(1, "index", key.index)
                .nested(1, "privateKey", &key.private_key.hex)
                .nested(1, "wif", &key.private_key.wif)
                .nested(1, "publicKey", &key.public_key)
                .nested(1, "pubkeyHash", &key.pubkey_hash)
                .maybe(1, "address", key.address.as_ref());

            // The brief form: four addresses fully broken down, times up to a
            // hundred keys, is not something anyone reads. `keys public` is
            // where one key gets taken apart.
            key.addresses.render_briefly(&mut fields, 1);
        }

        fields.write(w)
    }
}

/// Read the seed, walk the path, derive the children, emit.
///
/// # Errors
///
/// If the request cannot be read, the seed is not 16–64 bytes or is one BIP32
/// refuses, the path is not a path, more than [`MAX_COUNT`] children are asked
/// for, or the walk would run past the largest normal index.
pub fn run(mut args: Args, ctx: Context) -> Result<()> {
    let source = args.input.take();
    let seed_file = args.seed_file.take();
    let path = args.path.take();

    let request: Request = input::resolve_reading(source.as_deref(), || {
        // Both are `required_unless_present = "input"`, so clap has already
        // refused a partial set.
        match (seed_file.as_deref(), path) {
            (Some(file), Some(path)) => Ok(Some(Request {
                seed: input::secret_from(file)?,
                path,
                count: args.count,
                start_index: args.start_index,
                network: args.network,
            })),
            _ => Ok(None),
        }
    })?;

    if request.count > MAX_COUNT {
        bail!(
            "at most {MAX_COUNT} keys per request, asked for {}",
            request.count
        );
    }

    // A seed past the maximum is not a size-cap problem: 64 bytes is what BIP32
    // defines a seed as, so the user hears about the seed rather than about a
    // limit this program chose. No excerpt on the way — the value is the wallet.
    let seed = input::hex_bytes(&request.seed, SUBJECT, MAX_SEED_SIZE).map_err(|e| match e {
        InputError::TooLarge { got_bytes, .. } => {
            anyhow::Error::from(Bip32Error::SeedLength { got: got_bytes })
        }
        other => other.into(),
    })?;

    let path: DerivationPath = request
        .path
        .parse()
        .with_context(|| format!("reading {:?} as a derivation path", request.path))?;

    let master = Xpriv::new_master(&seed, request.network).context("deriving the master key")?;
    let branch = master
        .derive_path(&path)
        .with_context(|| format!("deriving {path}"))?;

    // Checked before the walk rather than during it, so asking for a range that
    // runs off the end says so once instead of after printing part of it.
    let last = u64::from(request.start_index) + u64::from(request.count.saturating_sub(1));
    if request.count > 0 && last > u64::from(MAX_INDEX) {
        bail!("child index {last} is past the largest normal index, {MAX_INDEX}");
    }

    let purpose = path
        .as_slice()
        .first()
        .and_then(|step| Purpose::from_number(step.index()));

    let keys = (request.start_index..)
        .take(request.count as usize)
        .map(|index| {
            let step = ChildNumber::normal(index)
                .with_context(|| format!("child index {index} is not a normal index"))?;
            let child = branch
                .derive_child(step)
                .with_context(|| format!("deriving child {index}"))?;

            Ok(view(
                purpose,
                request.network,
                index,
                &path.child(step)?,
                &child,
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    ctx.emit(&DeriveResponse {
        network: request.network,
        purpose,
        branch: ExtendedKeyView::of(&branch, path.to_string()),
        keys,
    })?;

    Ok(())
}

/// Render one derived child.
fn view(
    purpose: Option<Purpose>,
    network: Network,
    index: u32,
    path: &DerivationPath,
    key: &Xpriv,
) -> DerivedKeyView {
    let private = key.private_key();
    let public = private.public_key();

    DerivedKeyView {
        index,
        path: path.to_string(),
        private_key: DerivedPrivateKeyView {
            hex: hex::encode(&private.to_be_bytes()),
            wif: private.to_wif(),
        },
        public_key: public.to_string(),
        pubkey_hash: public.pubkey_hash().to_string(),
        address: purpose.and_then(|p| p.address(&public, network).ok().map(|a| a.to_string())),
        addresses: AddressesView::of(&public, network),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_tools_core::hd::Mnemonic;

    fn seed() -> String {
        let mnemonic = Mnemonic::from_entropy(&[0; 16]).expect("16 bytes is a defined size");
        hex::encode(&mnemonic.to_seed(""))
    }

    fn request(path: &str, count: u32) -> Request {
        Request {
            seed: seed(),
            path: path.to_owned(),
            count,
            start_index: 0,
            network: Network::Mainnet,
        }
    }

    /// The request holds the seed, so its `Debug` redacts it — and keeps the
    /// path, which is what you need to reproduce the run.
    #[test]
    fn the_request_does_not_print_the_seed() {
        let request = request("m/84'/0'/0'/0", 1);
        let rendered = format!("{request:?}");

        assert!(!rendered.contains(&request.seed), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("m/84'/0'/0'/0"), "{rendered}");
    }

    /// The derived key's own `Debug` redacts both spellings of the child key,
    /// and the composite inherits that for free.
    #[test]
    fn a_derived_debug_inherits_the_leafs_redaction() {
        let key = DerivedKeyView {
            index: 0,
            path: "m/0".to_owned(),
            private_key: DerivedPrivateKeyView {
                hex: "dead".repeat(16),
                wif: "L1xxTDd4RJ9GG7jZ".to_owned(),
            },
            public_key: "02aa".to_owned(),
            pubkey_hash: "bb".to_owned(),
            address: None,
            addresses: AddressesView::of(
                &bitcoin_tools_core::keys::PrivateKey::from_hex(
                    &"01".repeat(32),
                    Network::Mainnet,
                    true,
                )
                .unwrap()
                .public_key(),
                Network::Mainnet,
            ),
        };
        let rendered = format!("{key:?}");

        assert!(!rendered.contains("L1xxTDd4RJ9GG7jZ"), "{rendered}");
        assert!(!rendered.contains("deaddead"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(
            rendered.contains("m/0"),
            "the path still prints: {rendered}"
        );
    }

    /// The purpose comes from the path's first step, which is what decides
    /// which of the four addresses is *the* address.
    #[test]
    fn the_purpose_comes_from_the_path() {
        for (path, expected) in [
            ("m/44'/0'/0'/0", Some(Purpose::Bip44)),
            ("m/49'/0'/0'/0", Some(Purpose::Bip49)),
            ("m/84'/0'/0'/0", Some(Purpose::Bip84)),
            ("m/86'/0'/0'/0", Some(Purpose::Bip86)),
            ("m/0/1", None),
            ("m", None),
        ] {
            let parsed: DerivationPath = path.parse().unwrap();
            let purpose = parsed
                .as_slice()
                .first()
                .and_then(|step| Purpose::from_number(step.index()));

            assert_eq!(purpose, expected, "{path}");
        }
    }

    /// `--start-index` pages through one branch: the sixth key of a straight
    /// run is the first key of a run starting at five.
    #[test]
    fn start_index_pages_through_an_account() {
        let derive_at = |start: u32| {
            let request = request("m/84'/0'/0'/0", 1);
            let seed = hex::decode(&request.seed).unwrap();
            let master = Xpriv::new_master(&seed, Network::Mainnet).unwrap();
            let branch = master
                .derive_path(&"m/84'/0'/0'/0".parse().unwrap())
                .unwrap();

            branch
                .derive_child(ChildNumber::normal(start).unwrap())
                .unwrap()
                .to_base58()
        };

        assert_eq!(derive_at(5), derive_at(5));
        assert_ne!(derive_at(5), derive_at(0));
    }

    #[test]
    fn the_path_is_required_in_a_request_file_too() {
        assert!(serde_json::from_str::<Request>(r#"{"seed":"00"}"#).is_err());
    }

    #[test]
    fn a_typo_in_the_request_file_is_an_error() {
        assert!(serde_json::from_str::<Request>(r#"{"seed":"00","pth":"m"}"#).is_err());
    }
}
