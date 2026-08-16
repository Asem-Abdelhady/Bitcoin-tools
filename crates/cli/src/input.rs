//! Where a command's input comes from, and what counts as usable.
//!
//! Two sources, and every command that takes one takes both: values given as
//! arguments, or a JSON object read from a file — or from stdin, written `-`,
//! which is the spelling every other tool uses and users will try first.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use serde::de::{self, DeserializeOwned, Deserializer};

use bitcoin_tools_core::hex::{self, HexError};
use bitcoin_tools_core::transactions::tx::Tx;

/// Why a value a user supplied could not be used.
///
/// # This mirrors the server's `services::input`
///
/// Deliberately, and it is the one duplication in this crate. The two front
/// ends cannot share the policy without a fourth crate to put it in, and the
/// part worth not repeating — the hex codec itself — is already core's and is
/// called from both. What is restated here is four lines of policy: trim,
/// accept `0x`, refuse empty, cap the size.
///
/// Keep the *policy* identical. A hex string one front end accepts and the other
/// refuses is a bug a user experiences as flakiness, and if a third caller ever
/// appears this moves into core rather than being written a third time. The
/// wording is each front end's own — see [`InputError::Hex`], which carries a
/// subject here and does not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    /// The field was empty once `0x` and whitespace were removed.
    Empty {
        /// What was expected, for the message.
        subject: &'static str,
    },
    /// Past the size this command accepts.
    TooLarge {
        /// What was expected, for the message.
        subject: &'static str,
        /// The cap, in bytes.
        max_bytes: usize,
        /// What was supplied, in bytes.
        got_bytes: usize,
    },
    /// Not hex, or an odd number of digits.
    ///
    /// Carries the subject, unlike the server's otherwise-identical enum. With
    /// fourteen commands and several hex fields inside some of their requests,
    /// "invalid hex at byte 0" does not tell a user which of their arguments was
    /// wrong, and the noun is already in hand at every call site.
    Hex {
        /// What was being read, for the message.
        subject: &'static str,
        /// What was wrong with it.
        error: HexError,
    },
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InputError::Empty { subject } => write!(f, "{subject} must not be empty"),
            InputError::TooLarge {
                subject,
                max_bytes,
                got_bytes,
            } => write!(
                f,
                "{subject} is {got_bytes} bytes; the maximum is {max_bytes}"
            ),
            InputError::Hex { subject, error } => write!(f, "{subject}: {error}"),
        }
    }
}

impl std::error::Error for InputError {}

/// Normalise and decode a hex value.
///
/// `subject` is the noun the error message uses ("input", "transaction"). The
/// cap is checked against the hex length *before* decoding, so an oversized
/// value is refused without allocating for it.
///
/// # Errors
///
/// [`InputError`] if the value is empty, is not whole bytes of hex, or is past
/// `max_bytes`.
pub fn hex_bytes(
    input: &str,
    subject: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, InputError> {
    let trimmed = hex::normalize(input);

    if trimmed.is_empty() {
        return Err(InputError::Empty { subject });
    }

    if trimmed.len() > max_bytes * 2 {
        return Err(InputError::TooLarge {
            subject,
            max_bytes,
            // Rounded up: an odd digit count is not whole bytes, and truncating
            // gives a message that contradicts itself — "is 80 bytes; the
            // maximum is 80".
            got_bytes: trimmed.len().div_ceil(2),
        });
    }

    hex::decode(trimmed).map_err(|error| InputError::Hex { subject, error })
}

/// The same, for a field where empty is a real value rather than a mistake.
///
/// Most commands take one hex payload and an empty one is a user error — there
/// is nothing to decode. A transaction's *parts* are not like that: an unsigned
/// input has an empty `scriptSig`, so does every native segwit input, a witness
/// stack can carry an empty item as a placeholder, and an output may carry an
/// empty unspendable script. Refusing those would make the builder unable to
/// express ordinary transactions.
///
/// Split from [`hex_bytes`] rather than hidden behind a flag, so the decision
/// sits at the call site where the field is named and the answer is obvious.
///
/// # Errors
///
/// [`InputError`] if the value is not whole bytes of hex, or is past
/// `max_bytes`.
pub fn hex_bytes_allowing_empty(
    input: &str,
    subject: &'static str,
    max_bytes: usize,
) -> Result<Vec<u8>, InputError> {
    let trimmed = hex::normalize(input);

    if trimmed.len() > max_bytes * 2 {
        return Err(InputError::TooLarge {
            subject,
            max_bytes,
            got_bytes: trimmed.len().div_ceil(2),
        });
    }

    hex::decode(trimmed).map_err(|error| InputError::Hex { subject, error })
}

/// Decode a hex field that must be an exact number of bytes.
///
/// Most inputs have a *ceiling* — a script up to 10,000 bytes, a transaction up
/// to 4,000,000 — and [`hex_bytes`] is the whole story for those. A block
/// header, a private key and a message hash are not like that: they are one
/// width, and "too long" is not a different mistake from "too short". Both
/// directions become the caller's own error, built by `wrong_width` from the
/// size actually supplied, so the message names what was being parsed rather
/// than borrowing a size-cap message that means something else elsewhere.
///
/// The width is a const parameter and the return is an array, so a caller
/// needing `[u8; 32]` gets one — no `try_into`, and no `expect` asserting a
/// length the compiler could have known.
///
/// # This is the server's helper with its two-armed error collapsed
///
/// There, the same function returns `ServiceError<E>`, because an input problem
/// and a domain problem become different HTTP statuses. Here they become the
/// same exit code, so keeping them apart would buy a type the program has
/// nothing to do with. What is preserved is the part that reaches a user: the
/// wrong width is reported as the caller's own error either way.
///
/// # Errors
///
/// `wrong_width(got)` if the value is not exactly `N` bytes, or the input error
/// if it is not hex at all.
pub fn hex_bytes_exact<const N: usize, E>(
    input: &str,
    subject: &'static str,
    wrong_width: impl FnOnce(usize) -> E,
) -> Result<[u8; N]>
where
    E: std::error::Error + Send + Sync + 'static,
{
    // Both arms that reach `wrong_width` funnel into one call, so it stays
    // `FnOnce` — a caller should be able to pass a closure that moves.
    let got = match hex_bytes(input, subject, N) {
        // `TryFrom<Vec<_>>` rather than from a slice: it moves the bytes and
        // hands the vector back on failure, so the success path is a move.
        Ok(bytes) => match <[u8; N]>::try_from(bytes) {
            Ok(exact) => return Ok(exact),
            // Short: the cap above only rejects long ones.
            Err(short) => short.len(),
        },
        Err(InputError::TooLarge { got_bytes, .. }) => got_bytes,
        Err(other) => return Err(other.into()),
    };

    Err(wrong_width(got).into())
}

/// Read a secret from a file, or from stdin when `path` is `-`.
///
/// # Why a secret has no flag of its own
///
/// A private key, a seed and a passphrase never arrive as an argument *value*.
/// Command-line arguments are visible in `ps` to every user on the machine and
/// land verbatim in shell history, and neither is something a user can undo
/// after the fact. So the flag names a **file**, and the file — or stdin — is
/// what holds the secret:
///
/// ```console
/// $ bt keys public --private-key-file key.hex
/// $ printf %s "$KEY" | bt keys public --private-key-file -
/// ```
///
/// The second form is the scripting one, and it is why `-` is spelled the way
/// every other tool spells it.
///
/// # Exactly one trailing line ending is removed, and nothing else
///
/// Not `trim`. A private key and a seed are hex, and core's `hex::normalize`
/// already ignores surrounding whitespace in those — but a **BIP39 passphrase
/// is an arbitrary byte string**, it is not checksummed, and a leading or
/// trailing space in it is part of the wallet. Trimming made
/// `--passphrase-file` and the equivalent `--input` field derive two different
/// seeds from one passphrase, and the `--input` one is what the HTTP API
/// answers — so a wallet generated from a file could not be restored anywhere
/// else.
///
/// One line ending goes because `echo` appends one and refusing that would
/// teach people to reach for `printf` with no benefit. A passphrase whose last
/// character really is a newline is written without one and given as
/// `--input`, which carries it exactly.
///
/// The cap is [`MAX_REQUEST_BYTES`], the same as a request file's — a secret is
/// far smaller, and the point of the cap is that `-` on an endless pipe stops
/// rather than consuming the machine.
///
/// # Errors
///
/// If the source cannot be read or is past the cap. An empty one is *not* an
/// error here: what a secret has to look like is the command's own rule, and
/// each says so in its own vocabulary.
pub fn secret_from(path: &Path) -> Result<String> {
    let text = if path == Path::new("-") {
        read_capped(io::stdin().lock(), "stdin")?
    } else {
        let source = path.display().to_string();
        let file = fs::File::open(path).with_context(|| format!("reading {source}"))?;
        read_capped(file, &source)?
    };

    // One line ending, not `trim` — see above. `\r\n` as well as `\n`, so a
    // file written on Windows is not a different passphrase.
    let text = text.strip_suffix('\n').unwrap_or(&text);
    Ok(text.strip_suffix('\r').unwrap_or(text).to_owned())
}

/// At most a couple of dozen characters of a value, for an error message.
///
/// Error context names what was being read, and the whole value is the wrong
/// thing to name: `converter base` exists so a 256-bit private key can be read
/// in decimal, and echoing a rejected one into stderr puts a secret somewhere that
/// gets redirected into logs far more often than `argv` does. The length is
/// reported instead, which is the part that helps.
///
/// The domain error underneath already says what was wrong and where.
#[must_use]
pub fn excerpt(value: &str) -> String {
    /// Long enough to recognise what you typed, short enough not to be the
    /// value.
    const KEEP: usize = 24;

    let taken: String = value.chars().take(KEEP).collect();

    if taken.chars().count() == value.chars().count() {
        format!("{taken:?}")
    } else {
        format!("{taken:?}… ({} characters)", value.chars().count())
    }
}

/// The most a request file may be.
///
/// A request is a small JSON object whose largest field is one hex payload, so
/// this is that payload at its cap plus room for the envelope around it — the
/// same arithmetic the server's per-route transport cap uses.
///
/// Without it, `--input` is an unbounded read: a huge file, or a `-` fed from a
/// pipe that never ends, allocates until the machine gives up, and it happens
/// *before* any command's own cap can say anything.
const MAX_REQUEST_BYTES: u64 = Tx::MAX_SIZE as u64 * 2 + 1024;

/// Read a request from a JSON file, or from stdin when `path` is `-`.
///
/// # Errors
///
/// If the source cannot be read, is larger than [`MAX_REQUEST_BYTES`], or does
/// not hold the object this command expects. Every message names the source,
/// because "expected a string" is useless when three files were involved.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let (source, text) = if path == Path::new("-") {
        let text = read_capped(io::stdin().lock(), "stdin")?;
        ("stdin".to_owned(), text)
    } else {
        let source = path.display().to_string();
        let file =
            fs::File::open(path).with_context(|| format!("reading the request from {source}"))?;
        let text = read_capped(file, &source)?;
        (source, text)
    };

    // `from_str` rather than `from_reader`: the text is already in hand, and
    // this is the form that reports a line and column.
    serde_json::from_str(&text).with_context(|| format!("{source} is not a valid request"))
}

/// Read at most [`MAX_REQUEST_BYTES`], and say so rather than truncating.
///
/// One extra byte is requested so that hitting the cap is distinguishable from
/// a file that happens to be exactly that long.
fn read_capped(source: impl Read, name: &str) -> Result<String> {
    let mut text = String::new();

    source
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading the request from {name}"))?;

    if text.len() as u64 > MAX_REQUEST_BYTES {
        bail!("the request from {name} is larger than {MAX_REQUEST_BYTES} bytes");
    }

    Ok(text)
}

/// Take a request from the JSON source if one was given, otherwise from the
/// arguments.
///
/// Every command's front door, so the precedence is decided once. The arguments
/// arrive as a closure returning `None` when clap collected neither source.
/// Every command states "exactly one source" as one required, non-multiple
/// `ArgGroup` holding its own arguments and `--input`, so clap refuses that
/// with a usage error before this runs — the `None` arm is reachable only if a
/// future command forgets the group. It is an error rather than an `unwrap` for
/// exactly that reason: the command that forgets should print a sentence, not a
/// panic.
///
/// # Errors
///
/// Whatever [`read_json`] produced, or a usage message if neither source
/// supplied a request.
pub fn resolve<T, F>(source: Option<&Path>, from_args: F) -> Result<T>
where
    T: DeserializeOwned,
    F: FnOnce() -> Option<T>,
{
    resolve_reading(source, || Ok(from_args()))
}

/// The same, for a command whose arguments name a *file* the request is built
/// from.
///
/// Every command holding a secret is one of these: the secret arrives as
/// `--<name>-file`, so assembling the request from the arguments means reading
/// that file, which can fail on its own. The plain [`resolve`] cannot express
/// that, and threading a `Result` through its closure would make the three
/// commands that do not need it say so.
///
/// # Errors
///
/// Whatever [`read_json`] or `from_args` produced, or a usage message if
/// neither source supplied a request.
pub fn resolve_reading<T, F>(source: Option<&Path>, from_args: F) -> Result<T>
where
    T: DeserializeOwned,
    F: FnOnce() -> Result<Option<T>>,
{
    match source {
        Some(path) => read_json(path),
        None => from_args()?.context("expected arguments or --input; see --help"),
    }
}

/// Deserialize any field whose type already knows how to read itself from text.
///
/// `#[serde(deserialize_with = "from_str")]`. A request file names its notation
/// as a *value* — `{"base": "hexadecimal"}` — where the arguments name it as a
/// flag, and core gives `Base`, `Denomination` and `Network` a `FromStr` that
/// accepts the spellings a person would write. Reading the file through it
/// means `hex`, `16` and `HEX` work there too, so the file stays as forgiving
/// as the flags without this crate holding a second table of names.
///
/// # Errors
///
/// The type's own `FromStr` error, as a serde message.
pub fn from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    T::Err: fmt::Display,
{
    let text = String::deserialize(deserializer)?;
    T::from_str(&text).map_err(de::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_and_trims() {
        assert_eq!(hex_bytes("  0xdead ", "input", 100).unwrap(), [0xde, 0xad]);
    }

    #[test]
    fn empty_after_normalising_is_empty() {
        let err = hex_bytes("  0x  ", "input", 100).unwrap_err();
        assert_eq!(err.to_string(), "input must not be empty");
    }

    /// An odd digit count is not whole bytes, and the cap is checked before
    /// decoding — so the reported size has to round up or the message
    /// contradicts itself. The server has the same test for the same reason.
    #[test]
    fn an_oversized_odd_length_input_does_not_report_the_cap_as_its_size() {
        let err = hex_bytes(&format!("{}0", "00".repeat(10)), "input", 10).unwrap_err();
        assert_eq!(err.to_string(), "input is 11 bytes; the maximum is 10");
    }

    #[test]
    fn exactly_at_the_cap_is_allowed() {
        assert_eq!(hex_bytes(&"00".repeat(10), "input", 10).unwrap().len(), 10);
    }

    #[test]
    fn a_lone_nibble_is_not_bytes() {
        let err = hex_bytes("abc", "input", 100).unwrap_err();
        assert!(err.to_string().contains("odd"), "got {err}");
    }
}
