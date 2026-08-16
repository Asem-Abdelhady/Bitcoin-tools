//! One module per subcommand group.
//!
//! The groups are the server's, `converter` aside: it is `/tools` there, because
//! its argument surface genuinely differs — see
//! [`converter`]. Everything else is named as the
//! server names it, and no group is allowed to differ in its *answers*.
//!
//! | Group | Commands |
//! |---|---|
//! | [`blocks`] | `hash`, `header` |
//! | [`converter`] | `base`, `unit`, `reverse-bytes` |
//! | [`crypto`] | `sign`, `verify` |
//! | [`hd`] | `mnemonic`, `derive` |
//! | [`keys`] | `generate`, `public` |
//! | [`transactions`] | `script`, `splitter`, `builder` |
//!
//! Each command module holds the same four things in the same order, so the next
//! one is a matter of copying the shape rather than deciding it again:
//!
//! 1. `Args` — what clap collects.
//! 2. `Request` — the resolved input, which is also the shape `--input` reads.
//!    `deny_unknown_fields`, so a typo in a JSON file is an error rather than
//!    silence, and the field names are the HTTP API's so one file drives both
//!    front ends.
//! 3. An output type — the answer, `Serialize` for `--json` and `render` for a
//!    terminal. See [`crate::output`] for why those are one type.
//! 4. `run` — resolve the request, call core, emit. No Bitcoin logic: if a
//!    command needs to hash, encode or reverse something itself, the thing it
//!    needs belongs in core.
//!
//! # Exactly one source
//!
//! Every command takes its request from arguments *or* from `--input`, never a
//! mixture, and says so as a clap rule rather than as a check in `run`:
//!
//! - **A required [`ArgGroup`](clap::ArgGroup)** where the arguments are one
//!   thing — a positional hex value, a notation flag, a secret's file. Two at
//!   once, and none at all, are then the same kind of usage error and clap
//!   reports both.
//! - **`required_unless_present = "input"`** where several arguments are given
//!   *together* — `crypto verify`'s three, `hd derive`'s two. A group is
//!   mutually exclusive and cannot say "these together, or that instead".
//! - **`conflicts_with_all`** where nothing is required at all — `keys generate`
//!   and `hd mnemonic` answer with no arguments, so their flags only need to be
//!   kept apart from `--input`.
//!
//! [`input::resolve`](crate::input::resolve) is where the precedence lives, and
//! its `None` arm is reachable only if a command forgets to state its rule.
//!
//! # Handling a secret
//!
//! Four commands take one and three hand one back. These are the rules they
//! share, rather than each deciding alone. The server settled two of them; a CLI
//! has a third problem it does not.
//!
//! **A secret does not arrive as an argument.** Not as a positional, not as a
//! `--flag` value. Command-line arguments are visible in `ps` to every user on
//! the machine and land verbatim in shell history, and neither is something a
//! user can take back. So the flag names a **file** — `--private-key-file`,
//! `--seed-file`, `--passphrase-file` — and `-` means stdin, which is the
//! scripting form. [`input::secret_from`](crate::input::secret_from) is the one
//! place that reads one, and `keys::no_command_offers_a_flag_that_carries_a_secret`
//! in the test suite asserts the rule against the generated help rather than
//! against this paragraph.
//!
//! **A type holding a secret hand-writes a redacting `Debug`.** `Request` types
//! included — core hand-writes one for `PrivateKey`, `Mnemonic` and `Xpriv`, and
//! a struct here holding a `String` seed and deriving `Debug` undoes that. Only
//! the leaves need it: a derived `Debug` calls each field's impl, so redaction
//! propagates through a composite for free. Each impl also keeps printing the
//! public half, and each has a test asserting *both* — a redaction that blanked
//! everything would pass half a test and lose the only reason `Debug` is there.
//!
//! **An error message does not echo the value back.** Use
//! [`input::excerpt`](crate::input::excerpt) for a value that is merely long,
//! and *nothing at all* for one that is the secret: `keys public` and `hd derive`
//! report the width and the reason and never the key. stderr is redirected into
//! logs far more often than `argv` is read.
//!
//! **An answer carries only what it must.** `keys public` and `crypto sign` take
//! a secret and return none — a test asserts the key is absent from both output
//! modes, which is the CLI's equivalent of the API asserting `/keys/public` does
//! not set `Cache-Control: no-store`. The three commands that *do* return a
//! secret — `keys generate`, `hd mnemonic`, `hd derive` — return it because
//! producing it is their purpose, and their help says where it is going.

pub mod address;
pub mod blocks;
pub mod converter;
pub mod crypto;
pub mod hd;
pub mod keys;
pub mod transactions;
