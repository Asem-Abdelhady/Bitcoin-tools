//! Representation conversions.
//!
//! Small, self-contained transformations of a single value. Nothing here
//! parses a consensus structure; that is [`transactions`](crate::transactions)
//! and [`blocks`](crate::blocks).
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `reverse.rs` | Reverse Bytes — wire order ⇄ display order |
//! | `number.rs` | Number Converter — one value as binary, decimal, and hex |
//! | `units.rs` | Unit Converter — `Amount` in sats, µBTC, mBTC, BTC |
//!
//! `units.rs` owns an [`Amount`] newtype over integer satoshis, and
//! [`Output::value`](crate::transactions::tx::Output) is one — the two were
//! always one piece of work, since an amount that only the converter knows
//! about would leave the decoder handing out bare `u64`s that mean satoshis
//! only by convention. Money never touches a float here: `0.1 + 0.2` losing a
//! satoshi is a real bug in real wallets.
//!
//! `Amount` does **not** enforce the 21-million cap. It cannot: a malformed
//! transaction can declare any `u64` as an output value, and this crate shows
//! what it was given rather than refusing to represent it.
//! [`Amount::is_money_range`] is the question, asked by whoever wants to
//! validate rather than decode.
//!
//! ## Reverse Bytes is a wrapper, not the primitive
//!
//! Flipping a byte buffer is what [`hashes`](crate::hashes) needs for its
//! `Display`, and `hashes` is the same layer as this module — it must not
//! import sideways to get it. The primitive belongs in
//! [`hex`](crate::hex) at L0, alongside
//! [`hex::write_rev`](crate::hex::write_rev) which already encodes the same
//! decision; [`hex::encode_rev`](crate::hex::encode_rev) is the allocating
//! form it grew for this module. [`reverse`] is the feature-facing wrapper
//! over it: hex in, hex out, with the error handling a user-supplied string
//! needs.
//!
//! ## `Number` is arbitrary-precision because private keys need it to be
//!
//! [`Number`] could have been a `u64` and covered every amount, nonce and
//! locktime. It is not, because a *256-bit private key* has to be shown as
//! binary, decimal and hex, and a 64-bit converter would have made
//! [`keys`](crate::keys) write its own decimal renderer. The arithmetic is
//! two loops — see
//! [`number`] for the full argument and for why parsing does not go through
//! [`hex::decode`](crate::hex::decode).

pub mod number;
pub mod reverse;
pub mod units;

pub use number::{Base, Number, ParseNumberError, TooManyBytes, UnknownBase};
pub use reverse::reverse_hex;
pub use units::{Amount, Denomination, ParseAmountError, UnknownDenomination};
