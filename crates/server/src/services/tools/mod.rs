//! representation conversions.
//!
//! Three endpoints over one idea: a value, shown the other ways it can be
//! written. Nothing here parses a consensus structure — that is
//! [`transactions`](crate::services::transactions) and
//! [`blocks`](crate::services::blocks) — and nothing here has state, a
//! network, or a secret.
//!
//! ## Each of these has one error type, not two
//!
//! Every other service in this crate returns
//! [`ServiceError<E>`](crate::services::error::ServiceError), because it
//! decodes hex *and then* parses a structure out of the bytes, and those are
//! two different failures a caller fixes two different ways. None of these
//! three is like that. `/tools/reverse-bytes` decodes hex and stops, so its
//! only failure is an input one; `/tools/number` and `/tools/units` are given
//! a string in a stated notation and hand it to the domain's own parser, which
//! already trims, already refuses an empty value, and already reports the
//! offset. Wrapping either in a two-armed error would add a half that nothing
//! can construct.
//!
//! ## Why the values arrive as strings
//!
//! `value` and `amount` are JSON strings, and a JSON *number* in either field
//! is refused rather than accepted. Both fields would lose to a double: an
//! amount because `0.1 + 0.2` is a real satoshi-losing bug and the domain
//! keeps money in integers for exactly that reason, and a number because the
//! converter exists to show a 256-bit private key in decimal, which is 205
//! bits past what a JSON number carries. A field that silently mangles the value it was
//! given is worse than one that refuses it.

pub mod number;
pub mod reverse;
pub mod units;

use serde::Deserialize;

/// The request shape for a `/tools` endpoint whose input is one hex payload.
///
/// Shared rather than re-invented per endpoint: these tools have no domain
/// noun to name the field after — a byte string being flipped is not a
/// transaction or a header — so each one inventing its own key would leave a
/// caller needing a lookup table for an API with a single input shape. The
/// domain endpoints do the opposite and name their field (`tx`, `header`,
/// `script`), because there the noun is the point.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HexRequest {
    /// The payload. `0x` and surrounding whitespace are accepted, per the
    /// input policy every hex field in this API shares.
    pub hex: String,
}
