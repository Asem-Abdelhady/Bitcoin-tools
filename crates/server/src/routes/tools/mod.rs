//! The `/tools` URL space.
//!
//! ## The path is kebab-case
//!
//! `/tools/reverse-bytes` is the first endpoint in this API whose name is two
//! words, so it is the first that had to choose. Kebab-case is the ordinary
//! REST convention and is what `CLAUDE.md` already named as the likely answer;
//! the single-word paths that came before (`/script`, `/splitter`, `/derive`)
//! are unaffected either way, since one lowercase word is every convention at
//! once. Renaming *those* is still an open question — this only settles what a
//! new multi-word path does.

use axum::extract::DefaultBodyLimit;
use axum::{Router, routing::post};

use crate::handlers::tools::{number, reverse, units};
use crate::routes::body_limit;
use crate::services::tools::reverse::MAX_BYTES;
use bitcoin_tools_core::general::Number;

/// Transport budget for `/tools/number`.
///
/// [`body_limit`] is not called here, deliberately: it is documented as room
/// for a *hex* payload of a given many **bytes**, and this field is digits.
/// The arithmetic would come out the same — that is a coincidence of the two
/// formulas, not a use of the helper, and a reader who checked would find the
/// call claiming the field is something it is not.
///
/// The doubling is real headroom rather than a leftover of that formula. The
/// domain's cap is [`Number::MAX_DIGITS`] and a digit is one byte of JSON, so
/// a budget of exactly that would put the transport's refusal a few characters
/// from the parser's — and the two say different things. `input-too-large`
/// names the limit and the count sent; `unreadable-body` can only say the body
/// was too big. Anyone who overshoots by less than double gets the message that
/// tells them what to do.
const MAX_NUMBER_FIELD: usize = Number::MAX_DIGITS * 2 + 1024;

/// Transport budget for `/tools/units`.
///
/// The largest amount that exists is `u64::MAX` satoshis — twenty digits — and
/// the longest spelling of one is 21 million BTC written to eight decimal
/// places. A kilobyte is orders of magnitude past anything meaningful while
/// still refusing a pasted file, and every over-length value inside it reaches
/// the domain, which answers `amount-out-of-range` rather than leaving the
/// transport to say something vaguer.
const MAX_AMOUNT_FIELD: usize = 1024;

/// Routes mounted under `/tools`.
pub fn router() -> Router {
    Router::new()
        .route(
            "/reverse-bytes",
            post(reverse::post_reverse_bytes).layer(DefaultBodyLimit::max(body_limit(MAX_BYTES))),
        )
        .route(
            "/number",
            post(number::post_number).layer(DefaultBodyLimit::max(MAX_NUMBER_FIELD)),
        )
        .route(
            "/units",
            post(units::post_units).layer(DefaultBodyLimit::max(MAX_AMOUNT_FIELD)),
        )
}
