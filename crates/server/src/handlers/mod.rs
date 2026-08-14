pub mod address;
pub mod blocks;
pub mod crypto;
pub mod error;
pub mod hd;
pub mod keys;
pub mod transactions;

use axum::Json;
use axum::http::header;

/// The one header any endpoint in this API sets, and the only control it can
/// assert over a response body that is a credential.
///
/// A conforming cache will not store a POST response without explicit
/// freshness information, so on the server side this is belt over braces — but
/// it also covers the client: devtools, disk-backed HTTP client caches, and
/// anything replaying a session.
///
/// Set by every endpoint that returns a secret, and by no others, so its
/// presence is a statement about the response rather than boilerplate: right
/// now `/keys/generate`, `/hd/mnemonic` and `/hd/derive`.
///
/// `keys_api::the_secret_response_forbids_caching` is what keeps the second
/// half true — it asserts `/keys/public` does *not* set it. `hd_api` cannot
/// make that assertion, since both of its endpoints return secrets.
pub(crate) const NO_STORE: [(header::HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];

/// The return type of an endpoint that hands over a secret.
///
/// Pairs with [`NO_STORE`] so the signature says what the doc comment would
/// otherwise have to: this response is a credential. Three endpoints were
/// spelling the header tuple out, and a fourth would have spelled it again.
pub(crate) type Secret<T> = ([(header::HeaderName, &'static str); 1], Json<T>);
