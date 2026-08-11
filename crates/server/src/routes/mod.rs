//! URL and method binding. Nothing here should contain logic.

pub mod transactions;

/// Room for a hex payload of `max_bytes` plus the JSON envelope around it.
///
/// Every route that accepts hex must set this from its domain constant.
/// Without an explicit limit axum caps bodies at 2 MB, which would silently
/// override the size policy the services advertise — a caller would get a
/// transport-level rejection instead of the service's `input-too-large`.
pub(crate) const fn body_limit(max_bytes: usize) -> usize {
    max_bytes * 2 + 1024
}
