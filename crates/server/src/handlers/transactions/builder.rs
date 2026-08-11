//! Placeholder for the transaction builder.
//!
//! Wired up so the URL space is visible, but honest about not existing yet: a
//! fabricated 200 would let a client code against a response that will change
//! completely once this is real.

use crate::handlers::error::{ApiRejection, NotImplemented};

/// `POST /transactions/builder`
pub async fn post_tx_builder() -> ApiRejection<NotImplemented> {
    ApiRejection::Domain(NotImplemented("transaction builder"))
}
