//! The shape every service error takes: bad input, or a domain failure.
//!
//! Generic so that an endpoint which validates hex and *then* parses it — a
//! transaction, a PSBT, a public key — states only the parse error type and
//! inherits the rest.

use std::fmt;

use crate::services::input::InputError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceError<E> {
    /// The caller sent something unusable.
    Input(InputError),
    /// The input was usable but the operation failed on its own terms.
    Domain(E),
}

impl<E: fmt::Display> fmt::Display for ServiceError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServiceError::Input(e) => write!(f, "{e}"),
            ServiceError::Domain(e) => write!(f, "{e}"),
        }
    }
}

impl<E: fmt::Debug + fmt::Display> std::error::Error for ServiceError<E> {}

/// Lets `hex_bytes(..)?` work in any service.
impl<E> From<InputError> for ServiceError<E> {
    fn from(e: InputError) -> Self {
        ServiceError::Input(e)
    }
}
