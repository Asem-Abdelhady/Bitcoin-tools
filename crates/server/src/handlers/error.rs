//! Turning domain errors into HTTP responses, once.
//!
//! A handler declares its failure type as [`ApiRejection<E>`] and implements
//! [`ApiError`] for its own `E`. Status codes, the JSON envelope, malformed
//! request bodies, and the 404/405 fallbacks all come from here, so adding an
//! endpoint means writing a status-and-slug table and nothing else.

use std::fmt;

use axum::Json;
use axum::extract::rejection::JsonRejection;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

use crate::services::error::ServiceError;
use crate::services::input::InputError;

/// How a domain error presents over HTTP.
pub trait ApiError: fmt::Display {
    fn status(&self) -> StatusCode;
    /// Stable kebab-case identifier, for clients that branch on the failure.
    fn slug(&self) -> &'static str;
}

/// Everything a handler can fail with: a request that could not be read, or a
/// domain error from the service beneath it.
#[derive(Debug)]
pub enum ApiRejection<E> {
    /// The body was not the JSON this endpoint expects. Carries the status
    /// axum already determined rather than flattening everything to 400.
    Malformed {
        status: StatusCode,
        slug: &'static str,
        message: String,
    },
    Domain(E),
}

/// Lets `let Json(req) = payload?;` work in any handler.
///
/// `JsonRejection` distinguishes a missing `Content-Type` (415) from a syntax
/// error (400) from a well-formed body with the wrong types (422); keeping
/// only `body_text()` would collapse all three into one useless 400.
impl<E> From<JsonRejection> for ApiRejection<E> {
    fn from(r: JsonRejection) -> Self {
        let slug = match &r {
            JsonRejection::MissingJsonContentType(_) => "unsupported-media-type",
            JsonRejection::JsonSyntaxError(_) => "malformed-json",
            JsonRejection::JsonDataError(_) => "invalid-body",
            JsonRejection::BytesRejection(_) => "unreadable-body",
            // JsonRejection is #[non_exhaustive].
            _ => "bad-request",
        };
        ApiRejection::Malformed {
            status: r.status(),
            slug,
            message: r.body_text(),
        }
    }
}

/// The one error shape every endpoint returns.
#[derive(Debug, Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

fn envelope(status: StatusCode, slug: &'static str, message: String) -> Response {
    (
        status,
        Json(ErrorBody {
            error: slug,
            message,
        }),
    )
        .into_response()
}

impl<E: ApiError> IntoResponse for ApiRejection<E> {
    fn into_response(self) -> Response {
        match self {
            ApiRejection::Malformed {
                status,
                slug,
                message,
            } => envelope(status, slug, message),
            ApiRejection::Domain(e) => envelope(e.status(), e.slug(), e.to_string()),
        }
    }
}

/// Unknown path. Without this axum returns an empty body, breaking clients
/// that always parse the error envelope.
pub async fn not_found() -> Response {
    envelope(
        StatusCode::NOT_FOUND,
        "not-found",
        "no endpoint at this path".to_string(),
    )
}

/// Known path, wrong method.
pub async fn method_not_allowed() -> Response {
    envelope(
        StatusCode::METHOD_NOT_ALLOWED,
        "method-not-allowed",
        "this endpoint does not accept that method".to_string(),
    )
}

/// For an endpoint that can only fail at the body.
///
/// `/keys/generate` reads two optional flags and draws from an RNG — past
/// `Json` extraction there is nothing left to reject. Declaring
/// `ApiRejection<Infallible>` says that in the type, and the compiler enforces
/// it: the day that endpoint grows a failure, this stops compiling rather than
/// letting a real error be mapped onto a status somebody guessed. Every method
/// here is unreachable by construction, which is what `match *self {}` means.
impl ApiError for std::convert::Infallible {
    fn status(&self) -> StatusCode {
        match *self {}
    }

    fn slug(&self) -> &'static str {
        match *self {}
    }
}

/// A route that is wired up but has no implementation yet.
#[derive(Debug)]
pub struct NotImplemented(pub &'static str);

impl fmt::Display for NotImplemented {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the {} endpoint is not implemented yet", self.0)
    }
}

impl ApiError for NotImplemented {
    fn status(&self) -> StatusCode {
        StatusCode::NOT_IMPLEMENTED
    }

    fn slug(&self) -> &'static str {
        "not-implemented"
    }
}

/// Shared by every endpoint that accepts hex, so the vocabulary for "you sent
/// me something unusable" is identical across the API.
impl ApiError for InputError {
    fn status(&self) -> StatusCode {
        match self {
            InputError::Empty { .. } | InputError::Hex(_) => StatusCode::BAD_REQUEST,
            InputError::TooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }

    fn slug(&self) -> &'static str {
        match self {
            InputError::Empty { .. } => "empty-input",
            InputError::TooLarge { .. } => "input-too-large",
            InputError::Hex(_) => "invalid-hex",
        }
    }
}

/// A service error presents as whichever half of it failed, so an endpoint
/// only has to describe its own domain error.
impl<E: ApiError> ApiError for ServiceError<E> {
    fn status(&self) -> StatusCode {
        match self {
            ServiceError::Input(e) => e.status(),
            ServiceError::Domain(e) => e.status(),
        }
    }

    fn slug(&self) -> &'static str {
        match self {
            ServiceError::Input(e) => e.slug(),
            ServiceError::Domain(e) => e.slug(),
        }
    }
}
