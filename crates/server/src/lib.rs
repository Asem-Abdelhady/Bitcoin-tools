pub mod handlers;
pub mod routes;
pub mod services;

use axum::Router;

/// The composed application.
///
/// Lives here rather than in `main` so tests drive the same URL space clients
/// do — a mistyped `nest` prefix should fail a test, not ship.
pub fn app() -> Router {
    Router::new()
        .nest("/blocks", routes::blocks::router())
        .nest("/crypto", routes::crypto::router())
        .nest("/hd", routes::hd::router())
        .nest("/keys", routes::keys::router())
        .nest("/transactions", routes::transactions::router())
        .fallback(handlers::error::not_found)
        .method_not_allowed_fallback(handlers::error::method_not_allowed)
}
