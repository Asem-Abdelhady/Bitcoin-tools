//! HTTP surface for `/keys`.
//!
//! Nothing shared lives here, unlike [`blocks`](crate::handlers::blocks) where
//! two handlers genuinely read the same eighty bytes. These two endpoints have
//! no common input: one mints a key from an RNG and the other parses one, so
//! the view and the error mapping each sit with their single user.

pub mod generate;
pub mod public;
