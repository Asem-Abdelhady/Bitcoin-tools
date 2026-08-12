//! § 7 — Elliptic-curve operations over secp256k1.
//!
//! The single point at which this crate touches curve arithmetic. Anything
//! needing a scalar multiply goes through here rather than depending on the
//! backend directly, so swapping the backend is a change to one module.
//!
//! ## Done
//!
//! | File | Feature |
//! |---|---|
//! | `secp.rs` | The one `secp256k1` entry point: context, scalar and point types |
//!
//! ## Planned
//!
//! | File | Feature |
//! |---|---|
//! | `ecdsa.rs` | 7.1 ECDSA Sign, 7.2 ECDSA Verify, `Signature` (DER and compact) |
//!
//! Backend is the `secp256k1` crate — bindings to Bitcoin Core's
//! libsecp256k1, which is constant-time and is what actually validates the
//! chain. It pulls a C dependency, so a wasm build would need this module
//! swapped for a pure-Rust backend; keeping the surface narrow is what makes
//! that possible.
//!
//! ## This module sits *below* `keys`
//!
//! The natural signature for verification is
//! `verify(sig, msg, &keys::PublicKey)`, and taking it would invert the
//! layering: `crypto` is L2 and [`keys`](crate::keys) is L3, so `keys`
//! depends on this module and never the reverse.
//!
//! Sign and verify take the curve types from `secp.rs`. `keys::PublicKey`
//! wraps one and exposes the Bitcoin-specific encodings (compressed,
//! uncompressed, x-only) on top. That is also the honest split: a signature
//! check is about a point on a curve, not about how someone chose to
//! serialize it.

pub mod secp;

pub use secp::{Point, PointError, ScalarError, SecretScalar};
