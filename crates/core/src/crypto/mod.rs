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
//! | `secp.rs` | The one `secp256k1` entry point: contexts, scalar and point types, and the tweaks BIP32 and BIP340 need |
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
//! The two tweak operations are here for the same reason. BIP32's derivation
//! step and BIP340's taproot tweak are both "add `t * G` to something", which
//! is curve arithmetic; *which* `t`, and what the result means, is decided by
//! [`hd`](crate::hd) and [`keys`](crate::keys) above. The x-only tweak is
//! separate from the plain one because BIP340 normalises parity first, and
//! collapsing the two would give half of all taproot addresses the wrong
//! output key — see [`Point::add_tweak_x_only`](secp::Point::add_tweak_x_only).
//!
//! Sign and verify take the curve types from `secp.rs`. `keys::PublicKey`
//! wraps one and exposes the Bitcoin-specific encodings (compressed,
//! uncompressed, x-only) on top. That is also the honest split: a signature
//! check is about a point on a curve, not about how someone chose to
//! serialize it.

pub mod secp;

pub use secp::{Point, PointError, ScalarError, SecretScalar, TweakError};
