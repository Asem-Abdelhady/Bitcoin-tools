//! HTTP surface for `/tools`.
//!
//! ## The response keys are the domain's own spellings
//!
//! `/tools/number` answers under `binary`, `decimal` and `hexadecimal`;
//! `/tools/units` under `satoshi`, `microbitcoin`, `millibitcoin` and
//! `bitcoin`. Those are not new names invented here — they are exactly what
//! [`Base`](bitcoin_tools_core::general::Base) and
//! [`Denomination`](bitcoin_tools_core::general::Denomination) serialize as,
//! which is what the *request* field takes. So the token a caller sends and
//! the key they read the answer under are the same token, and a client can
//! round-trip one field into the other without a translation table.
//!
//! `a_units_response_names_every_denomination_the_domain_has` pins that
//! mechanically, by generating the expected keys from
//! [`Denomination::all`](bitcoin_tools_core::general::Denomination::all)
//! rather than restating them — and the same test is why
//! `a_missing_or_unknown_denomination_is_refused` generates its expected
//! message instead of grepping for `"bitcoin"`, which `microbitcoin` would
//! satisfy on its own.
//!
//! **That guarantee is one-directional for `/tools/number`.**
//! [`Base`](bitcoin_tools_core::general::Base) exposes no `all()` to generate
//! from, so `a_number_response_answers_in_every_base_it_accepts` names its
//! three bases and feeds each rendering back in as a request. That catches a
//! key that renders wrongly; it would not catch a *fourth* base added to the
//! enum and forgotten here. Known, and cheap to fix the day there is one —
//! `Denomination` is exhaustive by design and `Base` is `#[non_exhaustive]`,
//! so the two are not the same shape of promise.

pub mod number;
pub mod reverse;
pub mod units;
