//! Naming a small enum, once.
//!
//! Private to the crate and not part of its public API — it generates public
//! items, but nothing here is reachable from outside.
//!
//! Two shapes. The full one gives `as_str`, `Display`, `FromStr` and an
//! `Unknown…` error; the `spelling` one gives the first two and the serde
//! `Serialize` that follows from them, for an enum that is written but never
//! read from text.
//!
//! Three types wanted the identical forty lines: [`Network`](crate::network),
//! [`Base`](crate::general::Base) and
//! [`Denomination`](crate::general::Denomination) each name a small closed set
//! of choices, each spell one of those names in `as_str` and `Display`, each
//! read one back in `FromStr` accepting aliases case-insensitively, and each
//! carry an `Unknown…` error holding the string that failed. This stopped at
//! the third copy rather than the fifth because two more were already queued:
//! [`Purpose`](crate::hd::Purpose) landed on it in 4.2 and is the fourth.
//!
//! The fifth, an address-type enum, wanted only half of it. `AddressKind`
//! names five output types but nothing parses one from text — an address is
//! read from the address, not from someone naming its type — so it takes the
//! `spelling` form below, which stops at `as_str`, `Display` and the serde
//! `Serialize` that follows from them. `Base58Kind` and
//! [`Variant`](crate::encoding::bech32::Variant) are the same. That arm exists
//! because the alternative was a canonical name living only inside
//! `#[serde(rename_all)]`: invisible with `serde` off, and duplicated with it
//! on.
//!
//! The generated error types stay distinct — `UnknownNetwork` is not
//! `UnknownBase` — so a caller can still write `impl From<UnknownNetwork>` for
//! its own error. A single generic `Unknown<T>` would have collapsed them into
//! one type and taken that away.

/// Give an enum `as_str`, `Display`, `FromStr`, and its own `Unknown…` error.
///
/// The first spelling of each variant is canonical: it is what `as_str` and
/// `Display` produce. Every spelling listed, canonical included, is accepted by
/// `FromStr`, compared with `eq_ignore_ascii_case` against the trimmed input.
///
/// Comparing per spelling rather than lowercasing the input first is
/// deliberate. It means a table lists each spelling *once*, whatever its case:
/// `µBTC` is matched by `µbtc` without the folded form having to appear beside
/// it. The alternative — lowercase the input, match lowercase literals — makes
/// a canonical spelling that is not already lowercase (`µBTC`, `mBTC`) into an
/// arm that can never fire, and a table that forgets its folded twin then
/// writes a name it cannot read back. That failure is invisible except to a
/// round-trip test, which is a bad property for the thing every future named
/// enum copies. It also avoids allocating a `String` on every parse.
///
/// The cost is that `unreachable_patterns` no longer catches one literal
/// duplicated across two variants. That error is visible in the table.
macro_rules! name_table {
    (
        $(#[$from_str_doc:meta])*
        $enum:ident => $error:ident,
        kind: $kind:literal,
        expected: $expected:literal,
        {
            $( $variant:ident => $($spelling:literal),+ ; )*
        }
    ) => {
        impl $enum {
            #[doc = concat!("The name used on the wire and in this type's `Display` and `FromStr`.")]
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $enum::$variant => name_table!(@canonical $($spelling),+), )*
                }
            }
        }

        impl ::std::fmt::Display for $enum {
            /// Honours width and alignment, so these line up in a column.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.pad(self.as_str())
            }
        }

        #[doc = concat!("The string given to `", stringify!($enum), "::from_str` named no known ", $kind, ".")]
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $error(String);

        impl $error {
            /// The string that was not recognised.
            #[must_use]
            pub fn input(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $error {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                write!(
                    f,
                    concat!("unknown ", $kind, " {:?}: expected ", $expected),
                    self.0
                )
            }
        }

        impl ::std::error::Error for $error {}

        impl ::std::str::FromStr for $enum {
            type Err = $error;

            $(#[$from_str_doc])*
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let trimmed = s.trim();
                $(
                    if $( trimmed.eq_ignore_ascii_case($spelling) )||+ {
                        return Ok($enum::$variant);
                    }
                )*
                Err($error(trimmed.to_owned()))
            }
        }
    };

    // Spelling only: `as_str` and `Display`, no `FromStr` and no error type.
    //
    // For an enum that is *written* but never read from text.
    // [`AddressKind`](crate::keys::AddressKind) is the case: it names five
    // output types, but nothing parses one — an address is read from the
    // address, not from someone naming its type. Without this arm such an
    // enum has its canonical spelling only inside `#[serde(rename_all)]`,
    // which means it has no spelling at all with `serde` off, and two copies
    // of one with it on.
    (
        spelling $enum:ident {
            $( $variant:ident => $spelling:literal; )*
        }
    ) => {
        impl $enum {
            #[doc = concat!("The name used on the wire and in this type's `Display`.")]
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( $enum::$variant => $spelling, )*
                }
            }
        }

        impl ::std::fmt::Display for $enum {
            /// Honours width and alignment, so these line up in a column.
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.pad(self.as_str())
            }
        }

        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $enum {
            /// The same spelling `Display` gives, so there is only one.
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
    };

    // The first spelling in a variant's list is the one written back out.
    (@canonical $canonical:literal $(, $alias:literal)*) => { $canonical };
}

/// Give a type the serde `Serialize` that follows from its `Display`.
///
/// Fifteen types in this crate serialize as the string their `Display`
/// produces, which is the crate's JSON convention: the wire spelling and the
/// printed spelling are one definition rather than two that drift. Written by
/// hand that is a six-line block with a `#[cfg(feature = "serde")]` above it,
/// fifteen times — and the gate is the part that is easy to forget, because
/// nothing notices until someone builds with `--no-default-features`.
///
/// `name_table!` already emits this impl for the enums it generates; this is
/// the same impl for everything else. [`Hash<N>`](crate::hashes::Hash) keeps
/// its own, being generic over a const parameter.
macro_rules! display_serialize {
    ($type:ty) => {
        #[cfg(feature = "serde")]
        impl ::serde::Serialize for $type {
            /// The same spelling `Display` gives, so there is only one.
            fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
    };
}

pub(crate) use {display_serialize, name_table};
