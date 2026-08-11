//! Bitcoin script opcodes.
//!
//! An `Opcode` is a newtype over `u8` rather than an enum, for three reasons:
//!
//! * every one of the 256 byte values is representable, so decoding a script
//!   can never fail on an unknown byte — it reports it instead;
//! * 0x01..=0x4b are 75 "push this many bytes" opcodes that are one concept,
//!   not 75 names worth carrying through every `match`;
//! * the meaning of a byte depends on the script context. 0xba is
//!   `OP_CHECKSIGADD` in tapscript and unassigned everywhere else, and
//!   0xbb..=0xfe are unassigned in legacy but `OP_SUCCESSx` in tapscript.
//!   Encoding *the byte* lets one type serve all three contexts; encoding
//!   *the meaning* would need one enum per context.

use std::fmt;

/// A single script opcode. Any `u8` is a valid `Opcode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Opcode(u8);

impl Opcode {
    /// Total and infallible: every byte is some opcode.
    pub const fn from_u8(b: u8) -> Self {
        Opcode(b)
    }

    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// Number of data bytes this opcode pushes directly (0x01..=0x4b only).
    ///
    /// `OP_PUSHDATA1/2/4` return `None`: their length lives in the bytes that
    /// follow, so the decoder resolves it, not the opcode.
    pub const fn push_len(self) -> Option<usize> {
        match self.0 {
            b @ 0x01..=0x4b => Some(b as usize),
            _ => None,
        }
    }

    /// Width in bytes of the length prefix this opcode reads from the script.
    /// `None` for everything that is not `OP_PUSHDATA1/2/4`.
    pub const fn pushdata_width(self) -> Option<usize> {
        match self.0 {
            0x4c => Some(1),
            0x4d => Some(2),
            0x4e => Some(4),
            _ => None,
        }
    }

    /// True for the opcodes that consume a length prefix from the script.
    pub const fn is_pushdata(self) -> bool {
        self.pushdata_width().is_some()
    }

    /// Largest payload this push opcode can express, or `None` if it does not
    /// push data from the byte stream.
    ///
    /// A direct push (0x01..=0x4b) can only carry exactly its own value, so
    /// its maximum is also its minimum.
    pub const fn push_max_len(self) -> Option<usize> {
        match self.0 {
            b @ 0x01..=0x4b => Some(b as usize),
            0x4c => Some(u8::MAX as usize),
            0x4d => Some(u16::MAX as usize),
            0x4e => Some(u32::MAX as usize),
            _ => None,
        }
    }

    /// True if this opcode pushes a value of any kind (data, number, or empty).
    pub const fn is_push(self) -> bool {
        matches!(
            self.category(),
            Category::PushBytes | Category::PushData | Category::PushNum
        )
    }

    /// BIP342: in tapscript these bytes make the whole script succeed
    /// immediately, and are reserved for future soft forks. In legacy and
    /// segwit v0 the same bytes are disabled, reserved, or unassigned.
    pub const fn is_tapscript_success(self) -> bool {
        matches!(self.0,
            0x50 | 0x62 | 0x7e..=0x81 | 0x83..=0x86 | 0x89 | 0x8a
            | 0x8d | 0x8e | 0x95..=0x99 | 0xbb..=0xfe)
    }
}

/// Broad grouping, for syntax-highlighting and for flagging scripts that use
/// opcodes which can never execute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "kebab-case"))]
#[non_exhaustive]
pub enum Category {
    /// 0x01..=0x4b — push the next N bytes.
    PushBytes,
    /// `OP_PUSHDATA1/2/4` — push with an explicit length prefix.
    PushData,
    /// `OP_0`, `OP_1NEGATE`, `OP_1`..`OP_16`.
    PushNum,
    /// Branching and early exit.
    Control,
    /// Stack and altstack shuffling.
    Stack,
    /// String operators (all disabled except `OP_SIZE`).
    Splice,
    /// Bitwise and equality.
    Logic,
    /// Numeric.
    Arithmetic,
    /// Hashing and signature checking.
    Crypto,
    /// `OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY`.
    Locktime,
    /// No-ops reserved for future soft forks.
    Nop,
    /// Removed in 2010; presence makes the script unspendable.
    Disabled,
    /// Aborts the script if executed.
    Reserved,
    /// No assigned meaning (but see [`Opcode::is_tapscript_success`]).
    Unassigned,
}

macro_rules! define_opcodes {
    ($( $byte:literal, $name:ident, $cat:ident, $doc:literal; )*) => {
        /// Every named opcode, as constants.
        pub mod all {
            use super::Opcode;
            $( #[doc = $doc] pub const $name: Opcode = Opcode($byte); )*
        }

        impl Opcode {
            const fn named(self) -> Option<&'static str> {
                match self.0 {
                    $( $byte => Some(stringify!($name)), )*
                    _ => None,
                }
            }

            /// What this opcode does, for display in a decoder UI.
            pub const fn describe(self) -> Option<&'static str> {
                match self.0 {
                    $( $byte => Some($doc), )*
                    0x01..=0x4b => Some("Push the next N bytes onto the stack"),
                    _ => None,
                }
            }

            pub const fn category(self) -> Category {
                match self.0 {
                    $( $byte => Category::$cat, )*
                    0x01..=0x4b => Category::PushBytes,
                    _ => Category::Unassigned,
                }
            }
        }
    };
}

#[rustfmt::skip]
define_opcodes! {
    0x00, OP_0,                     PushNum,    "Push an empty byte vector";
    0x4c, OP_PUSHDATA1,             PushData,   "Next 1 byte is the push length";
    0x4d, OP_PUSHDATA2,             PushData,   "Next 2 bytes (LE) are the push length";
    0x4e, OP_PUSHDATA4,             PushData,   "Next 4 bytes (LE) are the push length";
    0x4f, OP_1NEGATE,               PushNum,    "Push -1";
    0x50, OP_RESERVED,              Reserved,   "Abort unless in an unexecuted branch";
    0x51, OP_1,                     PushNum,    "Push 1";
    0x52, OP_2,                     PushNum,    "Push 2";
    0x53, OP_3,                     PushNum,    "Push 3";
    0x54, OP_4,                     PushNum,    "Push 4";
    0x55, OP_5,                     PushNum,    "Push 5";
    0x56, OP_6,                     PushNum,    "Push 6";
    0x57, OP_7,                     PushNum,    "Push 7";
    0x58, OP_8,                     PushNum,    "Push 8";
    0x59, OP_9,                     PushNum,    "Push 9";
    0x5a, OP_10,                    PushNum,    "Push 10";
    0x5b, OP_11,                    PushNum,    "Push 11";
    0x5c, OP_12,                    PushNum,    "Push 12";
    0x5d, OP_13,                    PushNum,    "Push 13";
    0x5e, OP_14,                    PushNum,    "Push 14";
    0x5f, OP_15,                    PushNum,    "Push 15";
    0x60, OP_16,                    PushNum,    "Push 16";
    0x61, OP_NOP,                   Nop,        "Do nothing";
    0x62, OP_VER,                   Reserved,   "Abort unless in an unexecuted branch";
    0x63, OP_IF,                    Control,    "Execute the following if the top item is true";
    0x64, OP_NOTIF,                 Control,    "Execute the following if the top item is false";
    0x65, OP_VERIF,                 Reserved,   "Abort, even in an unexecuted branch";
    0x66, OP_VERNOTIF,              Reserved,   "Abort, even in an unexecuted branch";
    0x67, OP_ELSE,                  Control,    "Invert the enclosing branch condition";
    0x68, OP_ENDIF,                 Control,    "Close the enclosing IF/NOTIF";
    0x69, OP_VERIFY,                Control,    "Abort if the top item is not true";
    0x6a, OP_RETURN,                Control,    "Abort; marks the output provably unspendable";
    0x6b, OP_TOALTSTACK,            Stack,      "Move the top item to the altstack";
    0x6c, OP_FROMALTSTACK,          Stack,      "Move the top altstack item back";
    0x6d, OP_2DROP,                 Stack,      "Drop the top two items";
    0x6e, OP_2DUP,                  Stack,      "Duplicate the top two items";
    0x6f, OP_3DUP,                  Stack,      "Duplicate the top three items";
    0x70, OP_2OVER,                 Stack,      "Copy the third and fourth items to the top";
    0x71, OP_2ROT,                  Stack,      "Rotate the fifth and sixth items to the top";
    0x72, OP_2SWAP,                 Stack,      "Swap the top two pairs";
    0x73, OP_IFDUP,                 Stack,      "Duplicate the top item if it is true";
    0x74, OP_DEPTH,                 Stack,      "Push the stack depth";
    0x75, OP_DROP,                  Stack,      "Drop the top item";
    0x76, OP_DUP,                   Stack,      "Duplicate the top item";
    0x77, OP_NIP,                   Stack,      "Remove the second item";
    0x78, OP_OVER,                  Stack,      "Copy the second item to the top";
    0x79, OP_PICK,                  Stack,      "Copy the nth item to the top";
    0x7a, OP_ROLL,                  Stack,      "Move the nth item to the top";
    0x7b, OP_ROT,                   Stack,      "Rotate the top three items";
    0x7c, OP_SWAP,                  Stack,      "Swap the top two items";
    0x7d, OP_TUCK,                  Stack,      "Copy the top item below the second";
    0x7e, OP_CAT,                   Disabled,   "Disabled: concatenate two items";
    0x7f, OP_SUBSTR,                Disabled,   "Disabled: take a substring";
    0x80, OP_LEFT,                  Disabled,   "Disabled: keep the left substring";
    0x81, OP_RIGHT,                 Disabled,   "Disabled: keep the right substring";
    0x82, OP_SIZE,                  Splice,     "Push the byte length of the top item";
    0x83, OP_INVERT,                Disabled,   "Disabled: bitwise NOT";
    0x84, OP_AND,                   Disabled,   "Disabled: bitwise AND";
    0x85, OP_OR,                    Disabled,   "Disabled: bitwise OR";
    0x86, OP_XOR,                   Disabled,   "Disabled: bitwise XOR";
    0x87, OP_EQUAL,                 Logic,      "Push whether the top two items are equal";
    0x88, OP_EQUALVERIFY,           Logic,      "OP_EQUAL then OP_VERIFY";
    0x89, OP_RESERVED1,             Reserved,   "Abort unless in an unexecuted branch";
    0x8a, OP_RESERVED2,             Reserved,   "Abort unless in an unexecuted branch";
    0x8b, OP_1ADD,                  Arithmetic, "Add 1";
    0x8c, OP_1SUB,                  Arithmetic, "Subtract 1";
    0x8d, OP_2MUL,                  Disabled,   "Disabled: multiply by 2";
    0x8e, OP_2DIV,                  Disabled,   "Disabled: divide by 2";
    0x8f, OP_NEGATE,                Arithmetic, "Flip the sign";
    0x90, OP_ABS,                   Arithmetic, "Absolute value";
    0x91, OP_NOT,                   Arithmetic, "Push whether the top item is zero";
    0x92, OP_0NOTEQUAL,             Arithmetic, "Push whether the top item is non-zero";
    0x93, OP_ADD,                   Arithmetic, "Add the top two items";
    0x94, OP_SUB,                   Arithmetic, "Subtract the top item from the second";
    0x95, OP_MUL,                   Disabled,   "Disabled: multiply";
    0x96, OP_DIV,                   Disabled,   "Disabled: divide";
    0x97, OP_MOD,                   Disabled,   "Disabled: remainder";
    0x98, OP_LSHIFT,                Disabled,   "Disabled: shift left";
    0x99, OP_RSHIFT,                Disabled,   "Disabled: shift right";
    0x9a, OP_BOOLAND,               Arithmetic, "Push whether both items are non-zero";
    0x9b, OP_BOOLOR,                Arithmetic, "Push whether either item is non-zero";
    0x9c, OP_NUMEQUAL,              Arithmetic, "Push whether the two numbers are equal";
    0x9d, OP_NUMEQUALVERIFY,        Arithmetic, "OP_NUMEQUAL then OP_VERIFY";
    0x9e, OP_NUMNOTEQUAL,           Arithmetic, "Push whether the two numbers differ";
    0x9f, OP_LESSTHAN,              Arithmetic, "Push whether second < top";
    0xa0, OP_GREATERTHAN,           Arithmetic, "Push whether second > top";
    0xa1, OP_LESSTHANOREQUAL,       Arithmetic, "Push whether second <= top";
    0xa2, OP_GREATERTHANOREQUAL,    Arithmetic, "Push whether second >= top";
    0xa3, OP_MIN,                   Arithmetic, "Push the smaller of the two";
    0xa4, OP_MAX,                   Arithmetic, "Push the larger of the two";
    0xa5, OP_WITHIN,                Arithmetic, "Push whether a value is in a range";
    0xa6, OP_RIPEMD160,             Crypto,     "RIPEMD-160 of the top item";
    0xa7, OP_SHA1,                  Crypto,     "SHA-1 of the top item";
    0xa8, OP_SHA256,                Crypto,     "SHA-256 of the top item";
    0xa9, OP_HASH160,               Crypto,     "RIPEMD-160 of the SHA-256 of the top item";
    0xaa, OP_HASH256,               Crypto,     "Double SHA-256 of the top item";
    0xab, OP_CODESEPARATOR,         Crypto,     "Mark where signature checking starts";
    0xac, OP_CHECKSIG,              Crypto,     "Verify a signature against a public key";
    0xad, OP_CHECKSIGVERIFY,        Crypto,     "OP_CHECKSIG then OP_VERIFY";
    0xae, OP_CHECKMULTISIG,         Crypto,     "Verify m-of-n signatures";
    0xaf, OP_CHECKMULTISIGVERIFY,   Crypto,     "OP_CHECKMULTISIG then OP_VERIFY";
    0xb0, OP_NOP1,                  Nop,        "Reserved for future soft forks";
    0xb1, OP_CHECKLOCKTIMEVERIFY,   Locktime,   "Abort unless nLockTime has passed (BIP65)";
    0xb2, OP_CHECKSEQUENCEVERIFY,   Locktime,   "Abort unless nSequence has aged (BIP112)";
    0xb3, OP_NOP4,                  Nop,        "Reserved for future soft forks";
    0xb4, OP_NOP5,                  Nop,        "Reserved for future soft forks";
    0xb5, OP_NOP6,                  Nop,        "Reserved for future soft forks";
    0xb6, OP_NOP7,                  Nop,        "Reserved for future soft forks";
    0xb7, OP_NOP8,                  Nop,        "Reserved for future soft forks";
    0xb8, OP_NOP9,                  Nop,        "Reserved for future soft forks";
    0xb9, OP_NOP10,                 Nop,        "Reserved for future soft forks";
    0xba, OP_CHECKSIGADD,           Crypto,     "Tapscript only: increment a counter on valid sig (BIP342)";
    0xff, OP_INVALIDOPCODE,         Unassigned, "Always invalid";
}

/// Aliases for opcodes that go by more than one name.
pub mod alias {
    use super::Opcode;
    use super::all;

    pub const OP_FALSE: Opcode = all::OP_0;
    pub const OP_TRUE: Opcode = all::OP_1;
    /// Renamed by BIP65.
    pub const OP_NOP2: Opcode = all::OP_CHECKLOCKTIMEVERIFY;
    /// Renamed by BIP112.
    pub const OP_NOP3: Opcode = all::OP_CHECKSEQUENCEVERIFY;
    pub const OP_CLTV: Opcode = all::OP_CHECKLOCKTIMEVERIFY;
    pub const OP_CSV: Opcode = all::OP_CHECKSEQUENCEVERIFY;
}

impl fmt::Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.named() {
            return f.write_str(name);
        }
        match self.0 {
            b @ 0x01..=0x4b => write!(f, "OP_PUSHBYTES_{b}"),
            b => write!(f, "OP_UNASSIGNED_{b:02X}"),
        }
    }
}

impl From<u8> for Opcode {
    fn from(b: u8) -> Self {
        Opcode(b)
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> Self {
        op.0
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Opcode {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::all::*;
    use super::*;

    #[test]
    fn every_byte_round_trips() {
        for b in 0..=u8::MAX {
            assert_eq!(Opcode::from_u8(b).to_u8(), b);
        }
    }

    #[test]
    fn names_are_unique() {
        let mut names: Vec<String> = (0..=u8::MAX)
            .map(|b| Opcode::from_u8(b).to_string())
            .collect();
        names.sort();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "duplicate opcode names");
    }

    #[test]
    fn known_values() {
        assert_eq!(OP_DUP.to_u8(), 0x76);
        assert_eq!(OP_HASH160.to_u8(), 0xa9);
        assert_eq!(OP_CHECKSIG.to_u8(), 0xac);
        assert_eq!(OP_CHECKSIGADD.to_u8(), 0xba);
        assert_eq!(OP_DUP.to_string(), "OP_DUP");
        assert_eq!(Opcode::from_u8(0x14).to_string(), "OP_PUSHBYTES_20");
        assert_eq!(Opcode::from_u8(0xbb).to_string(), "OP_UNASSIGNED_BB");
    }

    #[test]
    fn push_lengths() {
        assert_eq!(Opcode::from_u8(0x14).push_len(), Some(20));
        assert_eq!(Opcode::from_u8(0x4b).push_len(), Some(75));
        assert_eq!(OP_PUSHDATA1.push_len(), None);
        assert_eq!(OP_0.push_len(), None);
        assert!(OP_PUSHDATA2.is_pushdata());
        assert!(OP_0.is_push() && OP_16.is_push() && !OP_DUP.is_push());
    }

    #[test]
    fn categories() {
        assert_eq!(OP_MUL.category(), Category::Disabled);
        assert_eq!(OP_CAT.category(), Category::Disabled);
        assert_eq!(OP_CHECKLOCKTIMEVERIFY.category(), Category::Locktime);
        assert_eq!(Opcode::from_u8(0xbb).category(), Category::Unassigned);
    }

    #[test]
    fn tapscript_success_set_matches_bip342() {
        // BIP342 lists these decimal values as OP_SUCCESSx.
        let expected: Vec<u8> = [80u8, 98]
            .into_iter()
            .chain(126..=129)
            .chain(131..=134)
            .chain(137..=138)
            .chain(141..=142)
            .chain(149..=153)
            .chain(187..=254)
            .collect();
        for b in 0..=u8::MAX {
            assert_eq!(
                Opcode::from_u8(b).is_tapscript_success(),
                expected.contains(&b),
                "mismatch at {b:#04x}"
            );
        }
    }

    #[test]
    fn aliases_agree() {
        assert_eq!(alias::OP_NOP2, OP_CHECKLOCKTIMEVERIFY);
        assert_eq!(alias::OP_CSV, OP_CHECKSEQUENCEVERIFY);
        assert_eq!(alias::OP_FALSE, OP_0);
    }
}
