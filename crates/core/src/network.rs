//! Which Bitcoin network a value belongs to.
//!
//! Lives at the root rather than under [`keys`](crate::keys) because four
//! unrelated features key tables off it: WIF prefixes, Base58 address version
//! bytes, BIP32 extended-key versions, and Bech32 human-readable parts. If it
//! lived with any one of them the others would import sideways for no reason.
//!
//! Each of those tables belongs to the module that owns the format, not here —
//! this module knows only that the four networks exist.

use crate::parse::name_table;

/// A Bitcoin network.
///
/// Testnet means testnet3. Signet means the default signet; custom signets
/// share its parameters, so they are not distinguished here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
#[non_exhaustive]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    /// True only for mainnet.
    ///
    /// The three test networks share prefixes and HRPs almost everywhere, so
    /// most tables are really a two-way split. Asking this is clearer at the
    /// call site than matching all four and grouping three of them.
    #[must_use]
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Network::Mainnet)
    }
}

name_table! {
    /// Accepts the canonical names case-insensitively, plus the aliases
    /// `bitcoin` and `main` for mainnet and `test` for testnet, which is what
    /// Core's `-chain` flag and most tooling emit.
    Network => UnknownNetwork,
    kind: "network",
    expected: "mainnet, testnet, signet, or regtest",
    {
        Mainnet => "mainnet", "bitcoin", "main";
        Testnet => "testnet", "test", "testnet3";
        Signet  => "signet";
        Regtest => "regtest";
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_from_str_round_trip() {
        for n in [
            Network::Mainnet,
            Network::Testnet,
            Network::Signet,
            Network::Regtest,
        ] {
            assert_eq!(n.to_string().parse(), Ok(n));
        }
    }

    #[test]
    fn accepts_the_aliases_other_tools_emit() {
        assert_eq!("bitcoin".parse(), Ok(Network::Mainnet));
        assert_eq!("  MAIN ".parse(), Ok(Network::Mainnet));
        assert_eq!("test".parse(), Ok(Network::Testnet));
        assert_eq!(
            "mainet".parse::<Network>(),
            Err(UnknownNetwork("mainet".to_owned()))
        );
    }

    #[test]
    fn only_mainnet_is_mainnet() {
        assert!(Network::Mainnet.is_mainnet());
        for n in [Network::Testnet, Network::Signet, Network::Regtest] {
            assert!(!n.is_mainnet(), "{n} claimed to be mainnet");
        }
    }
}
