pub mod blocks;
pub mod error;
pub mod hd;
pub mod input;
pub mod keys;
pub mod transactions;

use bitcoin_tools_core::network::Network;

/// Mainnet unless a request says otherwise.
///
/// Here rather than in one feature's module because `/keys` and `/hd` both
/// take a network and must not disagree about the default.
///
/// Deliberately not `Default::default()` on `Network`: the domain declines to
/// define one, and it is right to — a network is a decision, not a fact about
/// the type. Choosing here is a *transport* default for a tool whose users are
/// overwhelmingly looking at mainnet, and it is stated once so it cannot drift.
pub(crate) const fn default_network() -> Network {
    Network::Mainnet
}
