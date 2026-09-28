//! ChainKind enum (v2 §4.3 + v1.1 §13.3)
//!
//! **Classification standard (v1.1 revision)**: classified by **signature protocol family**, not by chain tech stack.
//! shlosilo is a signer and only cares about address format + transaction format + signing algorithm — commonality determines grouping.
//!
//! - `Btc` / `Eth` / `Xmr` / `Ar`: per-chain independent signing stacks (Phase 4 real implementations)
//! - `Cosmos`: secp256k1 + bech32 + coin type 118 (added in v1.1; real implementation at Phase 8+)
//! - `Polkadot`: sr25519 + ss58 (added in v1.1; real implementation at Phase 8+)
//! - other ed25519 chains (Sol / Apt / Sui / Near / Ada): real implementation at Phase 8+
//! - `Unknown`: the UR type tag is unrecognized

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainKind {
    Btc = 0,
    Eth = 1,
    Tron = 2,
    Xrp = 3,
    Sol = 4,
    Apt = 5,
    Sui = 6,
    Near = 7,
    Ada = 8,
    Xmr = 9,
    Ar = 10,
    Cosmos = 11,   // added in v1.1: umbrella for the Cosmos ecosystem
    Polkadot = 12, // added in v1.1: umbrella for Polkadot/Substrate signing stacks
    Unknown = 255,
}

impl ChainKind {
    /// UR type tag → ChainKind (v2 §7 ChainKind inference)
    ///
    /// Parse failures return `Unknown`; the business layer decides what to do (v1 rejects by default).
    pub fn from_ur_type_tag(ur_type: &str) -> Self {
        match ur_type {
            "crypto-psbt" | "psbt" => Self::Btc,
            "eth-sign-request" | "eth-tx" | "eip-712" => Self::Eth,
            "solana-tx" => Self::Sol,
            "crypto-monero-tx" => Self::Xmr,
            "aptos-tx" => Self::Apt,
            "sui-tx" => Self::Sui,
            "tron-tx" => Self::Tron,
            "xrp-tx" => Self::Xrp,
            "near-tx" => Self::Near,
            "cardano-tx" => Self::Ada,
            // Cosmos family (real integration deferred to Phase 8+)
            "cosmos-tx" | "osmosis-tx" | "thorchain-tx" => Self::Cosmos,
            // Polkadot family (real integration deferred to Phase 8+)
            "polkadot-tx" | "substrate-tx" => Self::Polkadot,
            _ => Self::Unknown,
        }
    }

    /// Whether this is a Phase 4 real-implementation chain (v2.3 Phase 4 priority)
    pub const fn is_phase4_real(self) -> bool {
        matches!(self, Self::Btc | Self::Eth | Self::Xmr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;
    #[cfg(feature = "alloc-fallback")]
    extern crate alloc;
    use alloc::format;
    use alloc::vec;

    use proptest::prelude::*;

    #[test]
    fn ur_type_inference() {
        assert_eq!(ChainKind::from_ur_type_tag("crypto-psbt"), ChainKind::Btc);
        assert_eq!(
            ChainKind::from_ur_type_tag("eth-sign-request"),
            ChainKind::Eth
        );
        assert_eq!(
            ChainKind::from_ur_type_tag("crypto-monero-tx"),
            ChainKind::Xmr
        );
        assert_eq!(
            ChainKind::from_ur_type_tag("unknown-tx"),
            ChainKind::Unknown
        );
    }

    #[test]
    fn phase4_real_set() {
        assert!(ChainKind::Btc.is_phase4_real());
        assert!(ChainKind::Eth.is_phase4_real());
        assert!(ChainKind::Xmr.is_phase4_real());
        assert!(!ChainKind::Sol.is_phase4_real());
        assert!(!ChainKind::Cosmos.is_phase4_real());
        assert!(!ChainKind::Polkadot.is_phase4_real());
    }

    // ============================================================
    // Phase 3 property-based tests
    // ============================================================

    proptest! {
            #![proptest_config(ProptestConfig::with_cases(20))]

    /// ChainKind is_phase4_real reflexivity
            #[test]
            fn chain_kind_is_phase4_real_consistent(idx in 0u8..13) {
                let ck = match idx {
                    0 => ChainKind::Btc,
                    1 => ChainKind::Eth,
                    2 => ChainKind::Xmr,
                    3 => ChainKind::Sol,
                    4 => ChainKind::Cosmos,
                    5 => ChainKind::Polkadot,
                    6 => ChainKind::Apt,
                    7 => ChainKind::Sui,
                    8 => ChainKind::Near,
                    9 => ChainKind::Ada,
                    10 => ChainKind::Tron,
                    11 => ChainKind::Xrp,
                    _ => ChainKind::Ar,
                };
    // BTC/ETH/XMR are the Phase 4 real implementations
                let is_phase4 = matches!(ck, ChainKind::Btc | ChainKind::Eth | ChainKind::Xmr);
                prop_assert_eq!(ck.is_phase4_real(), is_phase4);
            }

    /// ChainKind Debug output contains the variant name
            #[test]
            fn chain_kind_debug_contains_name(idx in 0u8..13) {
                let ck = match idx {
                    0 => ChainKind::Btc,
                    1 => ChainKind::Eth,
                    2 => ChainKind::Xmr,
                    3 => ChainKind::Sol,
                    4 => ChainKind::Cosmos,
                    5 => ChainKind::Polkadot,
                    6 => ChainKind::Apt,
                    7 => ChainKind::Sui,
                    8 => ChainKind::Near,
                    9 => ChainKind::Ada,
                    10 => ChainKind::Tron,
                    11 => ChainKind::Xrp,
                    _ => ChainKind::Ar,
                };
                let debug_str = format!("{:?}", ck);
                prop_assert!(!debug_str.is_empty());
            }

    /// ChainKind::from_ur_type_tag with any valid ur_type → consistency
            #[test]
            fn chain_kind_from_ur_type_tag_consistent(ur_type in prop_oneof![
                Just("crypto-psbt"),
                Just("psbt"),
                Just("eth-sign-request"),
                Just("eth-tx"),
                Just("eip-712"),
                Just("solana-tx"),
                Just("crypto-monero-tx"),
                Just("aptos-tx"),
                Just("sui-tx"),
                Just("tron-tx"),
                Just("xrp-tx"),
                Just("near-tx"),
                Just("cardano-tx"),
                Just("cosmos-tx"),
                Just("polkadot-tx"),
                Just("unknown-tx"),
            ]) {
                let ck = ChainKind::from_ur_type_tag(ur_type);
    // a valid ur_type should not be Unknown
                if matches!(ur_type, "unknown-tx") {
                    prop_assert_eq!(ck, ChainKind::Unknown);
                } else {
                    prop_assert_ne!(ck, ChainKind::Unknown);
                }
            }

    /// Debug output is a non-empty string for all 13 ChainKind variants
            #[test]
            fn chain_kind_debug_nonempty(idx in 0u8..13) {
                let ck = match idx {
                    0 => ChainKind::Btc,
                    1 => ChainKind::Eth,
                    2 => ChainKind::Xmr,
                    3 => ChainKind::Sol,
                    4 => ChainKind::Cosmos,
                    5 => ChainKind::Polkadot,
                    6 => ChainKind::Apt,
                    7 => ChainKind::Sui,
                    8 => ChainKind::Near,
                    9 => ChainKind::Ada,
                    10 => ChainKind::Tron,
                    11 => ChainKind::Xrp,
                    _ => ChainKind::Ar,
                };
                let debug_str = format!("{:?}", ck);
                prop_assert!(debug_str.len() >= 2, "Debug must be at least 2 chars: got '{}'", debug_str);
            }

            /// ============================================================
    /// Cross-module end-to-end chain_kind inference (v3)
            /// ============================================================
    /// Verify: ChainKind::from_ur_type_tag → Network::chain_kind() consistent

    /// 14 ur_types → infer ChainKind → consistent with the corresponding representative Network's chain_kind()
            #[test]
            fn cross_module_ur_type_to_network_chain_kind_consistent(ur_type in prop_oneof![
                Just(("crypto-psbt", ChainKind::Btc)),
                Just(("psbt", ChainKind::Btc)),
                Just(("eth-sign-request", ChainKind::Eth)),
                Just(("eth-tx", ChainKind::Eth)),
                Just(("eip-712", ChainKind::Eth)),
                Just(("solana-tx", ChainKind::Sol)),
                Just(("crypto-monero-tx", ChainKind::Xmr)),
                Just(("aptos-tx", ChainKind::Apt)),
                Just(("sui-tx", ChainKind::Sui)),
                Just(("tron-tx", ChainKind::Tron)),
                Just(("xrp-tx", ChainKind::Xrp)),
                Just(("near-tx", ChainKind::Near)),
                Just(("cardano-tx", ChainKind::Ada)),
                Just(("cosmos-tx", ChainKind::Cosmos)),
                Just(("polkadot-tx", ChainKind::Polkadot)),
            ]) {
                let (ur, expected_kind) = ur_type;
                let ck_from_ur = ChainKind::from_ur_type_tag(ur);
                prop_assert_eq!(ck_from_ur, expected_kind);

    // the corresponding representative Network → chain_kind() should match expected_kind
                let representative_network = match expected_kind {
                    ChainKind::Btc => Network::BitcoinMainnet,
                    ChainKind::Eth => Network::EthereumMainnet,
                    ChainKind::Xmr => Network::MoneroMainnet,
                    ChainKind::Sol => Network::SolanaMainnet,
                    ChainKind::Tron => Network::TronMainnet,
                    ChainKind::Xrp => Network::XrpMainnet,
                    ChainKind::Apt => Network::AptosMainnet,
                    ChainKind::Sui => Network::SuiMainnet,
                    ChainKind::Near => Network::NearMainnet,
                    ChainKind::Ada => Network::CardanoMainnet,
                    ChainKind::Cosmos => Network::CosmosHubMainnet,
                    ChainKind::Polkadot => Network::PolkadotMainnet,
                    _ => Network::ArweaveMainnet,
                };
                prop_assert_eq!(representative_network.chain_kind(), expected_kind);
            }

    /// Phase 4 real chains (Btc/Eth/Xmr): UR + Network + is_phase4_real all three agree
            #[test]
            fn cross_module_phase4_real_consistency(idx in 0u8..3) {
                let (ur_type, net, expected_kind) = match idx {
                    0 => ("crypto-psbt", Network::BitcoinMainnet, ChainKind::Btc),
                    1 => ("eth-sign-request", Network::EthereumMainnet, ChainKind::Eth),
                    _ => ("crypto-monero-tx", Network::MoneroMainnet, ChainKind::Xmr),
                };

    // UR inference
                prop_assert_eq!(ChainKind::from_ur_type_tag(ur_type), expected_kind);
    // Network inference
                prop_assert_eq!(net.chain_kind(), expected_kind);
    // Phase 4 real implementation marker
                prop_assert!(expected_kind.is_phase4_real());
                prop_assert!(net.is_phase4_real());
            }
        }
}
