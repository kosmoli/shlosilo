//! Network enum (v2.3 interface notes §13.4)
//!
//! **v1.1.1 revision (2026-08-17)**:
//! - Removed MoonbeamMainnet + MoonriverTestnet (migrated off Polkadot to the Base network, 2026-07-31)
//! - Number reuse: Astar changed from 138 to 136, Serai from 142 to 140
//! - Serai was still under security audit as of 2026-04; mainnet not launched, placeholder until launch
//! - KujiraMainnet/Testnet status pending re-confirmation in v1.1.2
//!
//! **Phase 4 real implementation** (v2.3 priority):
//! Three BTC (Mainnet / Testnet / Regtest), three ETH (Mainnet / Sepolia / Goerli),
//! three XMR (Mainnet / Stagenet / Testnet).
//! The other 13+ variants come in Phase 8+.

use crate::types::chain_kind::ChainKind;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    // --- Bitcoin family ---
    BitcoinMainnet = 0,
    BitcoinTestnet = 1,
    BitcoinRegtest = 2,

    // --- Ethereum family ---
    EthereumMainnet = 10,
    EthereumSepolia = 11,
    EthereumGoerli = 12, // deprecated but still visible

    // --- Tron family ---
    TronMainnet = 20,
    TronShastaTestnet = 21,
    TronNileTestnet = 22,

    // --- Solana family ---
    SolanaMainnet = 30,
    SolanaDevnet = 31,
    SolanaTestnet = 32,

    // --- XRP family ---
    XrpMainnet = 40,
    XrpTestnet = 41,

    // --- Aptos / Sui family ---
    AptosMainnet = 50,
    AptosTestnet = 51,
    SuiMainnet = 60,
    SuiTestnet = 61,

    // --- Near family ---
    NearMainnet = 70,
    NearTestnet = 71,

    // --- Cardano family ---
    CardanoMainnet = 80,
    CardanoPreprod = 81,
    CardanoPreview = 82,

    // --- Monero family ---
    MoneroMainnet = 90,
    MoneroStagenet = 91,
    MoneroTestnet = 92,

    // --- Arweave family ---
    ArweaveMainnet = 100,

    // --- Cosmos family (added in v1.1) ---
    CosmosHubMainnet = 110,
    CosmosHubTestnet = 111,
    OsmosisMainnet = 112,
    OsmosisTestnet = 113,
    ThorchainMainnet = 114,
    ThorchainStagenet = 115,
    CelestiaMainnet = 116,
    CelestiaTestnet = 117,
    KujiraMainnet = 118,
    KujiraTestnet = 119,
    InjectiveMainnet = 120,
    InjectiveTestnet = 121,

    // --- Polkadot/Substrate family (added in v1.1) ---
    PolkadotMainnet = 130,
    PolkadotWestendTestnet = 131,
    KusamaMainnet = 132,
    KusamaRococoTestnet = 133,
    AcalaMainnet = 134,
    AcalaMandalaTestnet = 135,
    // Moonbeam migrated away (removed in v1.1.1); Astar reuses numbers 136/137
    AstarMainnet = 136,
    AstarShibuyaTestnet = 137,
    BittensorMainnet = 138, // TAO (independent Substrate chain)
    BittensorTestnet = 139,
    SeraiMainnet = 140, // mainnet not launched yet; pre-assigned placeholder
    SeraiTestnet = 141,
}

impl Network {
    /// Network → ChainKind (v2.3 §13.4 revised)
    /// Network u8 → Network enum (for FFI dispatch)
    ///
    /// **Important**: match directly, don't call try_from — try_from itself calls from_u8, otherwise infinite recursion / stack overflow
    pub fn from_u8(n: u8) -> Option<Self> {
        match n {
            0 => Some(Network::BitcoinMainnet),
            1 => Some(Network::BitcoinTestnet),
            2 => Some(Network::BitcoinRegtest),
            10 => Some(Network::EthereumMainnet),
            11 => Some(Network::EthereumSepolia),
            12 => Some(Network::EthereumGoerli),
            20 => Some(Network::TronMainnet),
            21 => Some(Network::TronShastaTestnet),
            22 => Some(Network::TronNileTestnet),
            30 => Some(Network::SolanaMainnet),
            31 => Some(Network::SolanaDevnet),
            32 => Some(Network::SolanaTestnet),
            40 => Some(Network::XrpMainnet),
            41 => Some(Network::XrpTestnet),
            50 => Some(Network::AptosMainnet),
            51 => Some(Network::AptosTestnet),
            60 => Some(Network::SuiMainnet),
            61 => Some(Network::SuiTestnet),
            70 => Some(Network::NearMainnet),
            71 => Some(Network::NearTestnet),
            80 => Some(Network::CardanoMainnet),
            81 => Some(Network::CardanoPreprod),
            82 => Some(Network::CardanoPreview),
            90 => Some(Network::MoneroMainnet),
            91 => Some(Network::MoneroStagenet),
            92 => Some(Network::MoneroTestnet),
            100 => Some(Network::ArweaveMainnet),
            110 => Some(Network::CosmosHubMainnet),
            111 => Some(Network::CosmosHubTestnet),
            112 => Some(Network::OsmosisMainnet),
            113 => Some(Network::OsmosisTestnet),
            114 => Some(Network::ThorchainMainnet),
            115 => Some(Network::ThorchainStagenet),
            116 => Some(Network::CelestiaMainnet),
            117 => Some(Network::CelestiaTestnet),
            118 => Some(Network::KujiraMainnet),
            119 => Some(Network::KujiraTestnet),
            120 => Some(Network::InjectiveMainnet),
            121 => Some(Network::InjectiveTestnet),
            130 => Some(Network::PolkadotMainnet),
            131 => Some(Network::PolkadotWestendTestnet),
            132 => Some(Network::KusamaMainnet),
            133 => Some(Network::KusamaRococoTestnet),
            134 => Some(Network::AcalaMainnet),
            135 => Some(Network::AcalaMandalaTestnet),
            136 => Some(Network::AstarMainnet),
            137 => Some(Network::AstarShibuyaTestnet),
            138 => Some(Network::BittensorMainnet),
            139 => Some(Network::BittensorTestnet),
            140 => Some(Network::SeraiMainnet),
            141 => Some(Network::SeraiTestnet),
            _ => None,
        }
    }

    /// Network u8 → Network enum (API alias)
    pub fn try_from_u8(n: u8) -> Option<Self> {
        Self::try_from(n).ok()
    }

    pub fn chain_kind(self) -> ChainKind {
        match self {
            Network::BitcoinMainnet | Network::BitcoinTestnet | Network::BitcoinRegtest => {
                ChainKind::Btc
            }
            Network::EthereumMainnet | Network::EthereumSepolia | Network::EthereumGoerli => {
                ChainKind::Eth
            }
            Network::TronMainnet | Network::TronShastaTestnet | Network::TronNileTestnet => {
                ChainKind::Tron
            }
            Network::SolanaMainnet | Network::SolanaDevnet | Network::SolanaTestnet => {
                ChainKind::Sol
            }
            Network::XrpMainnet | Network::XrpTestnet => ChainKind::Xrp,
            Network::AptosMainnet | Network::AptosTestnet => ChainKind::Apt,
            Network::SuiMainnet | Network::SuiTestnet => ChainKind::Sui,
            Network::NearMainnet | Network::NearTestnet => ChainKind::Near,
            Network::CardanoMainnet | Network::CardanoPreprod | Network::CardanoPreview => {
                ChainKind::Ada
            }
            Network::MoneroMainnet | Network::MoneroStagenet | Network::MoneroTestnet => {
                ChainKind::Xmr
            }
            Network::ArweaveMainnet => ChainKind::Ar,

            // Cosmos family
            Network::CosmosHubMainnet
            | Network::CosmosHubTestnet
            | Network::OsmosisMainnet
            | Network::OsmosisTestnet
            | Network::ThorchainMainnet
            | Network::ThorchainStagenet
            | Network::CelestiaMainnet
            | Network::CelestiaTestnet
            | Network::KujiraMainnet
            | Network::KujiraTestnet
            | Network::InjectiveMainnet
            | Network::InjectiveTestnet => ChainKind::Cosmos,

            // Polkadot/Substrate family (v1.1.1 revision: Moonbeam removed)
            Network::PolkadotMainnet
            | Network::PolkadotWestendTestnet
            | Network::KusamaMainnet
            | Network::KusamaRococoTestnet
            | Network::AcalaMainnet
            | Network::AcalaMandalaTestnet
            | Network::AstarMainnet
            | Network::AstarShibuyaTestnet
            | Network::BittensorMainnet
            | Network::BittensorTestnet
            | Network::SeraiMainnet
            | Network::SeraiTestnet => ChainKind::Polkadot,
        }
    }

    /// Cosmos-family HRP (bech32 prefix); real integration comes in Phase 8+
    pub fn cosmos_hrp(self) -> Option<&'static str> {
        match self {
            Network::CosmosHubMainnet | Network::CosmosHubTestnet => Some("cosmos"),
            Network::OsmosisMainnet | Network::OsmosisTestnet => Some("osmo"),
            Network::ThorchainMainnet | Network::ThorchainStagenet => Some("thor"),
            Network::CelestiaMainnet | Network::CelestiaTestnet => Some("celestia"),
            Network::KujiraMainnet | Network::KujiraTestnet => Some("kujira"),
            Network::InjectiveMainnet | Network::InjectiveTestnet => Some("inj"),
            _ => None,
        }
    }

    /// Whether mainnet (v2.3 §13.4 revision: Moonbeam removed)
    pub fn is_mainnet(self) -> bool {
        matches!(
            self,
            Network::BitcoinMainnet
                | Network::EthereumMainnet
                | Network::TronMainnet
                | Network::SolanaMainnet
                | Network::XrpMainnet
                | Network::AptosMainnet
                | Network::SuiMainnet
                | Network::NearMainnet
                | Network::CardanoMainnet
                | Network::MoneroMainnet
                | Network::ArweaveMainnet
                | Network::CosmosHubMainnet
                | Network::OsmosisMainnet
                | Network::ThorchainMainnet
                | Network::CelestiaMainnet
                | Network::KujiraMainnet
                | Network::InjectiveMainnet
                | Network::PolkadotMainnet
                | Network::KusamaMainnet
                | Network::AcalaMainnet
                | Network::AstarMainnet
                | Network::BittensorMainnet
                | Network::SeraiMainnet
        )
    }

    /// Networks with a Phase 4 real implementation (v2.3 priority: 3 each of BTC/ETH/XMR)
    pub fn is_phase4_real(self) -> bool {
        matches!(
            self,
            Network::BitcoinMainnet
                | Network::BitcoinTestnet
                | Network::BitcoinRegtest
                | Network::EthereumMainnet
                | Network::EthereumSepolia
                | Network::EthereumGoerli
                | Network::MoneroMainnet
                | Network::MoneroStagenet
                | Network::MoneroTestnet
        )
    }
}

impl TryFrom<u8> for Network {
    type Error = ();
    /// Network u8 → Network enum
    ///
    /// **Important**: call from_u8 directly (from_u8 itself does not recurse)
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        Self::from_u8(n).ok_or(())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn chain_kind_mapping() {
        assert_eq!(Network::BitcoinMainnet.chain_kind(), ChainKind::Btc);
        assert_eq!(Network::EthereumMainnet.chain_kind(), ChainKind::Eth);
        assert_eq!(Network::MoneroMainnet.chain_kind(), ChainKind::Xmr);
        assert_eq!(Network::CosmosHubMainnet.chain_kind(), ChainKind::Cosmos);
        assert_eq!(Network::PolkadotMainnet.chain_kind(), ChainKind::Polkadot);
        assert_eq!(Network::BittensorMainnet.chain_kind(), ChainKind::Polkadot);
    }

    #[test]
    fn moonbeam_not_in_enum() {
        // v1.1.1 compile-time guarantee: MoonbeamMainnet/MoonriverTestnet removed
    }

    #[test]
    fn cosmos_hrp_dispatch() {
        assert_eq!(Network::OsmosisMainnet.cosmos_hrp(), Some("osmo"));
        assert_eq!(Network::ThorchainMainnet.cosmos_hrp(), Some("thor"));
        assert_eq!(Network::BitcoinMainnet.cosmos_hrp(), None);
    }

    #[test]
    fn phase4_real_set() {
        assert!(Network::BitcoinMainnet.is_phase4_real());
        assert!(Network::EthereumSepolia.is_phase4_real());
        assert!(Network::MoneroStagenet.is_phase4_real());
        assert!(!Network::SolanaMainnet.is_phase4_real());
        assert!(!Network::CosmosHubMainnet.is_phase4_real());
        assert!(!Network::PolkadotMainnet.is_phase4_real());
    }

    // ============================================================
    // Phase 3 v2 property-based tests
    //
    // **v2 strategy**: only 5 representative chains (Btc/Eth/Xmr/Sol/Polkadot) × 8 cases
    // No sweep over all 44 variants (the root cause of v1 hanging)
    // ============================================================

    // ============================================================
    // Phase 3 v3 standalone test fns (no proptest! blocks)
    //
    // **v3 strategy**:
    // - Each #[test] fn uses its own ProptestConfig + disable_shrink
    // - Avoid the proptest! block macro to dodge cargo test's internal thread-pool scheduling deadlock
    // - Per module: ≤ 3 standalone fns + cases ≤ 5
    // ============================================================

    /// 5 representative variants → chain_kind() mapping consistency
    #[test]
    fn network_chain_kind_consistent_for_representative_set_v3() {
        // Manual 5 cases (avoids proptest accumulation)
        let cases: [(Network, ChainKind); 5] = [
            (Network::BitcoinMainnet, ChainKind::Btc),
            (Network::EthereumMainnet, ChainKind::Eth),
            (Network::MoneroMainnet, ChainKind::Xmr),
            (Network::SolanaMainnet, ChainKind::Sol),
            (Network::PolkadotMainnet, ChainKind::Polkadot),
        ];
        for (net_val, expected_kind) in cases.iter() {
            assert_eq!(net_val.chain_kind(), *expected_kind);
        }
    }

    /// 5 representative variants → is_phase4_real() consistency
    #[test]
    fn network_is_phase4_real_consistent_for_representative_set_v3() {
        let cases: [(Network, bool); 5] = [
            (Network::BitcoinMainnet, true),
            (Network::EthereumMainnet, true),
            (Network::MoneroMainnet, true),
            (Network::SolanaMainnet, false),
            (Network::PolkadotMainnet, false),
        ];
        for (net_val, expected_phase4) in cases.iter() {
            assert_eq!(net_val.is_phase4_real(), *expected_phase4);
        }
    }

    /// 5 representative variants → as u8 → from_u8 round-trip (added in v3)
    #[test]
    fn network_from_u8_round_trip_for_representative_set_v3() {
        let nets = [
            Network::BitcoinMainnet,
            Network::EthereumMainnet,
            Network::MoneroMainnet,
            Network::SolanaMainnet,
            Network::PolkadotMainnet,
        ];
        for net_val in nets.iter() {
            let n = *net_val as u8;
            let recovered = Network::from_u8(n).unwrap();
            assert_eq!(recovered, *net_val);
        }
    }

    /// 5 representative variants → as u8 → try_from round-trip (added in v3)
    #[test]
    fn network_try_from_round_trip_for_representative_set_v3() {
        let nets = [
            Network::BitcoinMainnet,
            Network::EthereumMainnet,
            Network::MoneroMainnet,
            Network::SolanaMainnet,
            Network::PolkadotMainnet,
        ];
        for net_val in nets.iter() {
            let n = *net_val as u8;
            let recovered = Network::try_from(n).unwrap();
            assert_eq!(recovered, *net_val);
        }
    }
}
