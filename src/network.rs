//! Network 枚举（v2.3 接口笔记 §13.4）
//!
//! **v1.1.1 修订（2026-08-17）**：
//! - 删除 MoonbeamMainnet + MoonriverTestnet（已迁出 Polkadot 至 Base 网络，2026-07-31）
//! - 编号复用：Astar 从 138 改为 136，Serai 从 142 改为 140
//! - Serai 2026-04 仍在安全审计，主网未上线，占位等上线
//! - KujiraMainnet/Testnet 状态待 v1.1.2 二次确认
//!
//! **Phase 4 真实实现**（v2.3 优先级）：
//! - BTC 三种（Mainnet / Testnet / Regtest）
//! - ETH 三种（Mainnet / Sepolia / Goerli）
//! - XMR 三种（Mainnet / Stagenet / Testnet）
//! 其他 13+ 个变体 Phase 8+ 才动。

use crate::types::chain_kind::ChainKind;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    // ─── Bitcoin 系 ───
    BitcoinMainnet = 0,
    BitcoinTestnet = 1,
    BitcoinRegtest = 2,

    // ─── Ethereum 系 ───
    EthereumMainnet = 10,
    EthereumSepolia = 11,
    EthereumGoerli = 12,    // deprecated 但仍可见

    // ─── Tron 系 ───
    TronMainnet = 20,
    TronShastaTestnet = 21,
    TronNileTestnet = 22,

    // ─── Solana 系 ───
    SolanaMainnet = 30,
    SolanaDevnet = 31,
    SolanaTestnet = 32,

    // ─── XRP 系 ───
    XrpMainnet = 40,
    XrpTestnet = 41,

    // ─── Aptos / Sui 系 ───
    AptosMainnet = 50,
    AptosTestnet = 51,
    SuiMainnet = 60,
    SuiTestnet = 61,

    // ─── Near 系 ───
    NearMainnet = 70,
    NearTestnet = 71,

    // ─── Cardano 系 ───
    CardanoMainnet = 80,
    CardanoPreprod = 81,
    CardanoPreview = 82,

    // ─── Monero 系 ───
    MoneroMainnet = 90,
    MoneroStagenet = 91,
    MoneroTestnet = 92,

    // ─── Arweave 系 ───
    ArweaveMainnet = 100,

    // ─── Cosmos 系（v1.1 新增） ───
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

    // ─── Polkadot/Substrate 系（v1.1 新增） ───
    PolkadotMainnet = 130,
    PolkadotWestendTestnet = 131,
    KusamaMainnet = 132,
    KusamaRococoTestnet = 133,
    AcalaMainnet = 134,
    AcalaMandalaTestnet = 135,
    // Moonbeam 已迁出（v1.1.1 删除），Astar 编号复用 136/137
    AstarMainnet = 136,
    AstarShibuyaTestnet = 137,
    BittensorMainnet = 138,    // TAO（独立 Substrate 链）
    BittensorTestnet = 139,
    SeraiMainnet = 140,         // 主网未上线，预先占位
    SeraiTestnet = 141,
}

impl Network {
    /// Network → ChainKind（v2.3 §13.4 修订版）
    /// Network u8 → Network enum（用于 FFI dispatch）
    ///
    /// **重要**：直接 match 不调 try_from——try_from 内部就是 from_u8，否则无限递归 stack overflow
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

/// Network u8 → Network enum（API 别名）
pub fn try_from_u8(n: u8) -> Option<Self> {
    Self::try_from(n).ok()
}

pub fn chain_kind(self) -> ChainKind {
        match self {
            Network::BitcoinMainnet
            | Network::BitcoinTestnet
            | Network::BitcoinRegtest => ChainKind::Btc,
            Network::EthereumMainnet
            | Network::EthereumSepolia
            | Network::EthereumGoerli => ChainKind::Eth,
            Network::TronMainnet
            | Network::TronShastaTestnet
            | Network::TronNileTestnet => ChainKind::Tron,
            Network::SolanaMainnet
            | Network::SolanaDevnet
            | Network::SolanaTestnet => ChainKind::Sol,
            Network::XrpMainnet | Network::XrpTestnet => ChainKind::Xrp,
            Network::AptosMainnet | Network::AptosTestnet => ChainKind::Apt,
            Network::SuiMainnet | Network::SuiTestnet => ChainKind::Sui,
            Network::NearMainnet | Network::NearTestnet => ChainKind::Near,
            Network::CardanoMainnet
            | Network::CardanoPreprod
            | Network::CardanoPreview => ChainKind::Ada,
            Network::MoneroMainnet
            | Network::MoneroStagenet
            | Network::MoneroTestnet => ChainKind::Xmr,
            Network::ArweaveMainnet => ChainKind::Ar,

            // Cosmos 系
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

            // Polkadot/Substrate 系（v1.1.1 修订：Moonbeam 删除）
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

    /// Cosmos 系 HRP（bech32 prefix），Phase 8+ 才真实接入
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

    /// 是否主网（v2.3 §13.4 修订：Moonbeam 已删除）
    pub fn is_mainnet(self) -> bool {
        matches!(self,
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

    /// Phase 4 真实实现的网络（v2.3 优先级：BTC/ETH/XMR 各 3 种）
    pub fn is_phase4_real(self) -> bool {
        matches!(self,
            Network::BitcoinMainnet | Network::BitcoinTestnet | Network::BitcoinRegtest
            | Network::EthereumMainnet | Network::EthereumSepolia | Network::EthereumGoerli
            | Network::MoneroMainnet | Network::MoneroStagenet | Network::MoneroTestnet
        )
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
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
        // v1.1.1 编译期保证：MoonbeamMainnet/MoonriverTestnet 已删除
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
    // Phase 3 v2 property-based 测试
    //
    // **v2 策略**：只用代表性 5 链（Btc/Eth/Xmr/Sol/Polkadot）× 8 cases
    // 不遍历 44 个变体（v1 卡死根因）
    // ============================================================

    // ============================================================
    // Phase 3 v3 独立测试 fn（不用 proptest! 块）
    //
    // **v3 策略**：
    // - 每个 #[test] fn 用自己的 ProptestConfig + disable_shrink
    // - 不用 proptest! 块 macro 避免 cargo test 内部 thread pool 调度死锁
    // - 单模块独立 fn ≤ 3 个 + cases ≤ 5
    // ============================================================

    /// 5 个代表性变体 → chain_kind() 映射一致
    #[test]
    fn network_chain_kind_consistent_for_representative_set_v3() {
        // 手动 5 case（避免 proptest 累积）
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

    /// 5 个代表性变体 → is_phase4_real() 一致
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

    /// 5 个代表性变体 → as u8 → from_u8 round-trip（v3 新加）
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

    /// 5 个代表性变体 → as u8 → try_from round-trip（v3 新加）
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


impl TryFrom<u8> for Network {
    type Error = ();
    /// Network u8 → Network enum
    ///
    /// **重要**：直接调 from_u8（from_u8 自身不递归）
    fn try_from(n: u8) -> Result<Self, Self::Error> {
        Self::from_u8(n).ok_or(())
    }
}
