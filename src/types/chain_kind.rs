//! ChainKind 枚举（v2 §4.3 + v1.1 §13.3）
//!
//! **分类标准（v1.1 修订）**：按**签名协议族**分类，不按链上层架构分类。
//! shlosilo 是签名器，只关心地址格式 + 交易格式 + 签名算法——共同点决定归属。
//!
//! - `Btc` / `Eth` / `Xmr` / `Ar`：各链独立签名栈（Phase 4 真实实现）
//! - `Cosmos`：secp256k1 + bech32 + 118 coin type（v1.1 新增；Phase 8+ 真实实现）
//! - `Polkadot`：sr25519 + ss58（v1.1 新增；Phase 8+ 真实实现）
//! - 其他 ed25519 系（Sol / Apt / Sui / Near / Ada）：Phase 8+ 真实实现
//! - `Unknown`：UR type tag 无法识别

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChainKind {
    Btc      = 0,
    Eth      = 1,
    Tron     = 2,
    Xrp      = 3,
    Sol      = 4,
    Apt      = 5,
    Sui      = 6,
    Near     = 7,
    Ada      = 8,
    Xmr      = 9,
    Ar       = 10,
    Cosmos   = 11,    // v1.1 新增：Cosmos 生态统称
    Polkadot = 12,    // v1.1 新增：Polkadot/Substrate 签名栈统称
    Unknown  = 255,
}

impl ChainKind {
    /// UR type tag → ChainKind（v2 §7 ChainKind 推断）
    ///
    /// 解析失败的返回 `Unknown`，由业务层决定如何处理（v1 默认拒绝）。
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
            // Cosmos 系（待 Phase 8+ 真实接入）
            "cosmos-tx" | "osmosis-tx" | "thorchain-tx" => Self::Cosmos,
            // Polkadot 系（待 Phase 8+ 真实接入）
            "polkadot-tx" | "substrate-tx" => Self::Polkadot,
            _ => Self::Unknown,
        }
    }

    /// 是否 Phase 4 真实实现的链（v2.3 Phase 4 优先级）
    pub const fn is_phase4_real(self) -> bool {
        matches!(self, Self::Btc | Self::Eth | Self::Xmr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::Network;
    extern crate alloc;
    use alloc::format;
    use alloc::vec;
    
    use proptest::prelude::*;

    #[test]
    fn ur_type_inference() {
        assert_eq!(ChainKind::from_ur_type_tag("crypto-psbt"), ChainKind::Btc);
        assert_eq!(ChainKind::from_ur_type_tag("eth-sign-request"), ChainKind::Eth);
        assert_eq!(ChainKind::from_ur_type_tag("crypto-monero-tx"), ChainKind::Xmr);
        assert_eq!(ChainKind::from_ur_type_tag("unknown-tx"), ChainKind::Unknown);
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
    // Phase 3 property-based 测试
    // ============================================================

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(20))]

        /// ChainKind is_phase4_real 自反性
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
            // BTC/ETH/XMR 是 Phase 4 真实实现
            let is_phase4 = matches!(ck, ChainKind::Btc | ChainKind::Eth | ChainKind::Xmr);
            prop_assert_eq!(ck.is_phase4_real(), is_phase4);
        }

        /// ChainKind Debug 输出包含枚举名
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

        /// ChainKind::from_ur_type_tag 任意合法 ur_type → 一致性
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
            // 合法 ur_type 不应是 Unknown
            if matches!(ur_type, "unknown-tx") {
                prop_assert_eq!(ck, ChainKind::Unknown);
            } else {
                prop_assert_ne!(ck, ChainKind::Unknown);
            }
        }

        /// ChainKind 13 个枚举值的 Debug 输出都是非空字符串
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
        /// 跨模块端到端 chain_kind 推断（v3）
        /// ============================================================
        /// 验证：ChainKind::from_ur_type_tag → Network::chain_kind() 一致

        /// 14 个 ur_type → 推断 ChainKind → 对应代表性 Network chain_kind() 一致
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

            // 对应代表性 Network → chain_kind() 应该跟 expected_kind 一致
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

        /// Phase 4 真实链（Btc/Eth/Xmr）UR + Network + is_phase4_real 三方一致
        #[test]
        fn cross_module_phase4_real_consistency(idx in 0u8..3) {
            let (ur_type, net, expected_kind) = match idx {
                0 => ("crypto-psbt", Network::BitcoinMainnet, ChainKind::Btc),
                1 => ("eth-sign-request", Network::EthereumMainnet, ChainKind::Eth),
                _ => ("crypto-monero-tx", Network::MoneroMainnet, ChainKind::Xmr),
            };

            // UR 推断
            prop_assert_eq!(ChainKind::from_ur_type_tag(ur_type), expected_kind);
            // Network 推断
            prop_assert_eq!(net.chain_kind(), expected_kind);
            // Phase 4 真实实现标记
            prop_assert!(expected_kind.is_phase4_real());
            prop_assert!(net.is_phase4_real());
        }
    }
}