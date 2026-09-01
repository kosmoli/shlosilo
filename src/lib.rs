//! shlosilo L1 functional core（C-ABI 给 L3 imperative shell 调用）
//!
//! **架构**：v2 §0 三句话概括
//! 1. 业务只有 3 个：sign / export_readonly / create_account（+ restore_seed）
//! 2. 模块按"曲线原语 + 签名方案 + 派生方案 + 地址编码 + UR 编码"五层独立划分
//! 3. functional core + imperative shell：业务是纯函数链，副作用只在边界
//!
//! **Phase 2.0 stub 范围**（最小骨架，单 session 跑通 cargo check）：
//! - error.rs（错误码体系）
//! - network.rs + types/chain_kind.rs（Network enum + ChainKind enum）
//! - entropy/mnemonic.rs（Mnemonic struct + WordCount enum）
//! - derivation/path.rs（DerivationPath struct）
//! - 4 个业务函数签名（sign / export_readonly / create_account / restore_seed）
//!
//! **Phase 2.1+ 待补**：Layer A/B/C/D/E 五层 stub 模块、EntropySource enum、sr25519/cosmos/polkadot
//!
//! **Phase 4 待实现**：真实算法接入（k256 / curve25519-dalek / monero-oxide）

#![no_std]

// alloc 仅 test 时需要（mod tests 用 alloc::vec / alloc::string）
#[cfg(test)]
extern crate alloc;

// embedded（no_std staticlib）构建需要 global_allocator + panic_handler
// （底层 malloc 由 L3 宿主提供：shlosilo_embedded_malloc/free）
#[cfg(not(feature = "std"))]
mod embedded_alloc;

pub mod address;
pub mod business;
pub mod chain;
pub mod curve_primitive;
pub mod derivation;
pub mod encoding;
pub mod entropy;
pub mod error;
pub mod ffi;
pub mod network;
pub mod signature;
pub mod tx;
pub mod types;
pub mod ur;

// 公开业务 API（v2 §4.3 业务模块接口）
pub use business::{
    export_readonly::{export_readonly, ExportProtocol},
    restore_seed::restore_seed,
    sign::{sign, SignInput},
};
pub use entropy::mnemonic::WordCount;

// 公开 Layer A 类型（Phase 2.1 stub — Phase 4 真实算法接入）
pub use crate::curve_primitive::{
    ed25519::{Ed25519Point, Ed25519Scalar},
    p256::{P256Point, P256Scalar},
    rsa::{RsaPrivKey, RsaPubKey, RSA_SIGNATURE_MAX_LEN},
    secp256k1::{Secp256k1Point, Secp256k1Scalar},
};

// 公开 Layer B 签名类型（Phase 2.2 stub — Phase 4 真实算法接入）
pub use crate::signature::{
    clsag_ed25519::{ClsagAux, ClsagProof, CLSAG_PROOF_MAX_LEN},
    ecdsa_secp256k1::{EcdsaSignature, ECDSA_SIGNATURE_LEN},
    eddsa_ed25519::{EddsaSignature, EDDSA_SIGNATURE_LEN},
    fcmp_ed25519::{FcmpProof, FCMP_PROOF_MAX_LEN},
    rsa_pss::{RsaPssSignature, RSA_PSS_SIGNATURE_LEN},
    schnorr_secp256k1::{SchnorrSignature, SCHNORR_SIGNATURE_LEN},
};

// 公开 Layer C 派生类型（Phase 2.2 stub — Phase 4 真实算法接入）
pub use crate::derivation::{
    bip32_secp256k1::{ExtendedPrivKey, EXTENDED_PRIVKEY_LEN},
    icarus_ed25519::CardanoExtSk,
    monero_reduce_scalar::{MoneroKeyPair, MoneroPath},
    slip10_ed25519::{Slip10ExtendedKey, SLIP10_EXTENDED_KEY_LEN},
};

// 公开 Layer C multisig 类型（v1 不支持，返回 MultisigNotSupported）
pub use crate::derivation::bip32_secp256k1_multisig::{MultisigScript, MAX_MULTISIG_SIGNERS};

// 公开 Layer D 地址类型（Phase 2.3 stub — Phase 4 真实编码）
pub use crate::address::{
    aptos_sui::{AptosAddress, SuiAddress, APTOS_ADDRESS_LEN, SUI_ADDRESS_LEN},
    arweave::{ArweaveAddress, ARWEAVE_ADDRESS_MAX_LEN},
    btc_legacy::BtcLegacyAddress,
    btc_segwit::{BtcAddress, SegwitVariant, BTC_ADDRESS_MAX_LEN},
    cardano::{CardanoAddress, CARDANO_ADDRESS_MAX_LEN},
    eth::{EthAddress, ETH_ADDRESS_LEN},
    sol::{SolAddress, SOL_ADDRESS_MAX_LEN},
    tron::TronAddress,
    xmr::{XmrAddress, XMR_ADDRESS_MAX_LEN},
    xrp::{XrpAddress, XRP_ADDRESS_MAX_LEN},
};

// 公开 Layer E UR 类型（Phase 2.3 stub — Phase 4 真实 CBOR/Fountain）
pub use crate::ur::{
    codec::{
        crypto_hd_key::Bip32XPub,
        crypto_multi_accounts::MultiAccountsInput,
        json_monero_viewkey::{JsonMoneroViewkey, JSON_MONERO_VIEWKEY_MAX_LEN},
    },
    ur_decode::UrDecoded,
    ur_encode::{UrEncoded, UrTypeTag, UR_PAYLOAD_MAX_LEN},
};

// 公开 encoding 类型（Phase 2.4 stub — Phase 4 真实 SHA / bech32 / base58）
pub use crate::encoding::{
    base58::{Base58String, BASE58_MAX_LEN},
    base64::{Base64String, BASE64_MAX_LEN},
    bech32::{Bech32String, BECH32_MAX_LEN},
    keccak256::KECCAK256_OUTPUT_LEN,
    sha256::SHA256_OUTPUT_LEN,
    sha512::SHA512_OUTPUT_LEN,
};

// 公开 entropy 增量类型（Phase 2.4 stub — Phase 4 真实 BIP39）
pub use crate::entropy::{
    bip39_passphrase::{Bip39Seed, BIP39_SEED_LEN},
    bip39_words::{get_index_by_word, get_word_by_index, is_valid_word_index, BIP39_WORDLIST},
    dice_rolls::{bits_per_digit, minimum_rolls},
    source::EntropySource,
};

// 公开 tx 类型（Phase 2.4 stub — Phase 4 真实链特定序列化）
pub use crate::tx::tx_normalize::{to_template, TxTemplate};
