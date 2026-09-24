//! shlosilo L1 functional core (C-ABI called by the L3 imperative shell)
//!
//! **Architecture**: v2 §0 three-sentence summary
//! 1. Only 3 business functions: sign / export_readonly / create_account (+ restore_seed)
//! 2. Modules split independently into five layers: "curve primitives + signature schemes + derivation schemes + address encoding + UR encoding"
//! 3. functional core + imperative shell: business is a pure function chain; side effects live only at the boundary
//!
//! **Phase 2.0 stub scope** (minimal skeleton, cargo check passes in a single session):
//! - error.rs (error code system)
//! - network.rs + types/chain_kind.rs（Network enum + ChainKind enum）
//! - entropy/mnemonic.rs（Mnemonic struct + WordCount enum）
//! - derivation/path.rs（DerivationPath struct）
//! - signatures of the 4 business functions (sign / export_readonly / create_account / restore_seed)
//!
//! **Phase 2.1+ to add**: Layer A/B/C/D/E stub modules, EntropySource enum, sr25519/cosmos/polkadot
//!
//! **Phase 4 to implement**: real algorithm integration (k256 / curve25519-dalek / monero-oxide)

#![no_std]

// TEST-ONLY at the crate root (mod tests uses alloc::vec / alloc::string).
// NOTE (2026-09-24 zero-heap decision): production modules still carry their own
// `extern crate alloc` (49 files) — a transitional compromise from the SRAM-scarce
// era, against the v2 §3.5 zero-heap goal; the Z-series removes those uses. Until
// then the global allocator is supplied by the consuming appearance (flux).
#[cfg(test)]
extern crate alloc;

pub mod address;
pub mod business;
pub mod chain;
pub mod curve_primitive;
pub mod derivation;
pub mod device_timing;
pub mod encoding;
pub mod entropy;
pub mod error;
pub mod ffi;
pub mod network;
pub mod signature;
pub mod tx;
#[cfg(feature = "tx-phase-timing-ffi")]
pub mod tx_phase_hook;
pub mod types;
pub mod ur;

// Public business API (v2 §4.3 business module interface)
pub use business::{
    export_readonly::{export_readonly, ExportProtocol},
    restore_seed::restore_seed,
    sign::{sign, SignInput},
};
pub use entropy::mnemonic::WordCount;

// Public Layer A types (Phase 2.1 stub — Phase 4 real algorithm integration)
pub use crate::curve_primitive::{
    ed25519::{Ed25519Point, Ed25519Scalar},
    p256::{P256Point, P256Scalar},
    rsa::{RsaPrivKey, RsaPubKey, RSA_SIGNATURE_MAX_LEN},
    secp256k1::{Secp256k1Point, Secp256k1Scalar},
};

// Public Layer B signature types (Phase 2.2 stub — Phase 4 real algorithm integration)
pub use crate::signature::{
    clsag_ed25519::{ClsagAux, ClsagProof, CLSAG_PROOF_MAX_LEN},
    ecdsa_secp256k1::{EcdsaSignature, ECDSA_SIGNATURE_LEN},
    eddsa_ed25519::{EddsaSignature, EDDSA_SIGNATURE_LEN},
    fcmp_ed25519::{FcmpProof, FCMP_PROOF_MAX_LEN},
    rsa_pss::{RsaPssSignature, RSA_PSS_SIGNATURE_LEN},
    schnorr_secp256k1::{SchnorrSignature, SCHNORR_SIGNATURE_LEN},
};

// Public Layer C derivation types (Phase 2.2 stub — Phase 4 real algorithm integration)
pub use crate::derivation::{
    bip32_secp256k1::{ExtendedPrivKey, EXTENDED_PRIVKEY_LEN},
    icarus_ed25519::CardanoExtSk,
    monero_reduce_scalar::{MoneroKeyPair, MoneroPath},
    slip10_ed25519::{Slip10ExtendedKey, SLIP10_EXTENDED_KEY_LEN},
};

// Public Layer C multisig types (unsupported in v1, returns MultisigNotSupported)
pub use crate::derivation::bip32_secp256k1_multisig::{MultisigScript, MAX_MULTISIG_SIGNERS};

// Public Layer D address types (Phase 2.3 stub — Phase 4 real encoding)
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

// Public Layer E UR types (Phase 2.3 stub — Phase 4 real CBOR/Fountain)
pub use crate::ur::{
    codec::{
        crypto_hd_key::Bip32XPub,
        crypto_multi_accounts::MultiAccountsInput,
        json_monero_viewkey::{JsonMoneroViewkey, JSON_MONERO_VIEWKEY_MAX_LEN},
    },
    ur_decode::UrDecoded,
    ur_encode::{UrEncoded, UrTypeTag, UR_PAYLOAD_MAX_LEN},
};

// Public encoding types (Phase 2.4 stub — Phase 4 real SHA / bech32 / base58)
pub use crate::encoding::{
    base58::{Base58String, BASE58_MAX_LEN},
    base64::{Base64String, BASE64_MAX_LEN},
    bech32::{Bech32String, BECH32_MAX_LEN},
    keccak256::KECCAK256_OUTPUT_LEN,
    sha256::SHA256_OUTPUT_LEN,
    sha512::SHA512_OUTPUT_LEN,
};

// Public entropy types (Phase 2.4 stub — Phase 4 real BIP39)
pub use crate::entropy::{
    bip39_passphrase::{Bip39Seed, BIP39_SEED_LEN},
    bip39_words::{get_index_by_word, get_word_by_index, is_valid_word_index, BIP39_WORDLIST},
    dice_rolls::{bits_per_digit, minimum_rolls},
    source::EntropySource,
};

// Public tx types (Phase 2.4 stub — Phase 4 real chain-specific serialization)
pub use crate::tx::tx_normalize::{to_template, TxTemplate};
