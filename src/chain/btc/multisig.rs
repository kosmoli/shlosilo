//! BTC Multi-sig (P2SH/P2WSH) — Phase 5 v9.10
//!
//! ## 范围
//! - **P2SH multi-sig** (BIP-16): M-of-N 公钥, redeemScript = `OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG`
//! - **P2WSH multi-sig** (BIP-141): 同 redeemScript,scriptPubKey = `OP_0 SHA256(redeemScript)`
//! - **P2SH-P2WSH** (nested): P2SH 包裹 P2WSH
//! - **Sighash**: BIP-143 (segwit) + 传统 (legacy, 双 SHA256)
//!
//! ## L1 纯函数
//! 全模块无 IO/全局状态。

extern crate alloc;
use alloc::vec::Vec;

use crate::chain::btc::p2wpkh::Transaction;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use sha2::{Digest as _, Sha256};

/// Multi-sig M-of-N parameters
#[derive(Clone, Debug)]
pub struct MultisigConfig {
    /// Required signatures (M)
    pub threshold: u8,
    /// Public keys (sorted lexicographically per BIP-67)
    pub pubkeys: Vec<[u8; 33]>, // compressed pubkey
}

impl MultisigConfig {
    /// Create config with auto-sort (BIP-67)
    pub fn new(threshold: u8, mut pubkeys: Vec<[u8; 33]>) -> Result<Self> {
        if threshold == 0 || pubkeys.is_empty() || (threshold as usize) > pubkeys.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // BIP-67: sort pubkeys lexicographically
        pubkeys.sort();
        Ok(Self {
            threshold,
            pubkeys,
        })
    }

    pub fn n(&self) -> usize {
        self.pubkeys.len()
    }

    /// Create config WITHOUT sorting (preserves input order).
    /// Use this for chains like DOGE that don't enforce BIP-67.
    pub fn new_unchecked(threshold: u8, pubkeys: Vec<[u8; 33]>) -> Result<Self> {
        if threshold == 0 || pubkeys.is_empty() || (threshold as usize) > pubkeys.len() {
            return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        Ok(Self {
            threshold,
            pubkeys,
        })
    }
}

/// Build multi-sig redeemScript WITHOUT sorting pubkeys (caller-controlled order).
/// Use this when caller wants input order preserved (e.g., DOGE legacy multisig, keystone parity).
pub fn multisig_redeem_script_unsorted(config: &MultisigConfig) -> Vec<u8> {
    let mut script = Vec::new();
    script.push(0x50 + config.threshold);
    for pk in &config.pubkeys {
        script.push(0x21);
        script.extend_from_slice(pk);
    }
    script.push(0x50 + config.n() as u8);
    script.push(0xae);
    script
}

/// Build multi-sig redeemScript: `OP_M <pk1>...<pkN> OP_N OP_CHECKMULTISIG`
///
/// Opcodes:
/// - OP_1 = 0x51, OP_2 = 0x52, ... OP_16 = 0x60
/// - OP_CHECKMULTISIG = 0xae
pub fn multisig_redeem_script(config: &MultisigConfig) -> Vec<u8> {
    let mut script = Vec::new();
    // OP_M
    script.push(0x50 + config.threshold);
    // <pk1> ... <pkN>
    for pk in &config.pubkeys {
        script.push(0x21); // push 33 bytes
        script.extend_from_slice(pk);
    }
    // OP_N
    script.push(0x50 + config.n() as u8);
    // OP_CHECKMULTISIG
    script.push(0xae);
    script
}

/// Hash160 (RIPEMD160(SHA256(data)))
pub fn hash160(data: &[u8]) -> [u8; 20] {
    use ripemd::Ripemd160;
    let sha = Sha256::digest(data);
    let mut hasher = Ripemd160::new();
    hasher.update(sha);
    let result = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&result);
    out
}

/// P2SH scriptPubKey: `OP_HASH160 <20-byte-redeemScriptHash> OP_EQUAL`
/// = 0xa9 0x14 <hash160(redeemScript)> 0x87
pub fn p2sh_multisig_script_pubkey(config: &MultisigConfig) -> Vec<u8> {
    let redeem = multisig_redeem_script(config);
    let h160 = hash160(&redeem);
    let mut script = Vec::with_capacity(23);
    script.push(0xa9); // OP_HASH160
    script.push(0x14); // push 20 bytes
    script.extend_from_slice(&h160);
    script.push(0x87); // OP_EQUAL
    script
}

/// P2WSH scriptPubKey: `OP_0 <32-byte-sha256(redeemScript)>`
/// = 0x00 0x20 <sha256(redeemScript)>
pub fn p2wsh_multisig_script_pubkey(config: &MultisigConfig) -> Vec<u8> {
    let redeem = multisig_redeem_script(config);
    let sha = Sha256::digest(&redeem);
    let mut script = Vec::with_capacity(34);
    script.push(0x00); // OP_0
    script.push(0x20); // push 32 bytes
    script.extend_from_slice(&sha);
    script
}

/// P2SH-P2WSH redeemScript (P2WSH-wrapped-in-P2SH):
/// The redeemScript is the P2WSH scriptPubKey (00 20 <sha256>).
/// The P2SH scriptPubKey is OP_HASH160 <hash160(redeemScript)> OP_EQUAL.
pub fn p2sh_p2wsh_redeem_script(config: &MultisigConfig) -> Vec<u8> {
    p2wsh_multisig_script_pubkey(config)
}

pub fn p2sh_p2wsh_script_pubkey(config: &MultisigConfig) -> Vec<u8> {
    let redeem = p2sh_p2wsh_redeem_script(config);
    let h160 = hash160(&redeem);
    let mut script = Vec::with_capacity(23);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(&h160);
    script.push(0x87);
    script
}

/// Build multi-sig scriptSig for P2SH: <push sigs...> <push redeemScript (varint-len prefix)>
/// (M-of-N signatures + redeemScript)
pub fn build_multisig_scriptsig(sigs: &[Vec<u8>], redeem_script: &[u8]) -> Vec<u8> {
    let mut scriptsig = Vec::new();
    // OP_PUSHBYTES_0 (extra OP for CHECKMULTISIG bug): 0x00
    scriptsig.push(0x00);
    // sigs (each push-prefixed)
    for sig in sigs {
        scriptsig.push(sig.len() as u8);
        scriptsig.extend_from_slice(sig);
    }
    // redeemScript (push-prefixed)
    scriptsig.push(redeem_script.len() as u8);
    scriptsig.extend_from_slice(redeem_script);
    scriptsig
}

/// Build multi-sig witness items for P2WSH: [sig1, sig2, ..., redeemScript]
/// (caller serializes to bytes with witness item count + push)
pub fn build_multisig_witness_items(sigs: &[Vec<u8>], redeem_script: &[u8]) -> Vec<Vec<u8>> {
    let mut items: Vec<Vec<u8>> = sigs.to_vec();
    items.push(redeem_script.to_vec());
    items
}

/// Sign input for P2SH multi-sig
#[derive(Clone, Debug)]
pub struct P2SHMultisigSignInput {
    pub input_index: usize,
    pub config: MultisigConfig,
    pub signatures: Vec<Vec<u8>>, // DER-encoded sigs + sighash byte, one per signer
}

/// Sign P2SH multi-sig (legacy sighash):
/// Injects scriptSig = `OP_0 <sigs...> <push redeemScript>`
pub fn sign_p2sh_multisig(
    tx: &mut Transaction,
    sign_input: &P2SHMultisigSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let redeem = multisig_redeem_script(&sign_input.config);
    tx.inputs[input_idx].script_sig = build_multisig_scriptsig(&sign_input.signatures, &redeem);
    Ok(())
}

/// Sign P2WSH multi-sig (BIP-143 sighash):
/// Injects witness = [sigs..., redeemScript]
pub fn sign_p2wsh_multisig(
    tx: &mut Transaction,
    sign_input: &P2SHMultisigSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let redeem = multisig_redeem_script(&sign_input.config);
    tx.inputs[input_idx].witness = build_multisig_witness_items(&sign_input.signatures, &redeem);
    Ok(())
}

/// Sign P2SH-P2WSH multi-sig (nested):
/// scriptSig = push <P2WSH scriptPubKey>, witness = [sigs..., redeemScript]
pub fn sign_p2sh_p2wsh_multisig(
    tx: &mut Transaction,
    sign_input: &P2SHMultisigSignInput,
) -> Result<()> {
    let input_idx = sign_input.input_index;
    if input_idx >= tx.inputs.len() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat));
    }
    let redeem = multisig_redeem_script(&sign_input.config);
    // scriptSig: push P2WSH scriptPubKey
    let p2wsh_spk = p2wsh_multisig_script_pubkey(&sign_input.config);
    let mut scriptsig = Vec::new();
    scriptsig.push(p2wsh_spk.len() as u8);
    scriptsig.extend_from_slice(&p2wsh_spk);
    tx.inputs[input_idx].script_sig = scriptsig;
    // witness
    tx.inputs[input_idx].witness = build_multisig_witness_items(&sign_input.signatures, &redeem);
    Ok(())
}

/// Verify multisig redeemScript matches scriptPubKey expectation
pub fn verify_p2sh_multisig_matches(
    config: &MultisigConfig,
    script_pubkey: &[u8],
) -> bool {
    script_pubkey == p2sh_multisig_script_pubkey(config)
}

pub fn verify_p2wsh_multisig_matches(
    config: &MultisigConfig,
    script_pubkey: &[u8],
) -> bool {
    script_pubkey == p2wsh_multisig_script_pubkey(config)
}


// === Multi-sig Address Generation ===

/// Network for address encoding
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    BitcoinTestnet,
    Dogecoin,
}

impl Network {
    /// P2SH version byte (BIP-13)
    /// BTC mainnet: 0x05, BTC testnet: 0xc4, DOGE mainnet: 0x16
    /// Verified via keystone cross-validation: DOGE P2SH 2-of-3 → A2nev5... decodes to 0x16 + hash160=718c27...
    /// (base58 alphabet: 'A' is index 9, so 'A2...' decodes to 0x16 not 0x05)
    pub fn p2sh_version(&self) -> u8 {
        match self {
            Network::Bitcoin => 0x05,
            Network::BitcoinTestnet => 0xc4,
            Network::Dogecoin => 0x16,
        }
    }

    /// bech32 hrp for P2WSH (segwit v0)
    /// BTC: "bc", testnet: "tb"
    pub fn bech32_hrp(&self) -> &'static str {
        match self {
            Network::Bitcoin => "bc",
            Network::BitcoinTestnet => "tb",
            // Dogecoin does not support segwit (no P2WSH)
            Network::Dogecoin => "",
        }
    }

    /// Whether this network supports P2WSH (segwit v0)
    pub fn supports_p2wsh(&self) -> bool {
        !matches!(self, Network::Dogecoin)
    }
}

/// Build P2SH multi-sig address: base58check(version || hash160(redeemScript))
pub fn p2sh_multisig_address(network: Network, config: &MultisigConfig) -> alloc::string::String {
    p2sh_multisig_address_with_sort(network, config, true)
}

/// Build P2SH multi-sig address with optional BIP-67 sorting.
///
/// `sort_keys=true` (default): enforce BIP-67 lexicographic sort.
/// `sort_keys=false`: use pubkeys in input order (some chains like DOGE may not sort).
pub fn p2sh_multisig_address_with_sort(
    network: Network,
    config: &MultisigConfig,
    sort_keys: bool,
) -> alloc::string::String {
    let redeem = if sort_keys {
        multisig_redeem_script(config)
    } else {
        multisig_redeem_script_unsorted(config)
    };
    let h160 = hash160(&redeem);
    let mut data = alloc::vec![network.p2sh_version()];
    data.extend_from_slice(&h160);
    let encoded = crate::encoding::base58::encode_check(&data).unwrap();
    alloc::format!("{}", encoded)
}

/// Build P2WSH multi-sig address (segwit v0, bech32): bech32(hrp, witness_v0, sha256(redeemScript))
pub fn p2wsh_multisig_address(
    network: Network,
    config: &MultisigConfig,
) -> Result<alloc::string::String> {
    if !network.supports_p2wsh() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::ChainKindUnsupported));
    }
    let redeem = multisig_redeem_script(config);
    let sha = {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&redeem);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    };
    // witness v0: version byte 0, then 32-byte program
    let mut program = alloc::vec![0u8];
    program.extend_from_slice(&sha);

    // Convert 32 bytes to 5-bit groups for bech32
    let converted = crate::encoding::bech32::convertbits(&program, 8, 5, true).unwrap();
    let encoded = crate::encoding::bech32::encode(network.bech32_hrp(), &converted).unwrap();
    Ok(alloc::format!("{}", encoded))
}

/// Build P2SH-P2WSH multi-sig address (nested):
/// redeemScript = P2WSH scriptPubKey (OP_0 0x20 <sha256>)
/// address = base58check(version || hash160(redeemScript))
pub fn p2sh_p2wsh_multisig_address(
    network: Network,
    config: &MultisigConfig,
) -> Result<alloc::string::String> {
    if !network.supports_p2wsh() {
        return Err(ShlosiloError::new(ShlosiloErrorKind::ChainKindUnsupported));
    }
    let redeem = p2sh_p2wsh_redeem_script(config);
    let h160 = hash160(&redeem);
    let mut data = alloc::vec![network.p2sh_version()];
    data.extend_from_slice(&h160);
    let encoded = crate::encoding::base58::encode_check(&data).unwrap();
    Ok(alloc::format!("{}", encoded))
}


// === Tests ===

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    
    use crate::chain::btc::p2wpkh::{OutPoint, TxIn};
    use crate::curve_primitive::secp256k1::{base_mul, point_to_compressed, scalar_from_bytes};
    use std::eprintln;

    fn hex_encode(b: &[u8]) -> alloc::string::String {
        let mut s = alloc::string::String::with_capacity(b.len() * 2);
        for byte in b {
            s.push_str(&alloc::format!("{:02x}", byte));
        }
        s
    }

    fn make_test_pubkey(seed: u8) -> [u8; 33] {
        // Create a deterministic compressed pubkey from seed
        let mut sk_bytes = [0u8; 32];
        sk_bytes[31] = seed.wrapping_add(1); // avoid zero
        let sk = scalar_from_bytes(&sk_bytes).unwrap();
        let pub_point = base_mul(&sk);
        point_to_compressed(&pub_point)
    }

    /// MultisigConfig validates inputs
    #[test]
    fn multisig_config_validation() {
        // Valid 2-of-3
        let pks = alloc::vec![
            make_test_pubkey(1),
            make_test_pubkey(2),
            make_test_pubkey(3),
        ];
        let cfg = MultisigConfig::new(2, pks.clone()).unwrap();
        assert_eq!(cfg.threshold, 2);
        assert_eq!(cfg.n(), 3);

        // Threshold 0 → error
        assert!(MultisigConfig::new(0, pks.clone()).is_err());
        // Empty pubkeys → error
        assert!(MultisigConfig::new(2, alloc::vec![]).is_err());
        // Threshold > n → error
        assert!(MultisigConfig::new(4, pks).is_err());
    }

    /// BIP-67 pubkey sorting
    #[test]
    fn multisig_bip67_sorting() {
        let pk_a = make_test_pubkey(1);
        let pk_b = make_test_pubkey(2);
        let pk_c = make_test_pubkey(3);
        // Insert in wrong order
        let pks = alloc::vec![pk_c, pk_a, pk_b];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        // Should be sorted
        let mut sorted = alloc::vec![pk_a, pk_b, pk_c];
        sorted.sort();
        assert_eq!(cfg.pubkeys, sorted);
    }

    /// Multi-sig redeemScript structure
    #[test]
    fn multisig_redeem_script_structure() {
        let pks = alloc::vec![
            make_test_pubkey(1),
            make_test_pubkey(2),
            make_test_pubkey(3),
        ];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let redeem = multisig_redeem_script(&cfg);

        // Expected: 0x52 (OP_2) | 0x21 pk1 0x21 pk2 0x21 pk3 | 0x53 (OP_3) | 0xae (OP_CHECKMULTISIG)
        assert_eq!(redeem[0], 0x52); // OP_2
        assert_eq!(redeem[redeem.len() - 2], 0x53); // OP_3
        assert_eq!(redeem[redeem.len() - 1], 0xae); // OP_CHECKMULTISIG

        // 3 push-33 instructions between
        let mut count = 0;
        let mut i = 1;
        while i < redeem.len() - 2 {
            assert_eq!(redeem[i], 0x21);
            i += 1 + 33;
            count += 1;
        }
        assert_eq!(count, 3);
    }

    /// P2SH multi-sig scriptPubKey: `OP_HASH160 <hash160> OP_EQUAL`
    #[test]
    fn p2sh_multisig_script_pubkey_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let spk = p2sh_multisig_script_pubkey(&cfg);
        assert_eq!(spk.len(), 23);
        assert_eq!(spk[0], 0xa9); // OP_HASH160
        assert_eq!(spk[1], 0x14); // push 20
        assert_eq!(spk[22], 0x87); // OP_EQUAL
        eprintln!("P2SH multisig scriptPubKey: {}", hex_encode(&spk));
    }

    /// P2WSH multi-sig scriptPubKey: `OP_0 <sha256(redeemScript)>`
    #[test]
    fn p2wsh_multisig_script_pubkey_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let spk = p2wsh_multisig_script_pubkey(&cfg);
        assert_eq!(spk.len(), 34);
        assert_eq!(spk[0], 0x00); // OP_0
        assert_eq!(spk[1], 0x20); // push 32
        eprintln!("P2WSH multisig scriptPubKey: {}", hex_encode(&spk));
    }

    /// P2SH-P2WSH (nested)
    #[test]
    fn p2sh_p2wsh_multisig_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let spk = p2sh_p2wsh_script_pubkey(&cfg);
        assert_eq!(spk.len(), 23);
        assert_eq!(spk[0], 0xa9);
        // redeemScript is the P2WSH scriptPubKey (00 20 <sha256>)
        let redeem = p2sh_p2wsh_redeem_script(&cfg);
        assert_eq!(redeem.len(), 34);
        assert_eq!(redeem[0], 0x00);
    }

    /// Verify match helpers
    #[test]
    fn verify_match_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let p2sh_spk = p2sh_multisig_script_pubkey(&cfg);
        let p2wsh_spk = p2wsh_multisig_script_pubkey(&cfg);
        assert!(verify_p2sh_multisig_matches(&cfg, &p2sh_spk));
        assert!(verify_p2wsh_multisig_matches(&cfg, &p2wsh_spk));
        assert!(!verify_p2sh_multisig_matches(&cfg, &p2wsh_spk));
    }

    /// Build scriptSig for P2SH multi-sig
    #[test]
    fn build_multisig_scriptsig_test() {
        // 2-of-2, dummy 71-byte sigs
        let sig1 = alloc::vec![0xabu8; 71];
        let sig2 = alloc::vec![0xccu8; 71];
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let redeem = multisig_redeem_script(&cfg);

        let scriptsig = build_multisig_scriptsig(&[sig1.clone(), sig2.clone()], &redeem);
        // 1 (extra OP_0) + 1+71 + 1+71 + 1+redeem_len
        let expected_len = 1 + (1 + 71) + (1 + 71) + 1 + redeem.len();
        assert_eq!(scriptsig.len(), expected_len);
        assert_eq!(scriptsig[0], 0x00); // extra OP for CHECKMULTISIG bug
    }

    /// Build witness items for P2WSH multi-sig
    #[test]
    fn build_multisig_witness_items_test() {
        let sig1 = alloc::vec![0xabu8; 71];
        let sig2 = alloc::vec![0xccu8; 71];
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();
        let redeem = multisig_redeem_script(&cfg);

        let witness_items = build_multisig_witness_items(&[sig1.clone(), sig2.clone()], &redeem);
        // items = [sig1, sig2, redeemScript]
        assert_eq!(witness_items.len(), 3);
        assert_eq!(witness_items[0], sig1);
        assert_eq!(witness_items[1], sig2);
        assert_eq!(witness_items[2], redeem);
    }

    /// Sign P2SH multi-sig injects scriptSig
    #[test]
    fn sign_p2sh_multisig_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();

        let mut tx = Transaction {
            version: 2,
            inputs: alloc::vec![TxIn {
                prev_out: OutPoint {
                    txid: [1u8; 32],
                    vout: 0,
                },
                script_sig: alloc::vec![],
                sequence: 0xffffffff,
                witness: alloc::vec![],
            }],
            outputs: alloc::vec![],
            lock_time: 0,
        };

        let sig1 = alloc::vec![0xabu8; 71];
        let sig2 = alloc::vec![0xccu8; 71];
        let sign_input = P2SHMultisigSignInput {
            input_index: 0,
            config: cfg.clone(),
            signatures: alloc::vec![sig1, sig2],
        };

        sign_p2sh_multisig(&mut tx, &sign_input).unwrap();
        let script_sig = &tx.inputs[0].script_sig;
        assert!(!script_sig.is_empty());
        assert_eq!(script_sig[0], 0x00); // extra OP_0
        eprintln!("P2SH multisig scriptSig ({} bytes)", script_sig.len());
    }

    /// Sign P2WSH multi-sig injects witness
    #[test]
    fn sign_p2wsh_multisig_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();

        let mut tx = Transaction {
            version: 2,
            inputs: alloc::vec![TxIn {
                prev_out: OutPoint {
                    txid: [2u8; 32],
                    vout: 0,
                },
                script_sig: alloc::vec![],
                sequence: 0xffffffff,
                witness: alloc::vec![],
            }],
            outputs: alloc::vec![],
            lock_time: 0,
        };

        let sig1 = alloc::vec![0xabu8; 71];
        let sig2 = alloc::vec![0xccu8; 71];
        let sign_input = P2SHMultisigSignInput {
            input_index: 0,
            config: cfg,
            signatures: alloc::vec![sig1, sig2],
        };

        sign_p2wsh_multisig(&mut tx, &sign_input).unwrap();
        let witness = &tx.inputs[0].witness;
        // witness items: [sig1, sig2, redeemScript]
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[2], multisig_redeem_script(&MultisigConfig::new(
            2,
            alloc::vec![make_test_pubkey(1), make_test_pubkey(2)],
        ).unwrap()));
        eprintln!("P2WSH multisig witness ({} bytes)", witness.len());
    }

    /// Sign P2SH-P2WSH (nested)
    #[test]
    fn sign_p2sh_p2wsh_multisig_test() {
        let pks = alloc::vec![make_test_pubkey(1), make_test_pubkey(2)];
        let cfg = MultisigConfig::new(2, pks).unwrap();

        let mut tx = Transaction {
            version: 2,
            inputs: alloc::vec![TxIn {
                prev_out: OutPoint {
                    txid: [3u8; 32],
                    vout: 0,
                },
                script_sig: alloc::vec![],
                sequence: 0xffffffff,
                witness: alloc::vec![],
            }],
            outputs: alloc::vec![],
            lock_time: 0,
        };

        let sig1 = alloc::vec![0xabu8; 71];
        let sig2 = alloc::vec![0xccu8; 71];
        let sign_input = P2SHMultisigSignInput {
            input_index: 0,
            config: cfg,
            signatures: alloc::vec![sig1, sig2],
        };

        sign_p2sh_p2wsh_multisig(&mut tx, &sign_input).unwrap();
        let script_sig = &tx.inputs[0].script_sig;
        let witness = &tx.inputs[0].witness;
        assert!(!script_sig.is_empty());
        assert!(!witness.is_empty());
        eprintln!(
            "P2SH-P2WSH scriptSig ({} bytes) + witness ({} bytes)",
            script_sig.len(),
            witness.len()
        );
    }

    /// Different M-of-N configs produce different scripts
    #[test]
    fn different_threshold_produces_different_script() {
        let pks = alloc::vec![
            make_test_pubkey(1),
            make_test_pubkey(2),
            make_test_pubkey(3),
        ];
        let cfg_2of3 = MultisigConfig::new(2, pks.clone()).unwrap();
        let cfg_3of3 = MultisigConfig::new(3, pks).unwrap();
        assert_ne!(
            multisig_redeem_script(&cfg_2of3),
            multisig_redeem_script(&cfg_3of3)
        );
    }

    // === Keystone 3 cross-validation tests ===
    // Source: /home/komo/works/keystone3-firmware/rust/apps/bitcoin/src/multi_sig/address.rs::tests

    /// Helper: hex decode compressed pubkey
    fn hex_decode_pubkey(hex_str: &str) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(33);
        let bytes = hex_str.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = (bytes[i] as char).to_digit(16).unwrap();
            let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
            out.push(((hi << 4) | lo) as u8);
            i += 2;
        }
        out
    }

    /// keystone test_create_multi_sig_address_for_pubkeys:
    /// 3 pubkeys, 2-of-3 P2SH Dogecoin → A2nev5Fc7tFZ11oy1Ybz1kJRbebTWff8K6
    #[test]
    fn keystone_test_dogecoin_p2sh_2of3() {
        let pk1 = hex_decode_pubkey("03a0c95fd48f1a251c744629e19ad154dfe1d7fb992d6955d62c417ae4ac333340");
        let pk2 = hex_decode_pubkey("0361769c55b3035962fd3267da5cc4efa03cb400fe1971f5ec1c686d6b301ccd60");
        let pk3 = hex_decode_pubkey("021d24a7eda6ccbff4616d9965c9bb2a7871ce048b0161b71e91be83671be514d5");

        let mut pks = alloc::vec![[0u8; 33], [0u8; 33], [0u8; 33]];
        pks[0].copy_from_slice(&pk1);
        pks[1].copy_from_slice(&pk2);
        pks[2].copy_from_slice(&pk3);

        let cfg = MultisigConfig::new_unchecked(2, pks).unwrap();
        // keystone DOGE test uses sort_keys=false (preserves input order)
        let address = p2sh_multisig_address_with_sort(Network::Dogecoin, &cfg, false);
        assert_eq!(
            address, "A2nev5Fc7tFZ11oy1Ybz1kJRbebTWff8K6",
            "Keystone cross-validation failed: 2-of-3 P2SH Dogecoin"
        );
    }

    /// keystone test_create_multi_sig_address_with_sorted_keys_matches_unsorted:
    /// Same 3 pubkeys, P2WSH 2-of-3 mainnet:
    /// - Sorted manually → P2WSH address
    /// - Unsorted with sort_keys=true → same address
    #[test]
    fn keystone_test_p2wsh_sorted_matches_unsorted() {
        let pk1 = hex_decode_pubkey("0361769c55b3035962fd3267da5cc4efa03cb400fe1971f5ec1c686d6b301ccd60");
        let pk2 = hex_decode_pubkey("021d24a7eda6ccbff4616d9965c9bb2a7871ce048b0161b71e91be83671be514d5");
        let pk3 = hex_decode_pubkey("03a0c95fd48f1a251c744629e19ad154dfe1d7fb992d6955d62c417ae4ac333340");

        let mut pks_sorted = alloc::vec![[0u8; 33], [0u8; 33], [0u8; 33]];
        pks_sorted[0].copy_from_slice(&pk1);
        pks_sorted[1].copy_from_slice(&pk2);
        pks_sorted[2].copy_from_slice(&pk3);

        let mut pks_unsorted = alloc::vec![[0u8; 33], [0u8; 33], [0u8; 33]];
        pks_unsorted[0].copy_from_slice(&pk3); // unsorted order
        pks_unsorted[1].copy_from_slice(&pk1);
        pks_unsorted[2].copy_from_slice(&pk2);

        // Sorted: BIP-67 sort enforced in MultisigConfig::new
        let cfg_sorted = MultisigConfig::new(2, pks_sorted.clone()).unwrap();
        let addr_sorted = p2wsh_multisig_address(Network::Bitcoin, &cfg_sorted).unwrap();

        // Unsorted with sort_keys=true: also sorts via MultisigConfig::new
        let cfg_unsorted = MultisigConfig::new(2, pks_unsorted).unwrap();
        let addr_unsorted = p2wsh_multisig_address(Network::Bitcoin, &cfg_unsorted).unwrap();

        assert_eq!(
            addr_sorted, addr_unsorted,
            "Keystone cross-validation: P2WSH sorted == unsorted (BIP-67)"
        );
    }

    /// keystone test_create_multi_sig_address_testnet_prefix:
    /// 3 pubkeys, P2SH testnet should start with '2' (testnet P2SH prefix)
    #[test]
    fn keystone_test_p2sh_testnet_prefix() {
        let pk1 = hex_decode_pubkey("03a0c95fd48f1a251c744629e19ad154dfe1d7fb992d6955d62c417ae4ac333340");
        let pk2 = hex_decode_pubkey("0361769c55b3035962fd3267da5cc4efa03cb400fe1971f5ec1c686d6b301ccd60");
        let pk3 = hex_decode_pubkey("021d24a7eda6ccbff4616d9965c9bb2a7871ce048b0161b71e91be83671be514d5");

        let mut pks = alloc::vec![[0u8; 33], [0u8; 33], [0u8; 33]];
        pks[0].copy_from_slice(&pk1);
        pks[1].copy_from_slice(&pk2);
        pks[2].copy_from_slice(&pk3);

        let cfg = MultisigConfig::new(2, pks).unwrap();
        let address = p2sh_multisig_address(Network::BitcoinTestnet, &cfg);
        assert!(
            address.starts_with('2'),
            "Keystone cross-validation: P2SH testnet should start with '2', got: {address}"
        );
    }

    /// Verify multi-sig address generation is deterministic
    #[test]
    fn multisig_address_deterministic() {
        let pk1 = hex_decode_pubkey("03a0c95fd48f1a251c744629e19ad154dfe1d7fb992d6955d62c417ae4ac333340");
        let pk2 = hex_decode_pubkey("0361769c55b3035962fd3267da5cc4efa03cb400fe1971f5ec1c686d6b301ccd60");
        let mut pks = alloc::vec![[0u8; 33], [0u8; 33]];
        pks[0].copy_from_slice(&pk1);
        pks[1].copy_from_slice(&pk2);
        let cfg = MultisigConfig::new(2, pks).unwrap();

        let a1 = p2sh_multisig_address(Network::Bitcoin, &cfg);
        let a2 = p2sh_multisig_address(Network::Bitcoin, &cfg);
        assert_eq!(a1, a2, "same config should yield same address");
    }

    /// P2SH-P2WSH address (nested) keystone test
    #[test]
    fn keystone_test_p2sh_p2wsh_nested() {
        let pk1 = hex_decode_pubkey("03a0c95fd48f1a251c744629e19ad154dfe1d7fb992d6955d62c417ae4ac333340");
        let pk2 = hex_decode_pubkey("0361769c55b3035962fd3267da5cc4efa03cb400fe1971f5ec1c686d6b301ccd60");
        let pk3 = hex_decode_pubkey("021d24a7eda6ccbff4616d9965c9bb2a7871ce048b0161b71e91be83671be514d5");
        let mut pks = alloc::vec![[0u8; 33], [0u8; 33], [0u8; 33]];
        pks[0].copy_from_slice(&pk1);
        pks[1].copy_from_slice(&pk2);
        pks[2].copy_from_slice(&pk3);
        let cfg = MultisigConfig::new(2, pks).unwrap();

        // Nested P2SH-P2WSH mainnet
        let nested_addr = p2sh_p2wsh_multisig_address(Network::Bitcoin, &cfg).unwrap();
        // Verify it starts with '3' (P2SH mainnet)
        assert!(
            nested_addr.starts_with('3'),
            "P2SH-P2WSH mainnet should start with '3', got: {nested_addr}"
        );

        // Nested P2SH-P2WSH testnet — should start with '2'
        let nested_testnet = p2sh_p2wsh_multisig_address(Network::BitcoinTestnet, &cfg).unwrap();

        // X6: 不支持 P2WSH 的网络走错误码,不 panic(公开 API 非 total)
        let doge_err = p2wsh_multisig_address(Network::Dogecoin, &cfg).unwrap_err();
        assert_eq!(doge_err.kind, ShlosiloErrorKind::ChainKindUnsupported);
        let doge_err2 = p2sh_p2wsh_multisig_address(Network::Dogecoin, &cfg).unwrap_err();
        assert_eq!(doge_err2.kind, ShlosiloErrorKind::ChainKindUnsupported);
        assert!(
            nested_testnet.starts_with('2'),
            "P2SH-P2WSH testnet should start with '2', got: {nested_testnet}"
        );
    }

}
