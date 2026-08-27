//! 业务 1：签名（v2 §1.1 + §4.3）
//!
//! **P6.0d/e 真实化**：
//! - Mnemonic 输入 → restore_seed（真实 BIP-39）
//! - BTC（crypto-psbt）：CBOR 解出 PSBT bytes → parse_psbt → 逐 input 签名 → serialize
//! - ETH（eth-sign-request）：payload = raw EIP-1559 tx → parse_eip1559_raw → sign_eip1559
//! - XMR / 其他链：显式拒绝（XMR 等 Feather 真实 fixture，v2 定位不构造交易）

use crate::derivation::path::DerivationPath;
use crate::entropy::mnemonic::Mnemonic;
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};
use crate::network::Network;
use crate::tx::tx_normalize;

extern crate alloc;

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

/// 签名输入（v2 §1.1 双流程：默认 dice-roll 零存储 + 备选 TRNG/SE 持久化）
///
/// **v2.4 安全**：`Mnemonic` 变体持有 owned `Mnemonic`——业务模块签名完即 drop 出 scope。
/// `passphrase` 是 `&[u8]` borrow。`Seed` 变体是 `&[u8; 64]` borrow。
pub enum SignInput<'a> {
    /// 默认：零存储流程（mnemonic QR + passphrase 现场恢复 seed）
    Mnemonic {
        mnemonic: Mnemonic,
        passphrase: &'a [u8],
    },
    /// 备选：从 SE 芯片 / HSM 读取的 seed
    Seed { seed: &'a [u8; 64] },
}

/// 签名结果长度上界（按 ChainKind 不同，buffer 预检用）
pub fn stub_signature_len(chain_kind: crate::types::chain_kind::ChainKind) -> usize {
    use crate::types::chain_kind::ChainKind;
    match chain_kind {
        ChainKind::Btc => 64,  // ECDSA P2WPKH 64 bytes
        ChainKind::Eth => 65,  // ECDSA r/s/v 65 bytes
        ChainKind::Xmr => 96,  // CLSAG proof ≈ 96 bytes
        ChainKind::Tron => 65, // ECDSA（同 ETH）
        ChainKind::Sol => 64,  // EdDSA 64 bytes
        ChainKind::Apt | ChainKind::Sui | ChainKind::Near => 64,
        ChainKind::Ada => 64, // EdDSA 64 bytes
        ChainKind::Ar => 512, // RSA-PSS 512 bytes
        _ => 96,              // 其他链用最大估计
    }
}

/// 从 SignInput 拿 BIP-39 seed（borrow；Mnemonic 路径现场恢复到栈 buffer）
fn resolve_seed(sign_input: &SignInput<'_>) -> Result<[u8; 64]> {
    let mut restored = [0u8; 64];
    match sign_input {
        SignInput::Seed { seed } => Ok(**seed),
        SignInput::Mnemonic {
            mnemonic,
            passphrase,
        } => {
            crate::business::restore_seed::restore_seed(mnemonic, passphrase, &mut restored)?;
            Ok(restored)
        }
    }
}

/// 签名业务入口：typed UR payload → 按链 dispatch → 签名 bytes 写 output_buf
///
/// **P1-01（2026-08-26）**：`type_tag` 由 UR decode 层携带，不靠 payload 首字节
/// 推断；payload 是 codec 原样的 CBOR（crypto-psbt=bytes item，
/// eth-sign-request=map）。链处理函数按各自 codec 解析。
pub fn sign(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    let (seed) = resolve_seed(&sign_input)?;

    let template = tx_normalize::to_template(type_tag, ur_payload)?;
    let chain_kind = template.chain_kind;
    // payload 是完整 CBOR（不剥首字节——P1-01）
    if template.payload.is_empty() {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    let payload = template.payload.as_slice();

    match chain_kind {
        crate::types::chain_kind::ChainKind::Btc => {
            let n = sign_btc(&seed, payload, output_buf)?;
            Ok(n)
        }
        crate::types::chain_kind::ChainKind::Eth => {
            let n = sign_eth(&seed, payload, output_buf)?;
            Ok(n)
        }
        _ => Err(err(ShlosiloErrorKind::ChainKindUnsupported)),
    }
}


/// 从 BIP32_DERIVATION value 解析派生路径
/// value 格式（BIP-174）：master_key_fingerprint(4B) || derivation_index(u32LE) × depth
fn read_bip32_derivation_path(
    input_map: &[crate::chain::btc::psbt::KeyValue],
) -> Option<DerivationPath> {
    use crate::chain::btc::psbt::input_type;
    let kv = input_map
        .iter()
        .find(|kv| kv.key.first() == Some(&input_type::BIP32_DERIVATION))?;
    if kv.value.len() < 8 || (kv.value.len() - 4) % 4 != 0 {
        return None;
    }
    let depth = (kv.value.len() - 4) / 4;
    let mut flat = alloc::vec::Vec::with_capacity(depth);
    for j in 0..depth {
        let o = 4 + 4 * j;
        let raw = u32::from_le_bytes([
            kv.value[o],
            kv.value[o + 1],
            kv.value[o + 2],
            kv.value[o + 3],
        ]);
        flat.push(raw);
    }
    DerivationPath::from_flat(flat).ok()
}

/// BTC：crypto-psbt CBOR（裸 bytes item）→ PSBT 签名
///
/// 派生路径 = m/84'/0'/0'/0/0（native segwit 标准路径）。
/// 每个 input 用 BIP32_DERIVATION 提示的路径派生私钥；
/// 无提示时统一走默认路径。
fn sign_btc(seed: &[u8], cbor_payload: &[u8], output_buf: &mut [u8]) -> Result<usize> {
    use crate::chain::btc::psbt as psbt_mod;
    use crate::encoding::cbor;

    let psbt_bytes = match cbor::decode(cbor_payload)? {
        cbor::Cbor::Bytes(b) => b,
        _ => return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor)),
    };

    let mut psbt = psbt_mod::parse_psbt(psbt_bytes)?;

    let default_path = DerivationPath::parse("m/84'/0'/0'/0/0")?;
    for idx in 0..psbt.unsigned_tx.inputs.len() {
        // P1-02（P6.3 修复）：BIP32_DERIVATION value = master_fingerprint(4B) + path(u32LE × depth)，
        // 路径必须从 PSBT 读出而非硬编码。无该字段时才 fallback 默认路径。
        let path = psbt
            .inputs
            .get(idx)
            .and_then(|map| read_bip32_derivation_path(map))
            .unwrap_or_else(|| default_path.clone());
        let sk =
            crate::derivation::bip32_secp256k1::derive_from_seed(seed, &path)?;
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

        // pubkey hash：从 BIP32_DERIVATION key 里的压缩公钥算 HASH160
        let compressed_pk = psbt
            .inputs
            .get(idx)
            .and_then(|map| {
                map.iter()
                    .find(|kv| kv.key.first() == Some(&psbt_mod::input_type::BIP32_DERIVATION))
                    .map(|kv| kv.key[1..34].to_vec())
            });
        let pubkey_hash: [u8; 20] = match &compressed_pk {
            Some(pk) => {
                let h = crate::encoding::sha256::hash(pk)?;
                let r = crate::encoding::ripemd160::hash(&h)?;
                r
            }
            None => return Err(err(ShlosiloErrorKind::EncodingInvalidFormat)),
        };

        // witness utxo value
        let amount = psbt
            .inputs
            .get(idx)
            .and_then(|m| psbt_mod::get_witness_utxo(m))
            .map(|(v, _)| v)
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;

        psbt_mod::sign_psbt_p2wpkh(
            &mut psbt,
            &psbt_mod::PsbtSignInput {
                input_index: idx,
                private_key: sk_bytes,
                pubkey_hash,
                amount,
            },
        )?;
    }

    let signed = psbt_mod::serialize_psbt(&psbt);
    if output_buf.len() < signed.len() {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(signed.len()),
        ));
    }
    output_buf[..signed.len()].copy_from_slice(&signed);
    Ok(signed.len())
}

/// ETH：eth-sign-request CBOR map → 签名 tx bytes
///
/// P1-01（2026-08-26）：真实 UR 的 payload 是 CBOR map，含 sign_data / data_type /
/// chain_id / derivation_path。只支持 Transaction(1) / TypedTransaction(4) 的
/// raw tx 签名（= EIP-1559/legacy）；PersonalMessage / TypedData 显式拒绝。
///
/// 派生路径 = m/44'/60'/0'/0/0。
fn sign_eth(seed: &[u8], cbor_payload: &[u8], output_buf: &mut [u8]) -> Result<usize> {
    use crate::chain::eth::{eip1559, from_rlp};
    use crate::ur::codec::eth_sign_request::{EthSignDataType, parse_eth_sign_request};

    let req = parse_eth_sign_request(cbor_payload)?;
    match req.data_type {
        EthSignDataType::Transaction | EthSignDataType::TypedTransaction => {}
        EthSignDataType::TypedData | EthSignDataType::PersonalMessage => {
            // P6.4 才开放 typed-data / personal-message；现在显式拒绝
            return Err(err(ShlosiloErrorKind::ChainKindUnsupported));
        }
    }

    let tx = from_rlp::parse_eip1559_raw(&req.sign_data)?;
    // P1-02（ETH 部分）：eth-sign-request 自带 chain_id 时校验与 tx 一致
    if let Some(req_chain) = req.chain_id {
        if req_chain != tx.chain_id as i128 {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
    }
    let path = DerivationPath::parse("m/44'/60'/0'/0/0")?;
    let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, &path)?;
    let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

    let signed = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
        tx,
        private_key: sk_bytes,
    })?;
    if output_buf.len() < signed.tx_bytes.len() {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(signed.tx_bytes.len()),
        ));
    }
    output_buf[..signed.tx_bytes.len()].copy_from_slice(&signed.tx_bytes);
    Ok(signed.tx_bytes.len())
}

/// Phase 4 实际签名时需要的网络信息（业务模块通过 `Network` 传入）
pub fn sign_with_network(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    network: Network,
    output_buf: &mut [u8],
) -> Result<usize> {
    let _ = network;
    sign(sign_input, type_tag, ur_payload, output_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::chain_kind::ChainKind;
    extern crate alloc;
    use alloc::vec::Vec;

    #[test]
    fn stub_signature_len_table() {
        assert_eq!(stub_signature_len(ChainKind::Btc), 64);
        assert_eq!(stub_signature_len(ChainKind::Eth), 65);
        assert_eq!(stub_signature_len(ChainKind::Xmr), 96);
        assert_eq!(stub_signature_len(ChainKind::Sol), 64);
        assert_eq!(stub_signature_len(ChainKind::Ar), 512);
    }

    #[test]
    fn sign_unknown_chain_kind_rejected() {
        let seed = [0u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let ur_payload = [99u8, 1, 2, 3]; // payload 任意
        let mut output_buf = [0u8; 4096];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::Unknown,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::UrPayloadUnknownType
        );
    }

    /// XMR 显式拒绝（等 Feather fixture）
    #[test]
    fn sign_xmr_unsupported_for_now() {
        let seed = [0u8; 64];
        let input = SignInput::Seed { seed: &seed };
        // crypto-monero-tx type tag（payload 任意）
        let ur_payload = [1u8, 2, 3];
        let mut output_buf = [0u8; 4096];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoMoneroTx,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::ChainKindUnsupported
        );
    }

    /// ETH 端到端：构造 raw EIP-1559 tx → 真实 eth-sign-request CBOR map → sign → 输出合法 0x02 签名 tx
    #[test]
    fn sign_eth_end_to_end() {
        use crate::chain::eth::eip1559::Eip1559Transaction;

        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        // 构造 unsigned preimage 再剥掉签名部分——直接用 signing_preimage + 手动 RLP
        // 简单方式：from_rlp round-trip——先签一次拿 raw，再当输入
        let sk = crate::curve_primitive::secp256k1::scalar_from_bytes(&[42u8; 32]).unwrap();
        let direct = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: crate::curve_primitive::secp256k1::scalar_to_bytes(&sk),
            },
        )
        .unwrap();

        let mut output_buf = [0u8; 512];
        // seed 派生 m/44'/60'/0'/0/0 与上面直接签的 key 不同——这里验证流程而非字节一致：
        // 用同一 seed 先推出 child key，再用该 key 直签做对照
        let path = DerivationPath::parse("m/44'/60'/0'/0/0").unwrap();
        let test_seed = [7u8; 64];
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let derived_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&derived);
        let expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: derived_bytes,
            },
        )
        .unwrap();
        let _ = direct;

        // P1-01：构造真实 eth-sign-request CBOR map（ur-registry 形状）
        // {2: sign_data(bytes), 3: data_type(1), 4: chain_id(1)}
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 1);

        let input = SignInput::Seed { seed: &test_seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");
        assert_eq!(n, expected.tx_bytes.len());
        assert_eq!(&output_buf[..n], &expected.tx_bytes[..]);
        assert_eq!(output_buf[0], 0x02);
    }

    /// P1-01：ETH 端到端拒绝 chain_id 不匹配的请求
    #[test]
    fn sign_eth_rejects_chain_id_mismatch() {
        let tx = crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        // 请求 chain_id=5（≠ tx 的 1）
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 5);
        let test_seed = [7u8; 64];
        let input = SignInput::Seed { seed: &test_seed };
        let mut output_buf = [0u8; 512];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(result.unwrap_err().kind, ShlosiloErrorKind::NetworkUnrecognized);
    }

    /// P1-01：ETH 端到端拒绝 personal-message（当前不支持）
    #[test]
    fn sign_eth_rejects_personal_message() {
        let raw = encode_unsigned_tx_for_test(&crate::chain::eth::eip1559::Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 12345,
            data: Vec::new(),
            access_list: Vec::new(),
        });
        // data_type = 3 (PersonalMessage)
        let ur_payload = encode_eth_sign_request_for_test(&raw, 3, 1);
        let test_seed = [7u8; 64];
        let input = SignInput::Seed { seed: &test_seed };
        let mut output_buf = [0u8; 512];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(result.unwrap_err().kind, ShlosiloErrorKind::ChainKindUnsupported);
    }

    /// 测试辅助：把未签名 EIP-1559 tx 编成 raw bytes（供 from_rlp 解析）
    fn encode_unsigned_tx_for_test(
        tx: &crate::chain::eth::eip1559::Eip1559Transaction,
    ) -> alloc::vec::Vec<u8> {
        use crate::chain::eth::rlp;
        let list = rlp::encode_list(&[
            rlp::encode_uint(tx.chain_id as u128),
            rlp::encode_uint(tx.nonce as u128),
            rlp::encode_uint(tx.max_priority_fee_per_gas),
            rlp::encode_uint(tx.max_fee_per_gas),
            rlp::encode_uint(tx.gas_limit as u128),
            rlp::encode_bytes(&tx.destination.unwrap()),
            rlp::encode_uint(tx.amount),
            rlp::encode_bytes(&tx.data),
            rlp::encode_list(&[]),
            rlp::encode_bytes(b""), // y_parity placeholder（unsigned 形状）
            rlp::encode_bytes(b""),
            rlp::encode_bytes(b""),
        ]);
        let mut out = alloc::vec![0x02u8];
        out.extend_from_slice(&list);
        out
    }

    /// 测试辅助：构造 eth-sign-request CBOR map（ur-registry 形状，最小集）
    /// {2: sign_data(bytes), 3: data_type(uint), 4: chain_id(uint)}
    fn encode_eth_sign_request_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
    ) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        let pairs = alloc::vec![
            (cbor::encode_uint(2), cbor::encode_bytes(sign_data)),
            (cbor::encode_uint(3), cbor::encode_uint(data_type)),
            (cbor::encode_uint(4), cbor::encode_uint(chain_id)),
        ];
        cbor::encode_map(&pairs)
    }

    /// BTC 端到端：构造 P2WPKH PSBT → crypto-psbt CBOR → sign() → 验证 PARTIAL_SIG
    #[test]
    fn sign_btc_psbt_end_to_end() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        // 1. 派生 key：seed → m/84'/0'/0'/0/0
        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

        // 2. 从 sk 算 compressed pubkey + hash160
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk_point = crate::curve_primitive::secp256k1::base_mul(&sk_scalar);
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(&pk_point);
        let h = crate::encoding::sha256::hash(&compressed_pk).unwrap();
        let pk_hash = crate::encoding::ripemd160::hash(&h).unwrap();

        // 3. 构造 PSBT：1 in (P2WPKH witness utxo) + 1 out
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&pk_hash);
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0,
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone(),
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![],
            outputs: alloc::vec![alloc::vec![]], // 1 个 output map（空）
        };
        // input map: WITNESS_UTXO + BIP32_DERIVATION
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22); // varint(22) script len
        wu_value.extend_from_slice(&spk);
        psbt.inputs.push(alloc::vec![
            psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO],
                value: wu_value,
            },
            psbt::KeyValue {
                key: {
                    let mut k = alloc::vec![input_type::BIP32_DERIVATION];
                    k.extend_from_slice(&compressed_pk);
                    k
                },
                // 正确形状：fp(4) || depth(1) || child(4×n)
                value: {
                    let mut vv = alloc::vec![0u8; 4]; // master fingerprint（测试用 0）
                    vv.push(path.len() as u8);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_be_bytes());
                    }
                    vv
                },
            },
        ]);

        // 4. serialize → CBOR bytes（crypto-psbt payload 就是 CBOR bytes item，无首字节 tag）
        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        // 5. 走业务入口（P1-01：type 由 tag 显式携带）
        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        // 6. 验证输出是合法 PSBT 且含我们的 PARTIAL_SIG
        let signed = psbt::parse_psbt(&output_buf[..n]).expect("re-parse");
        assert_eq!(signed.unsigned_tx.inputs.len(), 1);
        let partial = signed.inputs[0]
            .iter()
            .find(|kv| kv.key[0] == input_type::PARTIAL_SIG)
            .expect("PARTIAL_SIG injected");
        assert_eq!(&partial.key[1..], &compressed_pk[..]);
        assert_eq!(partial.value.last(), Some(&0x01));

        // 7. L1 verifier 验证签名：重算 BIP-143 sighash 并 verify
        let der_sig = &partial.value[..partial.value.len() - 1];
        let ecdsa_sig = crate::signature::ecdsa_secp256k1::from_der(der_sig).expect("der parse");
        // BIP-143 scriptCode = 76a914{pk_hash}88ac（25 bytes，无 length prefix）
        let mut script_code = alloc::vec![0x76u8, 0xa9, 0x14];
        script_code.extend_from_slice(&pk_hash);
        script_code.extend_from_slice(&[0x88, 0xac]);
        let sighash = crate::chain::btc::p2wpkh::segwit_sighash_p2wpkh(
            &signed.unsigned_tx,
            0,
            &script_code,
            100_000,
            1, // SIGHASH_ALL
        )
        .expect("sighash");
        let pk = crate::curve_primitive::secp256k1::point_from_compressed(&compressed_pk).unwrap();
        assert!(crate::signature::ecdsa_secp256k1::verify(
            &pk,
            &sighash,
            &ecdsa_sig
        ));
    }
}
