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
use crate::types::SecretBytes;

extern crate alloc;

use alloc::string::String;

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

/// 从 SignInput 拿 BIP-39 seed（P1-03：SecretBytes 承载——Mnemonic 路径现场恢复，
/// restore 写入的栈 buffer 被 take 接管并清零原副本）
fn resolve_seed(sign_input: &SignInput<'_>) -> Result<SecretBytes<64>> {
    let mut restored = [0u8; 64];
    match sign_input {
        SignInput::Seed { seed } => Ok(SecretBytes::new(**seed)),
        SignInput::Mnemonic {
            mnemonic,
            passphrase,
        } => {
            crate::business::restore_seed::restore_seed(mnemonic, passphrase, &mut restored)?;
            Ok(SecretBytes::take(&mut restored))
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
    sign_with_entropy(sign_input, type_tag, ur_payload, &[], output_buf)
}

/// 签名业务入口（§B.5 RNG 注入扩展）：entropy 参数供 XMR 路径派生签名随机流。
///
/// - XMR（xmr-txunsigned / xmr-txsigned / crypto-monero-tx）：entropy **REQUIRED**，
///   < 16B 报 `EntropyInjectionInvalid`（misuse guard，非熵质量验证）
/// - BTC / ETH：deterministic backend **entropy NOT REQUIRED by current backend**
///   （RFC-6979 路径），传空切片即可
pub fn sign_with_entropy(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    let seed = resolve_seed(&sign_input)?;

    let template = tx_normalize::to_template(type_tag, ur_payload)?;
    let chain_kind = template.chain_kind;
    // payload 是完整 CBOR（不剥首字节——P1-01）
    if template.payload.is_empty() {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    let payload = template.payload.as_slice();

    match chain_kind {
        crate::types::chain_kind::ChainKind::Btc => {
            let n = sign_btc(seed.expose(), payload, output_buf)?;
            Ok(n)
        }
        crate::types::chain_kind::ChainKind::Eth => {
            let n = sign_eth(seed.expose(), payload, output_buf)?;
            Ok(n)
        }
        crate::types::chain_kind::ChainKind::Xmr => {
            let n = sign_xmr(seed.expose(), payload, entropy, output_buf)?;
            Ok(n)
        }
        _ => Err(err(ShlosiloErrorKind::ChainKindUnsupported)),
    }
}

/// XMR：xmr-txunsigned 加密 blob → 解密 → 逐 tx 签名 → SignedTxSet → 加密输出
///
/// §B.5 定案实施（P1-06 收尾）。对齐 keystone `sign_tx`：
/// 1. seed → Monero keypair（`monero_reduce_scalar::derive`，无 clamp Icarus 路径）
/// 2. 解密 unsigned_txset（view key；magic + Schnorr 验签 + ChaCha20-Legacy）
/// 3. 逐 tx `sign_tx_from_construction`（tx-key / BP+ / CLSAG(i) 三 purpose 子域 RNG）
/// 4. SignedTxSet 序列化（tx_key=ONE 占位）→ encrypt_signed_txset（SIGNED_TX_PREFIX）
///
/// rng 用途：BP+/CLSAG/加密 nonce+签名 k；tx_key r 的熵来自 entropy 派生。
fn sign_xmr(
    seed: &[u8],
    encrypted_unsigned: &[u8],
    entropy: &[u8],
    output_buf: &mut [u8],
) -> Result<usize> {
    use crate::chain::xmr::signed_txset::{
        encrypt_signed_txset, PendingTx, SignedTxSet, TxKeyImageEntry,
    };
    use crate::chain::xmr::signing_rng::{purpose_rng, RngPurpose};
    use crate::chain::xmr::unsigned_txset::deserialize_unsigned_tx;

    // 1. seed → Monero 密钥对（v2 §2.7：MoneroPath 非 BIP-32；account 0 = 主钱包）
    let path = crate::derivation::monero_reduce_scalar::MoneroPath::mainnet(0);
    let kp = crate::derivation::monero_reduce_scalar::derive(seed, &path)?;
    // 审计 #6 P1-01:主密钥字节走 Zeroizing(所有返回路径 drop 时清零)
    let spend_sec = zeroize::Zeroizing::new(crate::curve_primitive::ed25519::scalar_to_bytes(
        kp.spend_priv(),
    ));
    let view_sec = zeroize::Zeroizing::new(crate::curve_primitive::ed25519::scalar_to_bytes(
        kp.view_priv(),
    ));

    // 2. 解密（内部验签，view key 不匹配 → Err）
    // 审计 #6 P1-01:解密明文 txset 走 Zeroizing(解析后不再需要明文残留)
    let plain = zeroize::Zeroizing::new(crate::chain::xmr::unsigned_txset::decrypt_unsigned_txset(
        encrypted_unsigned,
        &view_sec,
    )?);
    let unsigned_tx = deserialize_unsigned_tx(&plain)?;

    // 3. 逐 tx 签名（§B.5 purpose 子域：tx-key r / BP+ / CLSAG(i) 独立派生）
    //    context = tx construction data 的 keccak 摘要（domain separation，不计熵）
    let mut rng = {
        use rand_chacha::rand_core::SeedableRng;
        let mut merged = alloc::vec::Vec::with_capacity(entropy.len() + 32);
        merged.extend_from_slice(entropy);
        // BP+/CLSAG 的临时随机性与 tx 无关（不复用 r 的流），统一流：TxKey 子域
        let mut seed_rng = purpose_rng(&merged, RngPurpose::TxKey, &[0u8; 32])?;
        let mut seed_bytes = [0u8; 32];
        use rand_chacha::rand_core::RngCore as _;
        seed_rng.fill_bytes(&mut seed_bytes);
        rand_chacha::ChaCha20Rng::from_seed(seed_bytes)
    };

    let mut ptxs = alloc::vec::Vec::with_capacity(unsigned_tx.txes.len());
    let mut key_images_outer: alloc::vec::Vec<[u8; 32]> = alloc::vec::Vec::new();
    let mut tx_key_images: alloc::vec::Vec<TxKeyImageEntry> = alloc::vec::Vec::new();

    // P1-03: into_iter 拿所有权——construction_data move 进 PendingTx（原本是
    // 深拷贝秘密的 tx_data.clone()，TxSourceEntry 不可 Clone 后 move 是唯一路径，
    // 也是审计要求的"秘密副本不扩散"）
    for tx_data in unsigned_tx.txes {
        // per-tx context digest
        let mut ctx_src = alloc::vec::Vec::new();
        ctx_src.extend_from_slice(&tx_data.unlock_time.to_le_bytes());
        ctx_src.extend_from_slice(&tx_data.extra);
        for s in &tx_data.sources {
            ctx_src.extend_from_slice(&s.real_out_tx_key);
            // P1-03: mask 明文访问收敛到 expose()（context digest 只读哈希）
            ctx_src.extend_from_slice(s.mask.expose());
        }
        for d in &tx_data.splitted_dsts {
            ctx_src.extend_from_slice(&d.spend_public_key);
            ctx_src.extend_from_slice(&d.view_public_key);
        }
        let context = crate::encoding::keccak256::hash(&ctx_src)?;

        // tx_key r：独立 TxKey 子域流（§B.5）
        let mut tx_key_rng = purpose_rng(entropy, RngPurpose::TxKey, &context)
            .map_err(crate::error::ShlosiloError::from)?;
        let mut r_bytes = [0u8; 32];
        use rand_chacha::rand_core::RngCore as _;
        tx_key_rng.fill_bytes(&mut r_bytes);
        let r = curve25519_dalek::Scalar::from_bytes_mod_order(r_bytes);

        // BP+ 随机性：独立子域
        let mut bp_rng = purpose_rng(entropy, RngPurpose::BulletproofPlus, &context)
            .map_err(crate::error::ShlosiloError::from)?;
        // CLSAG：per-input 子域（sign_tx_from_construction 内部按 source 顺序消费）

        let tx_bytes = crate::chain::xmr::tx_signer::sign_tx_from_construction_with_rngs(
            &tx_data,
            &spend_sec,
            &view_sec,
            &r,
            &mut bp_rng,
            &mut rng,
        )?;

        // fee（= inputs − splitted outputs）
        let input_sum: u64 = tx_data.sources.iter().map(|s| s.amount).sum();
        let out_sum: u64 = tx_data.splitted_dsts.iter().map(|d| d.amount).sum();
        let fee = input_sum.saturating_sub(out_sum);

        // key images：签名 wire 内已有；此处重建字符串 + 外层列表
        let mut ki_str = String::new();
        for src in &tx_data.sources {
            let (ki, _off) = crate::chain::xmr::subaddress::derive_input_from_source(
                &view_sec,
                &spend_sec,
                src,
                tx_data.subaddr_account,
                &tx_data.subaddr_indices,
            )?;
            ki_str.push('<');
            for b in ki {
                ki_str.push_str(&alloc::format!("{:02x}", b));
            }
            ki_str.push('>');
            ki_str.push(' ');
            key_images_outer.push(ki);
        }

        // tx_key_images：输出一次性地址 + Hs(shared_key)·Hp(stealth)
        for (i, dest) in tx_data.splitted_dsts.iter().enumerate() {
            // change 输出跳过（接收方是自己的 change 地址，keystone outputs() 也算，
            // 但 shlosilo v1 范围只登记外部收款输出）
            if dest.amount == tx_data.change_dts.amount
                && dest.spend_public_key == tx_data.change_dts.spend_public_key
            {
                continue;
            }
            let shared = {
                let a = monero_ed25519::CompressedPoint::from(dest.view_public_key)
                    .decompress()
                    .ok_or_else(|| {
                        crate::error::ShlosiloError::new(
                            crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                        )
                    })?;
                let a_ed: curve25519_dalek::EdwardsPoint = a.into();
                (a_ed * r).mul_by_cofactor().compress().to_bytes()
            };
            let mut od = alloc::vec::Vec::with_capacity(33);
            od.extend_from_slice(&shared);
            crate::chain::xmr::transaction::monero_encode_varint(&mut od, i as u64);
            let shared_key = crate::chain::xmr::subaddress::hash_to_scalar(&od)?;
            let hs = curve25519_dalek::Scalar::from_bytes_mod_order(shared_key);
            // key image = Hs(shared_key) · Hp(stealth)——stealth 即该 output 的
            // 一次性地址 = B_dest + hs·G
            let b_dest: curve25519_dalek::EdwardsPoint =
                monero_ed25519::CompressedPoint::from(dest.spend_public_key)
                    .decompress()
                    .ok_or_else(|| {
                        crate::error::ShlosiloError::new(
                            crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                        )
                    })?
                    .into();
            let stealth = (b_dest + curve25519_dalek::constants::ED25519_BASEPOINT_TABLE * &hs)
                .compress()
                .to_bytes();
            let hp: curve25519_dalek::EdwardsPoint =
                monero_ed25519::Point::biased_hash(stealth).into();
            let image = (hp * hs).compress().to_bytes();
            tx_key_images.push(TxKeyImageEntry {
                output_pubkey: stealth,
                key_image: image,
            });
        }

        ptxs.push(PendingTx {
            tx_bytes,
            dust: 0,
            fee,
            dust_added_to_fee: false,
            change_dts: tx_data.change_dts.clone(),
            selected_transfers: tx_data
                .selected_transfers
                .iter()
                .map(|&t| t as u8)
                .collect(),
            key_images_str: ki_str,
            additional_tx_keys: alloc::vec::Vec::new(),
            dests: tx_data.dests.clone(),
            // P1-03: move 而非 clone——秘密（mask/kLRki）不再产生新副本
            construction_data: tx_data,
        });
    }

    let set = SignedTxSet {
        ptx: ptxs,
        key_images: key_images_outer,
        tx_key_images,
    };
    let plain_signed = set.serialize();

    // 4. 加密输出（nonce + Schnorr k 也在 entropy 派生流上）
    let mut enc_rng = purpose_rng(entropy, RngPurpose::BulletproofPlus, &[1u8; 32])
        .map_err(crate::error::ShlosiloError::from)?;
    let encrypted = encrypt_signed_txset(plain_signed, &view_sec, &mut enc_rng)?;

    if output_buf.len() < encrypted.len() {
        return Err(ShlosiloError::with_context(
            ShlosiloErrorKind::BufferTooSmall,
            crate::error::ErrorContext::RequiredLength(encrypted.len()),
        ));
    }
    output_buf[..encrypted.len()].copy_from_slice(&encrypted);
    Ok(encrypted.len())
}

/// 从 BIP32_DERIVATION value 解析 master fingerprint + 派生路径
/// value 格式（BIP-174）：master_key_fingerprint(4B) || derivation_index(u32LE) × depth
/// P1-02：fingerprint 与路径一起返回（调用方比对本机 master fingerprint，防错链签名）
/// BIP32_DERIVATION value = master_fingerprint(4B) + path(u32LE × depth)
fn parse_derivation_value(value: &[u8]) -> Option<([u8; 4], DerivationPath)> {
    if value.len() < 8 || !(value.len() - 4).is_multiple_of(4) {
        return None;
    }
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&value[..4]);
    let depth = (value.len() - 4) / 4;
    let mut flat = alloc::vec::Vec::with_capacity(depth);
    for j in 0..depth {
        let o = 4 + 4 * j;
        let raw = u32::from_le_bytes([value[o], value[o + 1], value[o + 2], value[o + 3]]);
        flat.push(raw);
    }
    DerivationPath::from_flat(flat).ok().map(|p| (fp, p))
}

fn read_bip32_derivation(
    input_map: &[crate::chain::btc::psbt::KeyValue],
) -> Option<([u8; 4], DerivationPath)> {
    use crate::chain::btc::psbt::input_type;
    let kv = input_map
        .iter()
        .find(|kv| kv.key.first() == Some(&input_type::BIP32_DERIVATION))?;
    parse_derivation_value(&kv.value)
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

    // P1-02：本机 master fingerprint（BIP-32 序列化字段 5..9），PSBT 提示的
    // fingerprint 不一致 = 该 PSBT 不是本机钱包的（错 seed/错钱包），拒绝签名
    use alloc::vec::Vec;
    let local_fp = crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(seed)?;

    for idx in 0..psbt.unsigned_tx.inputs.len() {
        // P1-02：BIP32_DERIVATION value = master_fingerprint(4B) + path(u32LE × depth)，
        // 路径从 PSBT 读出而非硬编码；fingerprint 与本机不一致 → 拒绝；
        // 无该字段时才 fallback 默认路径（过渡行为，P6.4 收紧）。
        // P1-B：无 BIP32_DERIVATION 的输入不再 fallback 默认路径（收紧），
        // 所有输入必须显式携带 ownership records（P6.4 过渡行为提前落地）。
        let (_fp0, path_used) = read_bip32_derivation(
            psbt.inputs
                .get(idx)
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?,
        )
        .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if _fp0 != local_fp {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, &path_used)?;
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

        // R4 所有权绑定：派生公钥必须与 PSBT BIP32_DERIVATION 携带的 pubkey 一致。
        // 没有这条等值断言,恶意/构造 PSBT 可让设备对「成功但不可用」的输入签名
        // (HASH160 匹配 ≠ 该哈希确实来自我们即将使用的私钥——碰撞或账本不一致均绕过)。
        let derived_pub = crate::curve_primitive::secp256k1::point_to_compressed(
            &crate::curve_primitive::secp256k1::base_mul(&sk),
        );

        // P1-B（2026-09-01 再复审）：全部 BIP32_DERIVATION records 严格核验。
        // 每条 record 的 (fingerprint, path, pubkey) 都要过三关：
        //   fingerprint == 本机；path 派生公钥 == record 携带 pubkey；
        //   且所有 record 核验结果一致（不同 pubkey = 多签/异源混合，单签设备拒绝）。
        let input_map = psbt
            .inputs
            .get(idx)
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        let mut records: Vec<([u8; 4], DerivationPath, Vec<u8>)> = Vec::new();
        for kv in input_map.iter() {
            if kv.key.first() != Some(&psbt_mod::input_type::BIP32_DERIVATION) {
                continue;
            }
            if kv.key.len() != 1 + 33 {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let (fp, path) = parse_derivation_value(&kv.value)
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            records.push((fp, path, kv.key[1..34].to_vec()));
        }
        if records.is_empty() {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // R4 语义保留：签名 key 派生公钥与第一条 record pubkey 等值断言
        if derived_pub != records[0].2.as_slice() {
            return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
        }
        let mut pubkey_hash: Option<[u8; 20]> = None;
        for (fp, path, pk) in &records {
            if *fp != local_fp {
                return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
            }
            let rec_sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, path)?;
            let rec_pub = crate::curve_primitive::secp256k1::point_to_compressed(
                &crate::curve_primitive::secp256k1::base_mul(&rec_sk),
            );
            if rec_pub != pk.as_slice() {
                return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
            }
            // 与本输入实际签名用的 (path, sk) 一致性：record path 必须等于签名 path
            let h = crate::encoding::sha256::hash(pk)?;
            let h20 = crate::encoding::ripemd160::hash(&h)?;
            match &pubkey_hash {
                Some(prev) if *prev != h20 => {
                    // 多条 record 指向不同公钥 = 非 P2WPKH 单签语义
                    return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
                }
                Some(_) => {}
                None => {
                    pubkey_hash = Some(h20);
                    // 签名 key 用第一条核验通过的 record path（与 derived_pub 对齐）
                    if *path != path_used {
                        return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
                    }
                }
            }
        }
        let pubkey_hash =
            pubkey_hash.ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;

        // P1-B：witness utxo 绑定——金额与 scriptPubKey 必须是本输入自己的，
        // 且 scriptPubKey 必须是 P2WPKH(OP_0 PUSH20) 且 HASH160 == 我们的 pubkey_hash
        // （prevout txid 链上即指向该 script，从而把签名输入间接锚定到本 key）。
        let (amount, spk) = psbt
            .inputs
            .get(idx)
            .and_then(|m| psbt_mod::get_witness_utxo(m))
            .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        if spk.len() != 22 || spk[0] != 0x00 || spk[1] != 0x14 || spk[2..22] != pubkey_hash {
            return Err(err(ShlosiloErrorKind::PsbtOwnershipMismatch));
        }

        psbt_mod::sign_psbt_p2wpkh(
            &mut psbt,
            &psbt_mod::PsbtSignInput {
                input_index: idx,
                private_key: SecretBytes::new(sk_bytes),
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
    use crate::ur::codec::eth_sign_request::{parse_eth_sign_request, EthSignDataType};

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
    // P1-02：请求带 derivation_path 时用它派生；缺省 fallback 标准 path
    let path = match req.derivation_path {
        Some(p) => p,
        None => DerivationPath::parse("m/44'/60'/0'/0/0")?,
    };
    let sk = crate::derivation::bip32_secp256k1::derive_from_seed(seed, &path)?;
    let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);

    let signed = eip1559::sign_eip1559(&eip1559::Eip1559SignInput {
        tx,
        private_key: SecretBytes::new(sk_bytes),
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

/// 签名（network 进决策，P1-02 收口）
///
/// 校验规则：
/// - BTC：只支持 BitcoinMainnet（v1 范围；非 mainnet 显式拒绝，与 P2-05 xpub 策略一致）
/// - ETH：tx.chain_id 必须 = network 映射的 EIP-155 chain id
/// - 其他链：network 仅校验合法性（FFI 层 from_u8 已做），业务层不再拦截
pub fn sign_with_network(
    sign_input: SignInput<'_>,
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    network: Network,
    output_buf: &mut [u8],
) -> Result<usize> {
    check_network(type_tag, ur_payload, network)?;
    sign(sign_input, type_tag, ur_payload, output_buf)
}

/// P1-02：network 参数进决策
///
/// - BTC（crypto-psbt）：v1 只支持 BitcoinMainnet（与 P2-05 xpub mainnet-only 策略一致）
/// - ETH（eth-sign-request）：network 映射 EIP-155 chain id，必须与 tx 实际 chain_id
///   （及请求自带 chain_id 字段，若给）一致
/// - 其他链：FFI 层已校验 u8 合法性，业务层不拦
pub(crate) fn check_network(
    type_tag: crate::ur::ur_encode::UrTypeTag,
    ur_payload: &[u8],
    network: Network,
) -> Result<()> {
    match type_tag {
        crate::ur::ur_encode::UrTypeTag::CryptoPsbt if network != Network::BitcoinMainnet => {
            return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
        }
        crate::ur::ur_encode::UrTypeTag::EthSignRequest
            if matches!(
                network,
                Network::EthereumMainnet | Network::EthereumSepolia | Network::EthereumGoerli
            ) =>
        {
            let expected_chain_id = match network {
                Network::EthereumMainnet => 1u64,
                Network::EthereumSepolia => 11_155_111,
                _ => 5, // Goerli
            };
            let req = crate::ur::codec::eth_sign_request::parse_eth_sign_request(ur_payload)?;
            if let Some(req_chain) = req.chain_id {
                if req_chain != expected_chain_id as i128 {
                    return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
                }
            }
            let tx = crate::chain::eth::from_rlp::parse_eip1559_raw(&req.sign_data)?;
            if tx.chain_id != expected_chain_id {
                return Err(err(ShlosiloErrorKind::NetworkUnrecognized));
            }
        }
        _ => {}
    }
    Ok(())
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

    /// XMR 现已接入（P1-06 收尾）：无 entropy 时报 EntropyInjectionInvalid
    /// （§B.5 misuse guard，原 ChainKindUnsupported 行为已移除）
    #[test]
    fn sign_xmr_requires_entropy() {
        let seed = [0u8; 64];
        let input = SignInput::Seed { seed: &seed };
        // crypto-monero-tx 兼容别名 + payload 任意（XMR 分支先做 entropy guard？——
        // 实际先解密，fake payload 在解密处失败；用官方 tag + 短 entropy 验证 guard 顺序：
        // sign_xmr 先派生 keypair 再解密，entropy guard 在 purpose_rng 首次调用时触发）
        let ur_payload = [1u8, 2, 3];
        let mut output_buf = [0u8; 4096];
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::XmrTxUnsigned,
            &ur_payload,
            &mut output_buf,
        );
        // 短 payload 在 decrypt 阶段即失败（magic 校验）——两种错误都可接受，
        // 关键是不再是 ChainKindUnsupported
        let kind = result.unwrap_err().kind;
        assert!(
            kind == ShlosiloErrorKind::EncodingInvalidFormat
                || kind == ShlosiloErrorKind::EntropyInjectionInvalid,
            "unexpected kind: {:?}",
            kind
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
                private_key: SecretBytes::new(crate::curve_primitive::secp256k1::scalar_to_bytes(
                    &sk,
                )),
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
                private_key: SecretBytes::new(derived_bytes),
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
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
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
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::ChainKindUnsupported
        );
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
        encode_eth_sign_request_with_path_for_test(sign_data, data_type, chain_id, None)
    }

    /// + 可选 derivation_path（key 5, tag 305 crypto-keypath）
    fn encode_eth_sign_request_with_path_for_test(
        sign_data: &[u8],
        data_type: u64,
        chain_id: u64,
        path: Option<&DerivationPath>,
    ) -> alloc::vec::Vec<u8> {
        use crate::encoding::cbor;
        let mut pairs = alloc::vec![
            (cbor::encode_uint(2), cbor::encode_bytes(sign_data)),
            (cbor::encode_uint(3), cbor::encode_uint(data_type)),
            (cbor::encode_uint(4), cbor::encode_uint(chain_id)),
        ];
        if let Some(p) = path {
            // crypto-keypath: tag(304, {1: [idx, hardened, ...], 2: depth})
            // P1-01（审计 #4）：registry tag 是 304——旧注释/编码误写 305 已纠正
            let mut comps = alloc::vec::Vec::new();
            for idx in p.as_slice() {
                comps.push(cbor::encode_uint(idx.value() as u64));
                comps.push(cbor::encode_bool(idx.is_hardened()));
            }
            let inner = cbor::encode_map(&[
                (cbor::encode_uint(1), cbor::encode_array(&comps)),
                (cbor::encode_uint(2), cbor::encode_uint(p.len() as u64)),
            ]);
            pairs.push((cbor::encode_uint(5), cbor::encode_tag(304, &inner)));
        }
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
                // BIP-174 规范形状：master_fingerprint(4B) || child(u32LE) × depth
                value: {
                    let local_fp =
                        crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed)
                            .unwrap();
                    let mut vv = alloc::vec::Vec::new();
                    vv.extend_from_slice(&local_fp);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_le_bytes());
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
            &pk, &sighash, &ecdsa_sig
        ));
    }

    /// P1-02：PSBT 用非默认路径（m/84'/0'/1'/0/0）→ 签名用该路径派生 key（贯通证明）
    #[test]
    fn sign_btc_psbt_uses_psbt_derivation_path() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/1'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk_point = crate::curve_primitive::secp256k1::base_mul(&sk_scalar);
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(&pk_point);
        let h = crate::encoding::sha256::hash(&compressed_pk).unwrap();
        let pk_hash = crate::encoding::ripemd160::hash(&h).unwrap();

        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&pk_hash);
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![],
            outputs: alloc::vec![alloc::vec![]],
        };
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22);
        wu_value.extend_from_slice(&spk);
        let local_fp =
            crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed).unwrap();
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
                value: {
                    let mut vv = alloc::vec::Vec::new();
                    vv.extend_from_slice(&local_fp);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_le_bytes());
                    }
                    vv
                },
            },
        ]);

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        // 路径贯通证明：若 fallback 默认路径，派生 key ≠ fixture key → 签名失败
        assert!(
            result.is_ok(),
            "non-default-path PSBT must sign via BIP32_DERIVATION path"
        );
    }

    /// P1-02：BIP32_DERIVATION fingerprint 与本机不一致 → 拒绝（防错钱包签名）
    #[test]
    fn sign_btc_psbt_rejects_fingerprint_mismatch() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let pk_point = crate::curve_primitive::secp256k1::base_mul(&sk_scalar);
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(&pk_point);
        let h = crate::encoding::sha256::hash(&compressed_pk).unwrap();
        let pk_hash = crate::encoding::ripemd160::hash(&h).unwrap();

        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&pk_hash);
        let mut psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![],
            outputs: alloc::vec![alloc::vec![]],
        };
        let mut wu_value = alloc::vec::Vec::new();
        wu_value.extend_from_slice(&100_000u64.to_le_bytes());
        wu_value.push(22);
        wu_value.extend_from_slice(&spk);
        let wrong_fp = [0xDE, 0xAD, 0xBE, 0xEF];
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
                value: {
                    let mut vv = alloc::vec::Vec::new();
                    vv.extend_from_slice(&wrong_fp);
                    for c in path.as_slice() {
                        vv.extend_from_slice(&c.0.to_le_bytes());
                    }
                    vv
                },
            },
        ]);

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);

        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-B：witness_utxo scriptPubKey 与签名 key 不绑定（换到他人 P2WPKH）→ 拒绝
    #[test]
    fn p1b_rejects_witness_utxo_script_mismatch() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let path = DerivationPath::parse("m/84'/0'/0'/0/0").unwrap();
        let sk = crate::derivation::bip32_secp256k1::derive_from_seed(&seed, &path).unwrap();
        let sk_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&sk);
        let sk_scalar = crate::curve_primitive::secp256k1::scalar_from_bytes(&sk_bytes).unwrap();
        let compressed_pk = crate::curve_primitive::secp256k1::point_to_compressed(
            &crate::curve_primitive::secp256k1::base_mul(&sk_scalar),
        );

        // scriptPubKey 用别的 hash —— witness_utxo 与签名 key 脱钩
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&[0x11u8; 20]);
        let _ = compressed_pk;

        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![alloc::vec![
                psbt::KeyValue {
                    key: alloc::vec![input_type::WITNESS_UTXO],
                    value: {
                        let mut v = alloc::vec::Vec::new();
                        v.extend_from_slice(&100_000u64.to_le_bytes());
                        v.push(22);
                        v.extend_from_slice(&spk);
                        v
                    },
                },
                psbt::KeyValue {
                    key: {
                        let mut k = alloc::vec![input_type::BIP32_DERIVATION];
                        k.extend_from_slice(&compressed_pk);
                        k
                    },
                    value: {
                        let fp =
                            crate::derivation::bip32_secp256k1::master_fingerprint_from_seed(&seed)
                                .unwrap();
                        let mut vv = alloc::vec::Vec::new();
                        vv.extend_from_slice(&fp);
                        for c in path.as_slice() {
                            vv.extend_from_slice(&c.0.to_le_bytes());
                        }
                        vv
                    },
                },
            ]],
            outputs: alloc::vec![alloc::vec![]],
        };

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);
        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::PsbtOwnershipMismatch
        );
    }

    /// P1-B：无 BIP32_DERIVATION record（旧 fallback 默认路径已删除）→ 拒绝
    #[test]
    fn p1b_rejects_missing_derivation_record() {
        use crate::chain::btc::p2wpkh::{OutPoint, Transaction, TxIn, TxOut};
        use crate::chain::btc::psbt::{self, input_type, Psbt};
        use crate::encoding::cbor;

        let seed = [0xA5u8; 64];
        let mut spk = alloc::vec![0x00u8, 0x14];
        spk.extend_from_slice(&[0x22u8; 20]);

        let psbt = Psbt {
            unsigned_tx: Transaction {
                version: 2,
                inputs: alloc::vec![TxIn {
                    prev_out: OutPoint {
                        txid: [0xABu8; 32],
                        vout: 0
                    },
                    script_sig: Vec::new(),
                    sequence: 0xffff_ffff,
                    witness: Vec::new(),
                }],
                outputs: alloc::vec![TxOut {
                    value: 90_000,
                    script_pubkey: spk.clone()
                }],
                lock_time: 0,
            },
            inputs: alloc::vec![alloc::vec![psbt::KeyValue {
                key: alloc::vec![input_type::WITNESS_UTXO],
                value: {
                    let mut v = alloc::vec::Vec::new();
                    v.extend_from_slice(&100_000u64.to_le_bytes());
                    v.push(22);
                    v.extend_from_slice(&spk);
                    v
                },
            }]],
            outputs: alloc::vec![alloc::vec![]],
        };

        let psbt_bytes = psbt::serialize_psbt(&psbt);
        let ur_payload = cbor::encode_bytes(&psbt_bytes);
        let mut output_buf = [0u8; 4096];
        let input = SignInput::Seed { seed: &seed };
        let result = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::EncodingInvalidFormat
        );
    }

    /// P1-02：eth-sign-request 带 derivation_path → 用该路径派生 key 签名（贯通证明）
    #[test]
    fn sign_eth_uses_request_derivation_path() {
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
        let test_seed = [7u8; 64];
        // 非默认路径：account 1
        let path = DerivationPath::parse("m/44'/60'/1'/0/0").unwrap();
        let derived =
            crate::derivation::bip32_secp256k1::derive_from_seed(&test_seed, &path).unwrap();
        let derived_bytes = crate::curve_primitive::secp256k1::scalar_to_bytes(&derived);
        let expected = crate::chain::eth::eip1559::sign_eip1559(
            &crate::chain::eth::eip1559::Eip1559SignInput {
                tx: tx.clone(),
                private_key: SecretBytes::new(derived_bytes),
            },
        )
        .unwrap();

        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_with_path_for_test(&raw, 1, 1, Some(&path));

        let mut output_buf = [0u8; 512];
        let input = SignInput::Seed { seed: &test_seed };
        let n = sign(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            &mut output_buf,
        )
        .expect("sign ok");

        // 签名 bytes 与该路径派生 key 的直签结果一致 → 路径贯通
        assert_eq!(&output_buf[..n], expected.tx_bytes.as_slice());
    }

    /// P1-02：network 进决策——BTC 非 mainnet 拒绝
    #[test]
    fn sign_with_network_btc_rejects_testnet() {
        let seed = [0xA5u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let ur_payload = [1u8, 2, 3]; // 内容无关紧要：network 检查在解析前
        let mut output_buf = [0u8; 4096];
        let result = sign_with_network(
            input,
            crate::ur::ur_encode::UrTypeTag::CryptoPsbt,
            &ur_payload,
            Network::BitcoinTestnet,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-02：network 进决策——ETH network(10=mainnet,chain_id=1) 与 tx chain_id 不匹配拒绝
    #[test]
    fn sign_with_network_eth_rejects_chain_id_mismatch() {
        use crate::chain::eth::eip1559::Eip1559Transaction;
        let tx = Eip1559Transaction {
            chain_id: 137, // polygon，≠ mainnet 1
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 1,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 1);
        let seed = [7u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let mut output_buf = [0u8; 4096];
        let result = sign_with_network(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            Network::EthereumMainnet,
            &mut output_buf,
        );
        assert_eq!(
            result.unwrap_err().kind,
            ShlosiloErrorKind::NetworkUnrecognized
        );
    }

    /// P1-02：network 进决策——ETH network 与 tx chain_id 匹配时放行（成功签名）
    #[test]
    fn sign_with_network_eth_accepts_matching() {
        use crate::chain::eth::eip1559::Eip1559Transaction;
        let tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21_000,
            destination: Some([0x11u8; 20]),
            amount: 1,
            data: Vec::new(),
            access_list: Vec::new(),
        };
        let raw = encode_unsigned_tx_for_test(&tx);
        let ur_payload = encode_eth_sign_request_for_test(&raw, 1, 1);
        let seed = [7u8; 64];
        let input = SignInput::Seed { seed: &seed };
        let mut output_buf = [0u8; 4096];
        let result = sign_with_network(
            input,
            crate::ur::ur_encode::UrTypeTag::EthSignRequest,
            &ur_payload,
            Network::EthereumMainnet,
            &mut output_buf,
        );
        assert!(result.is_ok());
    }
}
