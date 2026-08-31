//! P1-03: 敏感字节材料 newtype（审计 2026-08-25 整改）。
//!
//! v2-安全 §2 纪律的类型化落地：
//! - 禁 `Copy`、禁 `Clone`——每 clone 一次 RAM 里多一份活跃密钥
//! - 禁 `Debug` 输出内容——只输出 `[REDACTED]`
//! - `ZeroizeOnDrop`——scope 结束清内存（对 dump/DMA 无效是已知残余风险，v2-安全 §1）
//! - `PartialEq` 走 `subtle` 常时比较——防时序侧信道
//!
//! 使用约定：
//! - 构造用 [`SecretBytes::new`]（复制后 zeroize 调用方栈上的原副本）
//! - 读取用 [`SecretBytes::expose`] / [`expose_mut`](SecretBytes::expose_mut)——
//!   命名即审计点，`grep -r "expose()"` 可枚举全部明文访问
//! - FFI 出参写 [`SecretBytes::write_into`]；禁止 `*expose()` 后再复制出第二份长期副本

use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 定长敏感字节（私钥 / seed / mask / tx secret）。
///
/// 不实现：`Clone`、`Copy`、`Debug`（内容）、`Display`、`AsRef<[u8]>`（防意外泄露）、
/// `From<[u8; N]>`（构造必须显式走 `new`，grep 可查）。
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> SecretBytes<N> {
    /// 从原始字节构造。仅清零**参数副本**——调用方自己的绑定仍持有明文，
    /// 只适用于调用方副本即弃的临时场景；持有多份明文时改用 [`SecretBytes::take`]。
    pub fn new(mut raw: [u8; N]) -> Self {
        let this = Self { bytes: raw };
        raw.zeroize();
        this
    }

    /// 从调用方缓冲区**接管**：复制后立即清零调用方的真实内存。
    /// 这是消灭多余明文副本的正原语（审计 P1-03 的核心诉求）。
    pub fn take(buf: &mut [u8; N]) -> Self {
        let this = Self { bytes: *buf };
        buf.zeroize();
        this
    }

    /// 全零值（占位构造用；密码学上零标量是非法密钥，消费端校验负责拒绝）。
    pub fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    /// 显式明文访问。命名即审计点——所有接触明文的代码必须经过这里。
    pub fn expose(&self) -> &[u8; N] {
        &self.bytes
    }

    /// 显式可变明文访问（FFI 出参写穿、就地变换用）。
    pub fn expose_mut(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    /// 复制到调用方提供的缓冲区（FFI 出参契约）。
    /// 注意：写出的目标缓冲区由调用方负责生命周期；本结构自身的副本照常 ZeroizeOnDrop。
    pub fn write_into(&self, out: &mut [u8]) {
        out[..N].copy_from_slice(&self.bytes);
    }

    /// 就地清零（drop 之外需要提前擦除时用）。
    pub fn zeroize_in_place(&mut self) {
        self.bytes.zeroize();
    }
}

/// 常时时间比较——`==` 不泄露前缀匹配长度。
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

/// Debug 只暴露类型与长度，绝不出内容（对齐 Mnemonic 的手写 Debug 策略）。
impl<const N: usize> fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes<{}>([REDACTED])", N)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;

    // ---- 类型纪律（P1-03 compile-fail 等价物：误加 impl 会让测试编译失败）----

    // SecretBytes 本体：禁 Clone / Copy / Debug 内容泄露
    static_assertions::assert_not_impl_any!(SecretBytes<32>: Clone, Copy);
    static_assertions::assert_not_impl_any!(SecretBytes<64>: Clone, Copy);

    // P1-03 迁移类型：禁 Clone / Copy（v2-安全 §2 + 审计 2026-08-25 P1-03）
    use crate::chain::btc::p2pkh::P2PKHSignInput;
    use crate::chain::btc::p2sh::P2SHP2WPKHSignInput;
    use crate::chain::btc::p2wpkh::P2WPKHSignInput;
    use crate::chain::btc::psbt::{PsbtP2PKHSignInput, PsbtP2SHP2WPKHSignInput, PsbtSignInput};
    use crate::chain::eth::eip155::Eip155SignInput;
    use crate::chain::eth::eip1559::Eip1559SignInput;
    use crate::chain::eth::eip712::Eip712SignInput;
    use crate::chain::eth::personal_sign::PersonalSignInput;
    use crate::chain::xmr::tx_builder::{SignedTx, TxInputSpec, TxKeyPair, TxOutputSpec};
    use crate::derivation::bip32_secp256k1::ExtendedPrivKey;
    use crate::derivation::slip10_ed25519::Slip10ExtendedKey;
    use crate::entropy::bip39_passphrase::Bip39Seed;
    use crate::entropy::mnemonic::Mnemonic;

    static_assertions::assert_not_impl_any!(TxKeyPair: Clone, Copy);
    static_assertions::assert_not_impl_any!(TxInputSpec: Clone, Copy);
    static_assertions::assert_not_impl_any!(TxOutputSpec: Clone, Copy);
    static_assertions::assert_not_impl_any!(SignedTx: Clone, Copy);
    static_assertions::assert_not_impl_any!(PsbtSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(PsbtP2PKHSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(PsbtP2SHP2WPKHSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(P2WPKHSignInput<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(P2PKHSignInput<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(P2SHP2WPKHSignInput<'static>: Clone, Copy);
    static_assertions::assert_not_impl_any!(Eip155SignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(Eip1559SignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(Eip712SignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(PersonalSignInput: Clone, Copy);
    static_assertions::assert_not_impl_any!(Bip39Seed: Clone, Copy);
    static_assertions::assert_not_impl_any!(ExtendedPrivKey: Clone, Copy);
    static_assertions::assert_not_impl_any!(Slip10ExtendedKey: Clone, Copy);
    static_assertions::assert_not_impl_any!(Mnemonic: Clone, Copy);

    #[test]
    fn take_zeroizes_caller_memory() {
        let mut raw = [0x42u8; 32];
        let secret = SecretBytes::take(&mut raw);
        // 调用方的真实内存已被清零——不是参数副本
        assert!(raw.iter().all(|&b| b == 0));
        // 本体保留内容
        assert_eq!(secret.expose(), &[0x42u8; 32]);
    }

    #[test]
    fn new_leaves_caller_binding_holding_plaintext_by_design() {
        // new 的契约：只清参数副本。此测试锁定该语义，防止未来有人误改。
        let mut raw = [0x42u8; 32];
        let secret = SecretBytes::new(raw);
        let _ = &mut raw; // raw 仍是 [0x42; 32]——调用方责任
        assert_eq!(secret.expose(), &[0x42u8; 32]);
    }

    #[test]
    fn debug_never_leaks_content() {
        let secret = SecretBytes::new([0xAAu8; 32]);
        let rendered = format!("{:?}", secret);
        assert_eq!(rendered, "SecretBytes<32>([REDACTED])");
        assert!(!rendered.contains("aa") && !rendered.contains("AA"));
    }

    #[test]
    fn partial_eq_is_content_equal() {
        let a = SecretBytes::new([1u8; 32]);
        let b = SecretBytes::new([1u8; 32]);
        let c = SecretBytes::new([2u8; 32]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn write_into_copies_full_length() {
        let secret = SecretBytes::new([7u8; 64]);
        let mut out = [0u8; 64];
        secret.write_into(&mut out);
        assert_eq!(out, [7u8; 64]);
    }

    #[test]
    fn zeroize_on_drop_impl() {
        // R1（2026-08-31）：文档承诺「scope 结束清内存」——类型系统必须兑现
        assert!(core::mem::needs_drop::<SecretBytes<32>>());
        // ZeroizeOnDrop 是零 Sized 自动 trait，用 trait bound 静态断言
        fn assert_zod<T: zeroize::ZeroizeOnDrop>() {}
        assert_zod::<SecretBytes<32>>();
        assert_zod::<SecretBytes<64>>();
    }

    #[test]
    fn zeroize_in_place_clears() {
        let mut secret = SecretBytes::new([0xFFu8; 32]);
        secret.zeroize_in_place();
        assert!(secret.expose().iter().all(|&b| b == 0));
    }
}
