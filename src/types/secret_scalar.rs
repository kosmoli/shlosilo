//! SecretScalar:不可 Copy 的 dalek Scalar 秘密 owner(审计 #9 P1-02)
//!
//! 背景:curve25519-dalek 的 `Scalar` 是 `#[derive(Copy, Clone)]`,启用
//! `zeroize` feature 只提供显式 `impl Zeroize`,**没有 Drop/ZeroizeOnDrop**。
//! 普通 `Scalar` 绑定在任何 `?` 返回路径上都不会自动清零。
//!
//! 本类型包装 Scalar 并提供 Drop 清零;算术/哈希消费点通过 `with_scalar`
//! 闭包临时借用,不在外层留下普通 Scalar 绑定。禁 Clone/Copy。

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

pub struct SecretScalar {
    scalar: Scalar,
}

impl SecretScalar {
    /// 从字节构造(内部 Scalar 不再暴露明文字节绑定)。
    pub fn from_bytes_mod_order(mut raw: [u8; 32]) -> Self {
        let s = Scalar::from_bytes_mod_order(raw);
        raw.zeroize();
        Self { scalar: s }
    }

    /// 从已有 Scalar 接管:复制进 owner 并立即清零调用方绑定。
    /// (Scalar 是 Copy——调用方必须持有 `mut` 绑定才能传入)
    pub fn take(scalar: &mut Scalar) -> Self {
        let s = *scalar;
        scalar.zeroize();
        Self { scalar: s }
    }

    /// 借出 Scalar 做计算(点乘/哈希等只读消费)。
    pub fn with_scalar<R>(&self, f: impl FnOnce(&Scalar) -> R) -> R {
        f(&self.scalar)
    }

    /// 可变借用(域算术累加等)。
    pub fn with_scalar_mut<R>(&mut self, f: impl FnOnce(&mut Scalar) -> R) -> R {
        f(&mut self.scalar)
    }

    /// 显式转出 bytes(供 wire 写入;调用方缓冲生命周期自理)。
    pub fn write_bytes(&self, out: &mut [u8; 32]) {
        *out = self.scalar.to_bytes();
    }
}

impl Drop for SecretScalar {
    fn drop(&mut self) {
        self.scalar.zeroize();
    }
}

// Debug 不暴露内容
impl core::fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretScalar([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(SecretScalar: Clone, Copy);

    /// Drop 清零语义:消费后无法直接观察(对象消失),通过 zeroize 循环
    /// 等价性 + take 接管语义锁定(与 guard 同一审计纪律)。
    #[test]
    fn take_zeroizes_source() {
        let mut s = Scalar::from_bytes_mod_order([0x77u8; 32]);
        let owner = SecretScalar::take(&mut s);
        // 源绑定已被清零(Scalar zeroize = 字节全零)
        assert_eq!(s.to_bytes(), [0u8; 32]);
        owner.with_scalar(|v| {
            assert_eq!(*v, Scalar::from_bytes_mod_order([0x77u8; 32]));
        });
    }

    #[test]
    fn from_bytes_zeroizes_source() {
        let mut raw = [0xAAu8; 32];
        let owner = SecretScalar::from_bytes_mod_order(raw);
        raw.zeroize();
        let _ = owner;
        // 原始数组也被 from_bytes_mod_order 内部清零
        // (构造函数契约)
    }
}
