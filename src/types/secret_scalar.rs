//! SecretScalar:不可 Copy 的 dalek Scalar 秘密 owner(审计 #9-#10 P1)
//!
//! 设计(审计 #10 P1-01/P1-02 重构):
//! - **白名单运算**:不向调用者暴露 `&Scalar`——`Scalar: Copy`,任何返回
//!   泛型 `R` 或 `&Scalar` 的回调都能让值逃逸(第十次复审用仓库外最小
//!   程序编译运行复现)。所有消费走本模块白名单:点乘/标量加/write_bytes。
//! - **内部 Zeroizing<Scalar>**:构造不建立普通 `let s: Scalar` 中间绑定
//!   (上一轮 `let s = ...; Self { scalar: s }` 的来源绑定不受 wrapper
//!   Drop 覆盖——Copy 类型构造后复制进 owner 不能证明来源栈槽已擦)。
//! - 算术结果如需继续保护,由本模块返回新的 SecretScalar;公开点结果
//!   (EdwardsPoint/压缩字节)本身非秘密,直接返回。

use curve25519_dalek::scalar::Scalar;
use zeroize::Zeroize;

pub struct SecretScalar {
    scalar: Zeroizing<Scalar>,
}

// Zeroizing<Scalar> 提供 Deref<Target=Scalar> 与 Drop 清零
use zeroize::Zeroizing;

impl SecretScalar {
    /// 从字节构造。raw 为调用方缓冲——本函数内部直接在 Zeroizing 中
    /// 建立 Scalar,不落地普通 `let s: Scalar` 中间绑定。
    pub fn from_bytes_mod_order(raw: [u8; 32]) -> Self {
        Self {
            scalar: Zeroizing::new(Scalar::from_bytes_mod_order(raw)),
        }
    }

    /// 从字节切片构造(view_sec 等已有 owner 的 expose() 结果)。
    pub fn from_slice(bytes: &[u8; 32]) -> Self {
        Self::from_bytes_mod_order(*bytes)
    }

    /// 白名单:标量加(bytes 形式,monero key_offset 派生场景)。
    /// 返回新 owner。审计 #11 P1-01:表达式直接进 owner——上一版
    /// `let o = ...; let sum = ...; let out = ...;` 三个普通绑定
    /// (注释声称"临时 o 被 Zeroizing 接管"与代码不符)全部消除
    pub fn add_bytes(&self, other: &[u8; 32]) -> Self {
        Self {
            scalar: Zeroizing::new(*self.scalar + Scalar::from_bytes_mod_order(*other)),
        }
    }

    /// 白名单:基础点乘(r·G)→ 压缩点(公开值)。
    pub fn mul_basepoint(&self) -> [u8; 32] {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        self.with(|v| (ED25519_BASEPOINT_TABLE * v).compress().to_bytes())
    }

    /// 白名单:任意点乘(point * scalar)→ 压缩点(公开值)。
    /// 接收压缩点字节(内部解压)。审计 #11 P0-01:解压失败返回 Err
    /// (不可信点编码可从敌对签名请求到达——expect panic 在真机
    /// panic=abort 下是整机 DoS;恢复改造前的 totality)
    pub fn mul_point(
        &self,
        point_bytes: &[u8; 32],
    ) -> Result<[u8; 32], crate::error::ShlosiloError> {
        let point: curve25519_dalek::EdwardsPoint =
            curve25519_dalek::edwards::CompressedEdwardsY(*point_bytes)
                .decompress()
                .ok_or_else(|| {
                    crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                    )
                })?;
        Ok(self.with(|v| (point * v).compress().to_bytes()))
    }

    /// 白名单:点乘 + cofactor(8Ra = (A_v·r)·8 变体,输入压缩点)。
    pub fn mul_point_cofactor(
        &self,
        point_bytes: &[u8; 32],
    ) -> Result<[u8; 32], crate::error::ShlosiloError> {
        let point: curve25519_dalek::EdwardsPoint =
            curve25519_dalek::edwards::CompressedEdwardsY(*point_bytes)
                .decompress()
                .ok_or_else(|| {
                    crate::error::ShlosiloError::new(
                        crate::error::ShlosiloErrorKind::EncodingInvalidFormat,
                    )
                })?;
        Ok(self.with(|v| (point * v).mul_by_cofactor().compress().to_bytes()))
    }

    /// 白名单:多标量点乘(monero stealth = B_dest + Hs·G)。
    /// 返回压缩点(公开值)。
    pub fn mul_basepoint_add_point(&self, point: &curve25519_dalek::EdwardsPoint) -> [u8; 32] {
        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
        self.with(|v| (point + ED25519_BASEPOINT_TABLE * v).compress().to_bytes())
    }

    /// 白名单:域加法(累加 blinding mask 场景)。
    pub fn add_assign(&mut self, other: &Scalar) {
        *self.scalar += *other;
    }

    /// 白名单:显式立即清零(正常路径收尾;错误路径由 Drop 覆盖)。
    pub fn zeroize_now(&mut self) {
        self.scalar.zeroize();
    }

    /// 白名单:与另一 SecretScalar 相加 → 新 SecretScalar。
    /// 审计 #11 P1-01:表达式直接进 owner(上版先建普通 sum 再复制)
    pub fn add_secret(&self, other: &SecretScalar) -> SecretScalar {
        Self {
            scalar: Zeroizing::new(self.with(|a| other.with(|b| a + b))),
        }
    }

    /// 白名单:与另一 SecretScalar 相减 → 新 SecretScalar。
    /// genRctSimple 最后输入 `a[last] = Σout_masks − Σprev_pseudo`。
    pub fn sub_secret(&self, other: &SecretScalar) -> SecretScalar {
        Self {
            scalar: Zeroizing::new(self.with(|a| other.with(|b| a - b))),
        }
    }

    /// 白名单:写出字节(wire 序列化等公开消费)。
    pub fn write_bytes(&self, out: &mut [u8; 32]) {
        *out = self.scalar.to_bytes();
    }

    /// 白名单:读出字节副本(调用方负责该副本的生命周期;仅限
    /// 立即进入下一个 owner/哈希的短路径)。
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar.to_bytes()
    }

    /// 内部:受控借用(仅限本模块白名单实现使用)
    fn with<R>(&self, f: impl FnOnce(&Scalar) -> R) -> R {
        f(&self.scalar)
    }
}

impl core::fmt::Debug for SecretScalar {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretScalar([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    static_assertions::assert_not_impl_any!(SecretScalar: Clone, Copy);

    /// 审计 #10 P1-01:白名单 API 不再暴露 &Scalar——点乘/加法返回公开点
    /// 或新 owner,不存在可复制底层 Scalar 的通用回调。
    /// (旧 API `with_scalar<R>(&self, f: impl FnOnce(&Scalar) -> R)` 已删除:
    ///  Scalar: Copy 时 `|s| *s` 可合法逃逸,复审判定为 owner 逃逸漏洞)
    #[test]
    fn whitelist_ops_return_public_or_owner() {
        let owner = SecretScalar::from_bytes_mod_order([0x77u8; 32]);
        // 点乘:返回压缩点(公开值)——无 Scalar 逃逸路径
        let pub_point = owner.mul_basepoint();
        assert_ne!(pub_point, [0u8; 32]);
        // 标量加:返回新 owner
        let sum = owner.add_bytes(&[0x11u8; 32]);
        let mut expect = [0u8; 32];
        expect.copy_from_slice(
            &(Scalar::from_bytes_mod_order([0x77u8; 32])
                + Scalar::from_bytes_mod_order([0x11u8; 32]))
            .to_bytes(),
        );
        assert_eq!(sum.to_bytes(), expect);
    }

    /// 审计 #10 P1-02:构造不建立普通 let s 中间绑定(内部直接
    /// Zeroizing<Scalar>);本测试锁定 API 面不被回退。
    #[test]
    fn construction_contract() {
        // 注意:from_bytes_mod_order 会 reduce mod l——非规范编码(如 0x42
        // 全填充)的字节表示会变化;测试用规范小标量(0x42 仅最低字节)
        let mut raw = [0u8; 32];
        raw[0] = 0x42;
        let owner = SecretScalar::from_bytes_mod_order(raw);
        let mut out = [0u8; 32];
        owner.write_bytes(&mut out);
        assert_eq!(out, raw);
        // mul_basepoint(BP+ 场景)
        let p = owner.mul_basepoint();
        assert_ne!(p, [0u8; 32]);
    }

    /// 审计 #11 P0-01:不可信压缩点解压失败 → Err(不 panic)。
    /// 复审以仓库外 PoC 复现 [0x02;32] 触发 expect panic(真机=abort/DoS)。
    /// totality 是本类型 API 的硬门禁——回归即失败。
    #[test]
    fn invalid_point_encoding_returns_err_not_panic() {
        let owner = SecretScalar::from_bytes_mod_order([0x42u8; 32]);
        // [0x02;32] 不是合法压缩点(复审 PoC 用的编码)
        assert!(owner.mul_point(&[0x02u8; 32]).is_err());
        assert!(owner.mul_point_cofactor(&[0x02u8; 32]).is_err());
        // 合法点仍正常工作(不误伤)
        let pt = curve25519_dalek::constants::ED25519_BASEPOINT_TABLE
            * &curve25519_dalek::Scalar::from(1u8);
        let pt_bytes = pt.compress().to_bytes();
        assert!(owner.mul_point(&pt_bytes).is_ok());
        assert!(owner.mul_point_cofactor(&pt_bytes).is_ok());
    }

    /// add_secret:owner + owner → owner(域算术全封闭)
    #[test]
    fn add_secret_returns_owner() {
        let a = SecretScalar::from_bytes_mod_order([1u8; 32]);
        let b = SecretScalar::from_bytes_mod_order([2u8; 32]);
        let c = a.add_secret(&b);
        let mut out = [0u8; 32];
        c.write_bytes(&mut out);
        let expect =
            Scalar::from_bytes_mod_order([1u8; 32]) + Scalar::from_bytes_mod_order([2u8; 32]);
        assert_eq!(out, expect.to_bytes());
    }

    /// sub_secret:owner − owner → owner(genRctSimple last-mask 用)
    #[test]
    fn sub_secret_returns_owner() {
        let a = SecretScalar::from_bytes_mod_order([7u8; 32]);
        let b = SecretScalar::from_bytes_mod_order([3u8; 32]);
        let c = a.sub_secret(&b);
        let mut out = [0u8; 32];
        c.write_bytes(&mut out);
        let expect =
            Scalar::from_bytes_mod_order([7u8; 32]) - Scalar::from_bytes_mod_order([3u8; 32]);
        assert_eq!(out, expect.to_bytes());
    }
}
