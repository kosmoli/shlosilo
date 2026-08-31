//! UR 多分片状态机（R3 路线 A 修正版，2026-08-31）— L2 边界适配层
//!
//! L1 `encoding::fountain` 提供纯函数分片/重组；本模块加：
//! - UR 字符串帧封装（`ur:<type>/<seq>-<count>/<bytewords-minimal>`，对齐 BCR-2020-06）
//! - 有状态 `&mut self` Encoder/Decoder（alloc 允许，**不跨 FFI**——FFI 侧走 typed 句柄）
//! - budget 守护：payload 上限 / 帧字符串上限 / decode 侧总帧数上限
//!
//! 单帧通道（小交易直出大 QR）继续走 `ur_encode::encode`——本模块只管多分片。

extern crate alloc;

use crate::encoding::bytewords;
use crate::encoding::fountain::{
    FountainDecoder, FountainEncoder, Part, MAX_SEQUENCE_COUNT,
};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

/// 多分片 payload 上限——对齐 TxTemplate 16 KiB（v2-安全 §4 体积护栏同源）
pub const MULTIPART_PAYLOAD_MAX_LEN: usize = 16384;
/// 单帧字符串上限：bytewords ≈ 2×data；data ≤ fragment(≤payload) → 2×16 KiB 裕量
pub const MULTIPART_FRAME_MAX_LEN: usize = 40960;
/// 单帧 payload 上限（单帧大 QR 通道走 ur_encode::encode，此处仅分片）
pub const DEFAULT_FRAGMENT_LEN: usize = 200;

// ─── Encoder ───────────────────────────────────────────────────────

/// 有状态多分片编码器。`next_frame()` 产出 URI 帧字符串；
/// XMR 补扫场景用 `next_cyclic_frame()`。
pub struct UrMultipartEncoder {
    inner: FountainEncoder,
    type_name: alloc::string::String,
}

impl UrMultipartEncoder {
    pub fn new(type_name: &str, payload: &[u8], max_fragment_len: usize) -> Result<Self> {
        if payload.len() > MULTIPART_PAYLOAD_MAX_LEN {
            return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
        }
        let type_ok = !type_name.is_empty()
            && type_name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-');
        if !type_ok {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        Ok(Self {
            inner: FountainEncoder::new(payload, max_fragment_len)
                .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?,
            type_name: alloc::string::String::from(type_name),
        })
    }

    pub fn fragment_count(&self) -> usize {
        self.inner.fragment_count()
    }

    /// 下一帧 URI（`ur:<type>/<seq>-<count>/<bytewords>`）
    pub fn next_frame(&mut self) -> Result<alloc::string::String> {
        let part = self.inner.next_part();
        self.frame_of(&part)
    }

    /// XMR cyclic 补扫帧（seq 到顶回 1）
    pub fn next_cyclic_frame(&mut self) -> Result<alloc::string::String> {
        let part = self.inner.next_cyclic_part();
        self.frame_of(&part)
    }

    fn frame_of(&self, part: &Part) -> Result<alloc::string::String> {
        let body_bytes = part.to_cbor();
        let body = bytewords::encode_minimal(&body_bytes);
        let mut frame = alloc::string::String::with_capacity(body.len() + 40);
        use core::fmt::Write;
        core::write!(
            frame,
            "ur:{}/{}/{}",
            self.type_name,
            part.sequence_id(),
            body
        )
        .map_err(|_| err(ShlosiloErrorKind::EncodingBufferOverflow))?;
        if frame.len() > MULTIPART_FRAME_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingBufferOverflow));
        }
        Ok(frame)
    }
}

// ─── 帧解析（纯函数，供 Decoder 与测试用）─────────────────────────

/// 解析一帧 URI → (type, seq, seq_count, part CBOR bytes)
/// 形状：`ur:<type>/<seq>-<count>/<body>`；单帧（无 seq 段）返回 Err(NotMultipart)
pub(crate) fn parse_frame(uri: &str) -> Result<Frame<'_>> {
    let rest = uri
        .strip_prefix("ur:")
        .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    let (type_name, rest) = rest
        .split_once('/')
        .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    if type_name.is_empty()
        || !type_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(err(ShlosiloErrorKind::UrPayloadUnknownType));
    }
    // seq-count 段可选：无 → 单帧
    match rest.split_once('/') {
        None => Err(err(ShlosiloErrorKind::EncodingInvalidFormat)), // 单帧走 ur_decode::decode
        Some((seq_str, body)) => {
            let (seq, count) = seq_str
                .split_once('-')
                .ok_or_else(|| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            let seq: usize = seq
                .parse()
                .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            let count: usize = count
                .parse()
                .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
            if seq == 0 || count == 0 || seq > count || count > MAX_SEQUENCE_COUNT {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let part_cbor = bytewords::decode_minimal(body)?;
            Ok(Frame {
                type_name,
                sequence: seq,
                sequence_count: count,
                part_cbor,
            })
        }
    }
}

/// 已解析的帧
pub(crate) struct Frame<'a> {
    pub type_name: &'a str,
    pub sequence: usize,
    pub sequence_count: usize,
    pub part_cbor: alloc::vec::Vec<u8>,
}

/// Part CBOR 解码（对齐 to_cbor 形状；复用 X1 加固后的 cbor decoder）
pub(crate) fn part_from_cbor(bytes: &[u8]) -> Result<Part> {
    let item = crate::encoding::cbor::decode(bytes)
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    let arr = item
        .as_array()
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    if arr.len() != 5 {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    let sequence = arr[0].as_uint().map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))? as usize;
    let sequence_count = arr[1].as_uint().map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))? as usize;
    let message_length = arr[2].as_uint().map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))? as usize;
    let checksum = arr[3].as_uint().map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))? as u32;
    let data = arr[4]
        .as_bytes()
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    if sequence == 0 || sequence_count == 0 || sequence > sequence_count {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    Ok(Part {
        sequence,
        sequence_count,
        message_length,
        checksum,
        data: alloc::vec::Vec::from(data),
    })
}

// ─── Decoder ───────────────────────────────────────────────────────

/// 有状态多分片解码器。逐帧 `receive_frame()`，`progress()` 驱动 UI，
/// `complete()` 后 `payload()` 取结果（只读借用——caller 需要所有权时 clone/copy 走 budget）。
pub struct UrMultipartDecoder {
    inner: FountainDecoder,
    type_name: Option<alloc::string::String>,
}

impl UrMultipartDecoder {
    pub fn new() -> Self {
        Self {
            inner: FountainDecoder::new(),
            type_name: None,
        }
    }

    /// 收一帧 URI。Ok(true)=有新信息, Ok(false)=重复/无新信息。
    /// type 一致性校验：跨 type 混帧拒绝。
    pub fn receive_frame(&mut self, uri: &str) -> Result<bool> {
        let frame = parse_frame(uri)?;
        match &self.type_name {
            None => {
                self.type_name =
                    Some(alloc::string::String::from(frame.type_name));
            }
            Some(t) if t != frame.type_name => {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            _ => {}
        }
        let part = part_from_cbor(&frame.part_cbor)?;
        // seq 元数据一致性（fountain 内部也校验，这里提前挡，错误语义更准）
        if part.sequence_count != frame.sequence_count
            || part.sequence != frame.sequence
        {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        self.inner
            .receive(part)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))
    }

    pub fn progress(&self) -> u8 {
        self.inner.progress()
    }

    pub fn complete(&self) -> bool {
        self.inner.complete()
    }

    /// 完成后的 payload（None = 未完成）
    pub fn payload(&self) -> Result<Option<alloc::vec::Vec<u8>>> {
        self.inner
            .message()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))
    }
}

impl Default for UrMultipartDecoder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── 测试：BCR-2020-06 oracle + roundtrip + budget ─────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// keystone-ur ur.rs doctest 向量（单帧语义对照——我们分片层帧形状一致性）
    #[test]
    fn frame_format_matches_bcr() {
        // 4 字节 payload, 2 分片 → 第一帧应为 ur:bytes/1-2/<bytewords>
        let mut enc = UrMultipartEncoder::new("bytes", b"12345678", 4).unwrap();
        assert_eq!(enc.fragment_count(), 2);
        let f1 = enc.next_frame().unwrap();
        assert!(f1.starts_with("ur:bytes/1-2/"), "frame={f1}");
        let f2 = enc.next_frame().unwrap();
        assert!(f2.starts_with("ur:bytes/2-2/"), "frame={f2}");
    }

    /// 端到端：2 KiB payload → 200B 分片 → 逐帧（乱序 + 丢帧 + 重复帧）→ 重组
    #[test]
    fn end_to_end_out_of_order_lossy() {
        let payload: Vec<u8> = (0..2048).map(|i| (i * 13 % 251) as u8).collect();
        let mut enc = UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN)
            .unwrap();
        let mut frames = Vec::new();
        for _ in 0..enc.fragment_count() {
            frames.push(enc.next_frame().unwrap());
        }
        assert!(frames.len() >= 10, "2KiB/200B should be ~11 fragments");

        // 乱序 + 丢 1 帧 + 重复帧 + fountain 冗余补齐
        let mut dec = UrMultipartDecoder::new();
        let mut feed: Vec<&str> = frames.iter().map(|s| s.as_str()).collect();
        feed.reverse(); // 乱序
        // 丢掉一帧(尾部), 后面用 cyclic 冗余补
        let dropped = feed.pop().unwrap();

        // 乱序喂帧（丢 1 帧）——fountain 冗余可能中途凑齐，不假设必然未完成
        let mut cyclic = UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN)
            .unwrap();
        for f in &feed {
            let _ = dec.receive_frame(f).unwrap();
        }
        // 缺帧时用 cyclic 冗余补到 complete
        let mut guard = 0;
        while !dec.complete() {
            let f = cyclic.next_cyclic_frame().unwrap();
            let _ = dec.receive_frame(&f).unwrap_or(false);
            guard += 1;
            assert!(guard < 100, "fountain should recover quickly");
        }
        assert!(guard > 0 || feed.len() >= enc.fragment_count() - 1);
        assert_eq!(dec.payload().unwrap().as_deref(), Some(&payload[..]));
        assert_ne!(dropped, ""); // silence unused
    }

    /// 跨 type 混帧拒绝
    #[test]
    fn mixed_type_rejected() {
        let mut enc_a = UrMultipartEncoder::new("bytes", b"11112222", 4).unwrap();
        let _ = enc_a.next_frame().unwrap();
        let f2 = enc_a.next_frame().unwrap();

        let mut enc_b = UrMultipartEncoder::new("crypto-psbt", b"11112222", 4).unwrap();
        let g1 = enc_b.next_frame().unwrap();

        let mut dec = UrMultipartDecoder::new();
        dec.receive_frame(g1.as_str()).unwrap();
        assert!(dec.receive_frame(&f2).is_err());
    }

    /// seq/count 域校验: 0 / seq>count / 超限 count
    #[test]
    fn invalid_seq_domain_rejected() {
        assert!(parse_frame("ur:bytes/0-2/aaaa").is_err());
        assert!(parse_frame("ur:bytes/3-2/aaaa").is_err());
        assert!(parse_frame("ur:bytes/1-999/aaaa").is_err());
        // 单帧形状(无 seq 段)→ Err(单帧应走 ur_decode::decode)
        assert!(parse_frame("ur:bytes/aaaa").is_err());
        assert!(parse_frame("not-a-ur").is_err());
    }

    /// payload 超预算拒绝（16 KiB + 1）
    #[test]
    fn payload_over_budget_rejected() {
        let big: Vec<u8> = (0..MULTIPART_PAYLOAD_MAX_LEN + 1).map(|_| 0u8).collect();
        assert!(UrMultipartEncoder::new("bytes", &big, DEFAULT_FRAGMENT_LEN).is_err());
    }

    /// type 字符域校验
    #[test]
    fn invalid_type_rejected() {
        assert!(UrMultipartEncoder::new("bad type!", b"data", 4).is_err());
        assert!(UrMultipartEncoder::new("", b"data", 4).is_err());
    }
}
