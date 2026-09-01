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
use crate::encoding::fountain::{FountainDecoder, FountainEncoder, Part, MAX_SEQUENCE_COUNT};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

/// P1-02（审计 #4）：wire u64 → usize fallible 转换——usize::MAX 之上直接拒绝，
/// 禁止 `as usize` 静默截断（32-bit Thumb 目标上 u64→usize 截断语义危险）
fn wire_len(n: u64) -> Result<usize> {
    usize::try_from(n)
        .ok()
        .filter(|&v| v <= MULTIPART_FRAME_MAX_LEN * 4)
        .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadTooLarge))
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
            // P0-B (2026-09-01): seq > count 是标准 fountain 混合冗余帧
            //（BC-UR 语义：sequence_count=原始分片数，seq 从 count+1 起为冗余），
            // 不再拒绝——否则 decoder 拒收自家 encoder 的冗余帧。
            // seq 上限仅为资源预算（长扫无限增长防护），非协议语义。
            // 审计 #5 P1-01: 两层预算统一——seq ≤ MAX_SEQUENCE_COUNT
            // (fountain 冗余帧 seq ≤ count ≤ 256;旧 1024 与 4096 不一致)
            if seq == 0 || count == 0 || count > MAX_SEQUENCE_COUNT || seq > MAX_SEQUENCE_COUNT {
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
    // P1-02（审计 #4）：wire u64 → usize/u32 全部 fallible，禁止静默窄化
    //（32-bit Thumb 上 u64 截断语义危险）；message_length 受 payload 预算约束
    let sequence = wire_len(
        arr[0]
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )?;
    let sequence_count = wire_len(
        arr[1]
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )?;
    let message_length = wire_len(
        arr[2]
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )?;
    let checksum = u32::try_from(
        arr[3]
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )
    .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    let data = arr[4]
        .as_bytes()
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    // P0-B: 允许 sequence > sequence_count（fountain 混合冗余帧）；上限同 parse_frame
    if sequence == 0
        || sequence_count == 0
        || sequence_count > MAX_SEQUENCE_COUNT
        || sequence > MAX_SEQUENCE_COUNT
    {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    // P1-02: message_length 预算——decoder 侧强制（修复前只有 encoder 侧检查）
    if message_length == 0 || message_length > MULTIPART_PAYLOAD_MAX_LEN {
        return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
    }
    // P1-02: fragment/count/message 三者互相验证——
    // fragment data 不得超 budget；seq≥1 时 message ≥ (count-1)*data + 1（末片可短），
    // 且 message ≤ count*data（padding 允许，但过小说明 wire 谎报）
    let dlen = data.len();
    if dlen == 0 || dlen > MULTIPART_PAYLOAD_MAX_LEN {
        return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
    }
    // 单片即完整：data.len() 必须 ≥ message_length（末片短于 fragment 时成立）
    // 多片：message_length ≤ count * dlen（count 片 × 每片 dlen 覆盖全部）
    if sequence_count > 1 && message_length > sequence_count * dlen {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    if sequence_count == 1 && dlen < message_length {
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
/// 审计 #5 P1-01: 会话累计保留内存预算——decoded/buffer/queue 中 Part.data
/// 总字节超过此值 = 异常会话,reset 清空(攻击者不能长期占用内存)。
/// payload 本身 ≤ 16KiB;2 倍裕量覆盖 fountain 消元中间态。
pub const MULTIPART_SESSION_RETAINED_MAX: usize = MULTIPART_PAYLOAD_MAX_LEN * 2;

pub struct UrMultipartDecoder {
    inner: FountainDecoder,
    type_name: Option<alloc::string::String>,
    /// 审计 #5: 累计保留字节数(每帧 data 长度累加)
    retained_bytes: usize,
}

impl UrMultipartDecoder {
    pub fn new() -> Self {
        Self {
            inner: FountainDecoder::new(),
            type_name: None,
            retained_bytes: 0,
        }
    }

    /// 审计 #5 P1-01: 超预算 reset——清空全部会话状态(类型记忆一并丢弃),
    /// 攻击会话不能长期占用内存。调用方需重新从头扫码。
    fn reset(&mut self) {
        self.inner = FountainDecoder::new();
        self.type_name = None;
        self.retained_bytes = 0;
    }

    /// 收一帧 URI。Ok(true)=有新信息, Ok(false)=重复/无新信息。
    /// type 一致性校验：跨 type 混帧拒绝。
    pub fn receive_frame(&mut self, uri: &str) -> Result<bool> {
        let frame = parse_frame(uri)?;
        match &self.type_name {
            None => {
                self.type_name = Some(alloc::string::String::from(frame.type_name));
            }
            Some(t) if t != frame.type_name => {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            _ => {}
        }
        let part = part_from_cbor(&frame.part_cbor)?;
        // seq 元数据一致性（fountain 内部也校验，这里提前挡，错误语义更准）
        if part.sequence_count != frame.sequence_count || part.sequence != frame.sequence {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        // 审计 #5 P1-01: 累计保留内存,超预算 reset 会话
        self.retained_bytes += part.data.len();
        if self.retained_bytes > MULTIPART_SESSION_RETAINED_MAX {
            self.reset();
            return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
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

    /// P0-C（2026-09-01）：已完成帧序列的 UR type（首帧起记录，跨 type 混帧已拒）。
    /// L3 据此路由 typed sign；None = 尚未收到任何帧。
    pub fn ur_type(&self) -> Option<&str> {
        self.type_name.as_deref()
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

    /// P0-B 回归（2026-09-01 再复审）: keystone-ur 0.1.1 上游混合冗余帧（seq > count）
    /// 必须可被本 decoder 接受——golden 向量由 keystone-ur Encoder 生成（见排坑笔记）。
    #[test]
    fn p0b_keystone_upstream_mixed_frames_accepted() {
        // keystone-ur: payload "12345678", max_fragment_len=4 → 2 fragments; seq 3/4/5 = 混合帧
        let mut dec = UrMultipartDecoder::new();
        for uri in [
            "ur:bytes/3-2/lpaxaoaycynyvttnpefyeheyeoeeclmudtrd",
            "ur:bytes/4-2/lpaaaoaycynyvttnpefyecenemetrhgynlfg",
            "ur:bytes/5-2/lpahaoaycynyvttnpefyecenemetiestfzsr",
        ] {
            dec.receive_frame(uri).unwrap();
        }
        assert!(dec.complete());
        assert_eq!(dec.payload().unwrap().as_deref(), Some(&b"12345678"[..]));
    }

    /// P0-B 验收: 丢系统帧后仅靠 seq>count 的混合帧恢复完整 payload
    #[test]
    fn p0b_loss_recovery_via_mixed_frames_only() {
        // keystone-ur: 64B payload, max_fragment_len=8 → 8 fragments; BIG9..12 = 混合帧
        // 丢 BIG3/BIG6 两个系统帧, 只喂 BIG9-12 混合帧恢复
        let all: [(&str, &str); 18] = [
            (
                "1-8",
                "ur:bytes/1-8/lpadaycsfzcyvaiowkkkfdaeatbabzcecndrehttzckeme",
            ),
            (
                "2-8",
                "ur:bytes/2-8/lpaoaycsfzcyvaiowkkkfdetfhfggtghhpidinfyvwhpwk",
            ),
            (
                "3-8",
                "ur:bytes/3-8/lpaxaycsfzcyvaiowkkkfdjoktkblplkmunyoycpvyhydy",
            ),
            (
                "4-8",
                "ur:bytes/4-8/lpaaaycsfzcyvaiowkkkfdpdperprysssbtdtarolademk",
            ),
            (
                "5-8",
                "ur:bytes/5-8/lpahaycsfzcyvaiowkkkfdvtvdwyykadaybscmrsdirljk",
            ),
            (
                "6-8",
                "ur:bytes/6-8/lpamaycsfzcyvaiowkkkfdcadkdneyesfzflglrtdwfepm",
            ),
            (
                "7-8",
                "ur:bytes/7-8/lpataycsfzcyvaiowkkkfdgohhiaimjskslblnchbyleti",
            ),
            (
                "8-8",
                "ur:bytes/8-8/lpayaycsfzcyvaiowkkkfdlgmwndoeptpfrlrnrfrycfsk",
            ),
            (
                "9-8",
                "ur:bytes/9-8/lpasaycsfzcyvaiowkkkfdskztvlbkjscsbsengtcentas",
            ),
            (
                "10-8",
                "ur:bytes/10-8/lpbkaycsfzcyvaiowkkkfdmhrlueahmetpzmswdeecuyeh",
            ),
            (
                "11-8",
                "ur:bytes/11-8/lpbdaycsfzcyvaiowkkkfdaeatbabzcecndrehsrksrhck",
            ),
            (
                "12-8",
                "ur:bytes/12-8/lpbnaycsfzcyvaiowkkkfdskwmryjlvtnblafzosahrpwt",
            ),
            (
                "13-8",
                "ur:bytes/13-8/lpbtaycsfzcyvaiowkkkfdgohhiaimjskslblnahmwgwhe",
            ),
            (
                "14-8",
                "ur:bytes/14-8/lpbaaycsfzcyvaiowkkkfdetfhfggtghhpidinhdcecpze",
            ),
            (
                "15-8",
                "ur:bytes/15-8/lpbsaycsfzcyvaiowkkkfdskztlslejzbwdrehcpsrrkot",
            ),
            (
                "16-8",
                "ur:bytes/16-8/lpbeaycsfzcyvaiowkkkfdpdpdropdtpvsyavstyhgetam",
            ),
            (
                "17-8",
                "ur:bytes/17-8/lpbyaycsfzcyvaiowkkkfdetbsenutsspyoeinehytbeem",
            ),
            (
                "18-8",
                "ur:bytes/18-8/lpbgaycsfzcyvaiowkkkfdgohpjnlbjnhpgorlmwmwdwpe",
            ),
        ];
        let mut dec = UrMultipartDecoder::new();
        // 系统帧: 1,2,4,5,7,8（丢 3、6）
        for (_, uri) in all
            .iter()
            .take(8)
            .filter(|(s, _)| !(*s == "3-8" || *s == "6-8"))
        {
            dec.receive_frame(uri).unwrap();
        }
        assert!(!dec.complete());
        // 仅混合帧 9-18（Gaussian 消元逐 X² 降未知数,帧多几个必收齐）
        for (_, uri) in all.iter().skip(8) {
            dec.receive_frame(uri).unwrap();
        }
        assert!(dec.complete());
        let msg = dec.payload().unwrap().unwrap();
        assert_eq!(msg.len(), 64);
        // 上游 payload = (0..64).map(|i| (i*7 % 251) as u8)
        for (i, b) in msg.iter().enumerate() {
            assert_eq!(*b, (i as u32 * 7 % 251) as u8, "byte {i}");
        }
    }

    /// P0-B: 自家 encoder 的第一个 fountain 冗余帧（seq=count+1）必须能进自家 decoder
    #[test]
    fn p0b_own_encoder_mixed_frame_roundtrip() {
        let payload: Vec<u8> = (0..2048).map(|i| (i * 13 % 251) as u8).collect();
        let mut enc =
            UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN).unwrap();
        let n = enc.fragment_count();
        let mut dec = UrMultipartDecoder::new();
        // 先喂 count+1 帧（含第 count+1 个冗余帧）
        for _ in 0..n + 1 {
            dec.receive_frame(&enc.next_frame().unwrap()).unwrap();
        }
        assert!(dec.complete());
        assert_eq!(dec.payload().unwrap().as_deref(), Some(payload.as_slice()));
    }

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
        let mut enc =
            UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN).unwrap();
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
        let mut cyclic =
            UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN).unwrap();
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

    /// seq/count 域校验: 0 / 超限 count / seq>count 合法(P0-B 语义)
    ///
    /// 假阳性测试重写(审计 #4 工程项 4):原测试用 `ur:bytes/3-2/aaaa` 断言
    /// seq>count 被拒——但 `aaaa` 是无效 bytewords(4 字符 < 5 字节下限),
    /// Err 实际来自 body 解码,并未证明 sequence 策略,且断言方向与
    /// P0-B 已修语义(seq>count = fountain 冗余帧,合法)相反。
    /// 现用有效 bytewords body 分别锁定:seq>count → Ok,真非法域 → Err。
    #[test]
    fn invalid_seq_domain_rejected() {
        use alloc::format;
        // 有效 body:Part CBOR [seq, count, msg_len, checksum, data]
        // (bytewords-minimal 编码,形状对齐 part_from_cbor 期望)
        use crate::encoding::bytewords;
        let part_cbor = crate::encoding::cbor::encode_array(&[
            crate::encoding::cbor::encode_uint(1),
            crate::encoding::cbor::encode_uint(2),
            crate::encoding::cbor::encode_uint(4),
            crate::encoding::cbor::encode_uint(0xdeadbeef),
            crate::encoding::cbor::encode_bytes(b"abcd"),
        ]);
        let body = bytewords::encode_minimal(&part_cbor);

        // seq > count:标准 fountain 冗余帧 → Ok(P0-B 语义;修复前假阳性测试断言相反)
        let uri_redundant = format!("ur:bytes/3-2/{}", body);
        let frame = parse_frame(&uri_redundant)
            .expect("seq>count with valid body must parse (fountain redundant frame)");
        assert_eq!(frame.sequence, 3);
        assert_eq!(frame.sequence_count, 2);

        // seq=0 → Err(真非法域)
        assert!(parse_frame(&format!("ur:bytes/0-2/{}", body)).is_err());
        // count 超限(> MAX_SEQUENCE_COUNT=256)→ Err
        assert!(parse_frame(&format!("ur:bytes/1-999/{}", body)).is_err());
        // 无效 bytewords body(原测试的真实失败原因)→ Err,但这是 body 错而非 seq 错
        assert!(parse_frame("ur:bytes/3-2/aaaa").is_err());
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
