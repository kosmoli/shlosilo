//! BC-UR fountain 编码（R3 路线 A 修正版，2026-08-31 定稿）
//!
//! 对齐规范：BCR-2020-06 / keystone-ur 0.1.1 行为（oracle 三方验证的基准实现）。
//!
//! L1 判据 = 纯函数性：xoshiro RNG 是确定性伪随机（seed 全部来自 (sequence, checksum)，
//! 无外部熵源），编码/解码无 I/O、无全局状态、无副作用——归 functional core。
//!
//! 组件（全部对齐 keystone-ur 语义）：
//! - [`Xoshiro256**`]：seed = SHA256(seed_bytes)，算法与 rand_xoshiro 0.6 逐位一致
//! - `Weighted`：Vose 别名法 degree 采样（权重 1/i）
//! - [`Part`]：fountain 分片，wire 形状 = CBOR array(5) [seq, seqCount, msgLen, crc32, data]
//! - [`FountainEncoder`]：分片 + next_part / next_cyclic_part
//! - [`FountainDecoder`]：received/decoded/buffer 集合覆盖重组（Gaussian elimination 贪心）
//!
//! budget 纪律（X1 同源）：decoder 侧 received/buffer 条目数受 `sequence_count` 上限约束。

extern crate alloc;

use crate::encoding::sha256;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

// ─── Xoshiro256** ───────────────────────────────────────────────────

/// 与 rand_xoshiro 0.6 `Xoshiro256StarStar` 逐位一致的实现。
#[derive(Clone)]
pub(crate) struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// keystone-ur 语义：seed 先过 SHA256 再按 BE 读入 4×u64。
    /// （keystone-ur 用 bitcoin_hashes::sha256；shlosilo 用自家 L1 sha256，同算法）
    pub(crate) fn from_seed_bytes(seed: &[u8]) -> Self {
        let h = sha256::hash(seed).expect("sha256 of fixed input cannot fail");
        let mut s = [0u64; 4];
        for (i, word) in s.iter_mut().enumerate() {
            let b = &h[i * 8..(i + 1) * 8];
            *word = u64::from_be_bytes(b.try_into().expect("8 bytes"));
        }
        Self { s }
    }

    #[inline]
    fn next_u64(&mut self) -> u64 {
        // result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9)
        let result = self.s[1]
            .wrapping_mul(5)
            .rotate_left(7)
            .wrapping_mul(9);
        // xoshiro256 core step
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// keystone-ur 用 f64 路径（next_double），此处保持一致以保证逐位 oracle 对齐。
    fn next_double(&mut self) -> f64 {
        self.next_u64() as f64 / (u64::MAX as f64 + 1.0)
    }

    fn next_int(&mut self, low: u64, high: u64) -> u64 {
        (self.next_double() * ((high - low + 1) as f64)) as u64 + low
    }

    fn shuffled(&mut self, items: Vec<usize>) -> Vec<usize> {
        let mut items = items;
        let mut out = Vec::with_capacity(items.len());
        while !items.is_empty() {
            let index = self.next_int(0, (items.len() - 1) as u64) as usize;
            out.push(items.remove(index));
        }
        out
    }

    /// degree 采样：权重 1/i（i = 1..=count），Vose 别名法，返回 1..=count
    fn choose_degree(&mut self, count: usize) -> usize {
        let weights: Vec<f64> = (1..=count).map(|x| 1.0 / x as f64).collect();
        let mut sampler = Weighted::new(&weights);
        sampler.next(self) + 1
    }
}

// ─── Weighted alias sampler ────────────────────────────────────────

/// Vose 别名法（对齐 keystone-ur sampler.rs，含 f64 路径）。
struct Weighted {
    aliases: Vec<usize>,
    probs: Vec<f64>,
}

impl Weighted {
    fn new(weights: &[f64]) -> Self {
        debug_assert!(!weights.is_empty());
        let count = weights.len();
        let summed: f64 = weights.iter().sum();
        debug_assert!(summed > 0.0);
        let mut w = weights.to_vec();
        for x in &mut w {
            *x *= count as f64 / summed;
        }

        // partition: small/large
        let mut small: Vec<usize> = Vec::new();
        let mut large: Vec<usize> = Vec::new();
        // keystone-ur 顺序：j 从 1..=count，count-j；partition 谓词 w[j] < 1.0 → small
        // 等价实现：for j in (0..count).rev() — 保持与上游一致的填充顺序
        for j in (0..count).rev() {
            if w[j] < 1.0 {
                small.push(j);
            } else {
                large.push(j);
            }
        }
        // 上游: (1..=count).map(|j| count - j) = [count-1, count-2, .., 0] 逆序，
        // partition 后 s/l 各自保持该逆序。上面 for j in (0..count).rev() 产生相同顺序。

        let mut probs = alloc::vec![0.0; count];
        let mut aliases = alloc::vec![0usize; count];

        while !small.is_empty() && !large.is_empty() {
            let a = small.remove(small.len() - 1);
            let g = large.remove(large.len() - 1);
            probs[a] = w[a];
            aliases[a] = g;
            w[g] += w[a] - 1.0;
            if w[g] < 1.0 {
                small.push(g);
            } else {
                large.push(g);
            }
        }
        for g in large.drain(..) {
            probs[g] = 1.0;
        }
        for a in small.drain(..) {
            probs[a] = 1.0;
        }

        Self { aliases, probs }
    }

    fn next(&mut self, rng: &mut Xoshiro256) -> usize {
        let r1 = rng.next_double();
        let r2 = rng.next_double();
        let n = self.probs.len();
        let i = (n as f64 * r1) as usize;
        if r2 < self.probs[i] {
            i
        } else {
            self.aliases[i]
        }
    }
}

// ─── Part ──────────────────────────────────────────────────────────

/// fountain 分片。wire 形状（对齐 keystone-ur Part::to_cbor）：
/// CBOR array(5) = [sequence, sequence_count, message_length, checksum, data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub sequence: usize,
    pub sequence_count: usize,
    pub message_length: usize,
    pub checksum: u32,
    pub data: Vec<u8>,
}

impl Part {
    /// CBOR 编码（用 shlosilo 自家 cbor.rs，形状与 minicbor 逐字节一致：
    /// 82: array(5)；四个 uint 按 u32 范围选取最短 arg 编码；data 为 byte string）
    pub fn to_cbor(&self) -> Vec<u8> {
        use crate::encoding::cbor as c;
        let mut out = Vec::new();
        out.push(0x80 | 5); // array(5) definite
        out.extend_from_slice(&c::encode_uint(self.sequence as u64));
        out.extend_from_slice(&c::encode_uint(self.sequence_count as u64));
        out.extend_from_slice(&c::encode_uint(self.message_length as u64));
        out.extend_from_slice(&c::encode_uint(self.checksum as u64));
        out.extend_from_slice(&c::encode_bytes(&self.data));
        out
    }

    /// 分片覆盖索引（keystone-ur Part::indexes 语义）
    pub fn indexes(&self) -> Vec<usize> {
        choose_fragments(self.sequence, self.sequence_count, self.checksum)
    }

    pub fn is_simple(&self) -> bool {
        self.indexes().len() == 1
    }

    /// "seq-count" 字符串（URI 段）
    pub fn sequence_id(&self) -> alloc::string::String {
        alloc::format!("{}-{}", self.sequence, self.sequence_count)
    }
}

fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// keystone-ur choose_fragments：seq ≤ count 时输出单段原片；
/// 否则 seed = [seq BE u32][checksum BE u32] → SHA256 → xoshiro 采样。
pub(crate) fn choose_fragments(sequence: usize, fragment_count: usize, checksum: u32) -> Vec<usize> {
    if sequence <= fragment_count {
        return alloc::vec![sequence - 1];
    }
    let mut seed = [0u8; 8];
    seed[0..4].copy_from_slice(&(sequence as u32).to_be_bytes());
    seed[4..8].copy_from_slice(&checksum.to_be_bytes());
    let mut xoshiro = Xoshiro256::from_seed_bytes(&seed);
    let degree = xoshiro.choose_degree(fragment_count);
    let mut shuffled = xoshiro.shuffled((0..fragment_count).collect());
    shuffled.truncate(degree);
    shuffled
}

// ─── Encoder ───────────────────────────────────────────────────────

#[allow(clippy::manual_div_ceil)]
fn div_ceil(a: usize, b: usize) -> usize {
    (a + b - 1) / b
}

fn fragment_length(data_length: usize, max_fragment_length: usize) -> usize {
    let fragment_count = div_ceil(data_length, max_fragment_length);
    div_ceil(data_length, fragment_count)
}

fn partition(data: &[u8], fragment_length: usize) -> Vec<Vec<u8>> {
    let pad = (fragment_length - (data.len() % fragment_length)) % fragment_length;
    let mut padded = Vec::with_capacity(data.len() + pad);
    padded.extend_from_slice(data);
    padded.resize(padded.len() + pad, 0u8);
    padded.chunks(fragment_length).map(<[u8]>::to_vec).collect()
}

/// fountain 编码器（无副作用：全部状态封闭于 self，输出即值）
pub struct FountainEncoder {
    parts: Vec<Vec<u8>>,
    message_length: usize,
    checksum: u32,
    current_sequence: usize,
}

impl FountainEncoder {
    pub fn new(message: &[u8], max_fragment_length: usize) -> Result<Self, FountainError> {
        if message.is_empty() {
            return Err(FountainError::EmptyMessage);
        }
        if max_fragment_length == 0 {
            return Err(FountainError::InvalidFragmentLen);
        }
        let fl = fragment_length(message.len(), max_fragment_length);
        Ok(Self {
            parts: partition(message, fl),
            message_length: message.len(),
            checksum: crate::encoding::bytewords::crc32(message),
            current_sequence: 0,
        })
    }

    pub fn fragment_count(&self) -> usize {
        self.parts.len()
    }

    pub fn current_sequence(&self) -> usize {
        self.current_sequence
    }

    pub fn checksum(&self) -> u32 {
        self.checksum
    }

    fn make_part(&self, sequence: usize) -> Part {
        let indexes = choose_fragments(sequence, self.parts.len(), self.checksum);
        let mut mixed = alloc::vec![0u8; self.parts[0].len()];
        for item in indexes {
            xor_into(&mut mixed, &self.parts[item]);
        }
        Part {
            sequence,
            sequence_count: self.parts.len(),
            message_length: self.message_length,
            checksum: self.checksum,
            data: mixed,
        }
    }

    pub fn next_part(&mut self) -> Part {
        self.current_sequence += 1;
        self.make_part(self.current_sequence)
    }

    /// XMR cyclic 模式（对齐 keystone：seq 走到 count 后回 1 循环，供软件钱包补扫）
    pub fn next_cyclic_part(&mut self) -> Part {
        if self.current_sequence == self.parts.len() {
            self.current_sequence = 1;
        } else {
            self.current_sequence += 1;
        }
        self.make_part(self.current_sequence)
    }
}

/// fountain 层错误（L1 无 panic；错误码路径）
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FountainError {
    EmptyMessage,
    EmptyPart,
    InvalidFragmentLen,
    InconsistentPart,
    InvalidPadding,
    ExpectedItem,
    /// budget 超限（R3 整改新增——keystone-ur 无此上限，属 shlosilo 纪律加严）
    BudgetExceeded,
}

// ─── Decoder ───────────────────────────────────────────────────────

/// fountain 解码器：集合覆盖贪心重组（对齐 keystone-ur Decoder 语义）
#[derive(Default)]
pub struct FountainDecoder {
    received: BTreeSet<Vec<usize>>,
    decoded: BTreeMap<usize, Part>,
    buffer: BTreeMap<Vec<usize>, Part>,
    queue: VecDeque<(usize, Part)>,
    sequence_count: usize,
    message_length: usize,
    checksum: u32,
    fragment_length: usize,
    processed_parts_count: usize,
}

/// decoder 侧 budget（X1 纪律同源）：上限=分片数上限。
/// TxTemplate 16 KiB / 最小帧 200B → 最多 ~82 分片；256 给足裕量。
pub const MAX_SEQUENCE_COUNT: usize = 256;

/// Gate4 #4（2026-09-01 再复审）：单 session 总接收帧数预算。
/// BC-UR 允许无限冗余帧，但 decoder 资源必须有限：received(buffer/queue 同源)
/// 都以 received 集合为闸，超过此上限的会话视为异常/攻击，稳定报错。
pub const MAX_TOTAL_FRAMES: usize = 4096;

impl FountainDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn complete(&self) -> bool {
        self.message_length != 0 && self.decoded.len() == self.sequence_count
    }

    pub fn progress(&self) -> u8 {
        if self.processed_parts_count == 0 {
            return 0;
        }
        let percent =
            self.processed_parts_count as f32 / (self.sequence_count as f32 * 1.75);
        let pct = (percent * 100.0) as usize;
        pct.min(99) as u8
    }

    /// 收片。Ok(true) = 接受了新信息，Ok(false) = 重复/无新信息。
    pub fn receive(&mut self, part: Part) -> Result<bool, FountainError> {
        if self.complete() {
            return Ok(false);
        }
        if part.sequence_count == 0 || part.data.is_empty() || part.message_length == 0 {
            return Err(FountainError::EmptyPart);
        }
        // X1 同源 budget：sequence_count 上限（防 wire 可控超限造成资源失控）
        if part.sequence_count > MAX_SEQUENCE_COUNT {
            return Err(FountainError::BudgetExceeded);
        }

        if self.received.is_empty() {
            self.sequence_count = part.sequence_count;
            self.message_length = part.message_length;
            self.checksum = part.checksum;
            self.fragment_length = part.data.len();
        } else if !self.validate(&part) {
            return Err(FountainError::InconsistentPart);
        }

        let indexes = part.indexes();
        if self.received.contains(&indexes) {
            return Ok(false);
        }
        // Gate4 #4: session frame budget——重复帧不计（幂等），新帧计入
        if self.received.len() >= MAX_TOTAL_FRAMES {
            return Err(FountainError::BudgetExceeded);
        }
        self.received.insert(indexes);

        if part.is_simple() {
            self.process_simple(part)?;
        } else {
            self.process_complex(part)?;
        }
        self.processed_parts_count += 1;
        Ok(true)
    }

    pub fn validate(&self, part: &Part) -> bool {
        !self.received.is_empty()
            && part.sequence_count == self.sequence_count
            && part.message_length == self.message_length
            && part.checksum == self.checksum
            && part.data.len() == self.fragment_length
    }

    fn process_simple(&mut self, part: Part) -> Result<(), FountainError> {
        let index = *part.indexes().first().ok_or(FountainError::ExpectedItem)?;
        self.decoded.insert(index, part.clone());
        self.queue.push_back((index, part));
        self.process_queue()?;
        Ok(())
    }

    fn process_queue(&mut self) -> Result<(), FountainError> {
        while let Some((index, simple)) = self.queue.pop_front() {
            let to_process: Vec<Vec<usize>> = self
                .buffer
                .keys()
                .filter(|idxs| idxs.contains(&index))
                .cloned()
                .collect();
            for indexes in to_process {
                let mut part = self.buffer.remove(&indexes).ok_or(FountainError::ExpectedItem)?;
                let mut new_indexes = indexes.clone();
                let to_remove = indexes
                    .iter()
                    .position(|&x| x == index)
                    .ok_or(FountainError::ExpectedItem)?;
                new_indexes.remove(to_remove);
                xor_into(&mut part.data, &simple.data);
                if new_indexes.len() == 1 {
                    let only = *new_indexes.first().ok_or(FountainError::ExpectedItem)?;
                    self.decoded.insert(only, part.clone());
                    self.queue.push_back((only, part));
                } else {
                    self.buffer.insert(new_indexes, part);
                }
            }
        }
        Ok(())
    }

    fn process_complex(&mut self, mut part: Part) -> Result<(), FountainError> {
        let mut indexes = part.indexes();
        let to_remove: Vec<usize> = indexes
            .iter()
            .copied()
            .filter(|idx| self.decoded.contains_key(idx))
            .collect();
        if indexes.len() == to_remove.len() {
            return Ok(());
        }
        for remove in to_remove {
            let pos = indexes
                .iter()
                .position(|&x| x == remove)
                .ok_or(FountainError::ExpectedItem)?;
            indexes.remove(pos);
            let decoded_part = self.decoded.get(&remove).ok_or(FountainError::ExpectedItem)?;
            xor_into(&mut part.data, &decoded_part.data);
        }
        if indexes.len() == 1 {
            let only = *indexes.first().ok_or(FountainError::ExpectedItem)?;
            self.decoded.insert(only, part.clone());
            self.queue.push_back((only, part));
        } else {
            self.buffer.insert(indexes, part);
        }
        Ok(())
    }

    /// 完成时返回重组消息（校验 padding 零字节 + message_length 截断）
    pub fn message(&self) -> Result<Option<Vec<u8>>, FountainError> {
        if !self.complete() {
            return Ok(None);
        }
        let mut combined = Vec::with_capacity(self.fragment_length * self.sequence_count);
        for idx in 0..self.sequence_count {
            let part = self.decoded.get(&idx).ok_or(FountainError::ExpectedItem)?;
            combined.extend_from_slice(&part.data);
        }
        let pad = &combined
            .get(self.message_length..)
            .ok_or(FountainError::ExpectedItem)?;
        if pad.iter().any(|&x| x != 0) {
            return Err(FountainError::InvalidPadding);
        }
        Ok(Some(
            combined
                .get(..self.message_length)
                .ok_or(FountainError::ExpectedItem)?
                .to_vec(),
        ))
    }
}

// sequence_id 在 Part 上的实现（alloc::format——lib 内已接受 alloc，与 cbor/unsigned_txset 一致）

// ─── oracle 测试：keystone-ur 官方向量 + roundtrip ─────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// keystone-ur fountain.rs doctest 向量 1：
    /// "Ten chars!" / max_len=4 → p1="Ten " p2="char" p3="s!\0\0"
    /// 首两帧是原片；丢 p3；第 4 帧仍是 p3（RNG 选中单段）；
    /// 第 5 帧 = p1^p2^p3（RNG 选 3 段）
    #[test]
    fn keystone_doctest_ten_chars() {
        let data = b"Ten chars!";
        let mut enc = FountainEncoder::new(data, 4).unwrap();
        let p1 = enc.next_part();
        assert_eq!(p1.data, b"Ten ");
        let p2 = enc.next_part();
        assert_eq!(p2.data, b"char");
        // 丢掉 p3
        let _p3 = enc.next_part();
        // RNG 接管后第一帧仍是 p3
        let p3_again = enc.next_part();
        assert_eq!(p3_again.data, b"s!\0\0");
        // 下一帧 = p1 ^ p2 ^ p3
        let mixed = enc.next_part();
        let xor3 = {
            let mut x = p1.data.clone();
            xor_into(&mut x, &p2.data);
            xor_into(&mut x, &p3_again.data);
            x
        };
        assert_eq!(mixed.data, xor3);

        // decoder: 收 p1, p2, 丢 p3, 收 p3_again → 已完整（mixed 是冗余帧）
        let mut dec = FountainDecoder::new();
        assert!(dec.receive(p1).unwrap());
        assert!(dec.receive(p2).unwrap());
        assert!(dec.receive(p3_again).unwrap());
        assert!(dec.complete());
        assert_eq!(dec.message().unwrap().as_deref(), Some(&data[..]));
        // 完成后收到 mixed 帧 → Ok(false)（不崩不重复处理）
        assert!(!dec.receive(mixed).unwrap());
    }

    /// keystone-ur sampler doctest 向量：weights [1,2,4,8], seed "Wolf"
    /// 期望序列前 31 个采样值
    #[test]
    fn keystone_sampler_wolf_vector() {
        let weights = vec![1.0, 2.0, 4.0, 8.0];
        let mut xoshiro = Xoshiro256::from_seed_bytes(b"Wolf");
        let mut sampler = Weighted::new(&weights);

        let expected = [
            3, 3, 3, 3, 3, 3, 3, 0, 2, 3, 3, 3, 3, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1, 1, 2, 1, 1, 3, 1,
        ];
        for (i, &e) in expected.iter().enumerate() {
            assert_eq!(
                sampler.next(&mut xoshiro),
                e,
                "sample #{} mismatch",
                i
            );
        }
    }

    /// keystone-ur fragment_length doctest 向量
    #[test]
    fn keystone_fragment_length_vector() {
        assert_eq!(fragment_length(12345, 1955), 1764);
        assert_eq!(fragment_length(12345, 30000), 12345);
    }

    /// keystone-ur bytewords 统计 doctest：
    /// "Fifty chars"×5 = 55 字节, max_len=5 → 11 分片；100 帧中原片占比 ≈ 39/100，
    /// 平均每帧 index 数 ≈ 3.33
    #[test]
    fn keystone_fifty_chars_statistics() {
        let data = b"Fifty chars".repeat(5);
        let mut enc = FountainEncoder::new(&data, 5).unwrap();
        assert_eq!(enc.fragment_count(), 11);
        let mut simple_count = 0usize;
        let mut idx_sum = 0usize;
        for _ in 0..100 {
            let p = enc.next_part();
            if p.is_simple() {
                simple_count += 1;
            }
            idx_sum += p.indexes().len();
        }
        assert_eq!(simple_count, 39, "simple part ratio drift");
        assert_eq!(idx_sum, 333, "average degree drift");
    }

    /// roundtrip: 真实 XMR unsigned payload 形状 (2 KiB) + 分片 200B → 完整重组
    #[test]
    fn roundtrip_2k_payload_200b_fragments() {
        let payload: Vec<u8> = (0..2048).map(|i| (i * 7 % 251) as u8).collect();
        let mut enc = FountainEncoder::new(&payload, 200).unwrap();
        let mut dec = FountainDecoder::new();
        // 只收 60% 的帧（模拟丢帧）——fountain 冗余应仍能重组
        let mut dropped = 0;
        for i in 0.. {
            if dec.complete() {
                break;
            }
            let p = enc.next_part();
            let keep = i % 5 != 0; // 丢 20% 帧
            if keep {
                dec.receive(p).unwrap();
            } else {
                dropped += 1;
            }
            assert!(i < 500, "should complete well before 500 frames");
        }
        let _ = dropped;
        assert_eq!(dec.message().unwrap().as_deref(), Some(&payload[..]));
    }

    /// budget: sequence_count 超限拒绝
    #[test]
    fn oversized_sequence_count_rejected() {
        let mut dec = FountainDecoder::new();
        let part = Part {
            sequence: 1,
            sequence_count: MAX_SEQUENCE_COUNT + 1,
            message_length: 16,
            checksum: 0xdeadbeef,
            data: alloc::vec![0u8; 16],
        };
        assert_eq!(dec.receive(part), Err(FountainError::BudgetExceeded));
    }

    /// Part CBOR 形状 vs keystone-ur minicbor：array(5) + 4 uint + bytes
    #[test]
    fn part_cbor_shape() {
        let part = Part {
            sequence: 1,
            sequence_count: 3,
            message_length: 10,
            checksum: 0x01020304,
            data: alloc::vec![0xab_u8; 4],
        };
        let cbor = part.to_cbor();
        // 82 array(5), 01 uint1, 03 uint3, 0a uint10, 1a01020304 uint32bit, 44abcd... bytes(4)
        assert_eq!(
            cbor,
            vec![
                0x85, 0x01, 0x03, 0x0a, 0x1a, 0x01, 0x02, 0x03, 0x04, 0x44, 0xab, 0xab, 0xab, 0xab
            ]
        );
    }
}
