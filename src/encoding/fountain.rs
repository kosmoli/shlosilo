//! BC-UR fountain encoding (R3 route A revised, finalized 2026-08-31)
//!
//! **Support-scope statement (Audit #6 re-review P2-03)**: this module is a `pub(crate)` internal API —
//! the only committed entry point outside the crate is [`crate::ur::ur_multipart::UrMultipartDecoder`],
//! whose sequence/frame/retained triple budget forms a provable total work bound.
//! This module's direct API is not a stable support surface; behavior may change with internal implementation.
//!
//! Spec alignment: BCR-2020-06 / keystone-ur 0.1.1 behavior (the baseline implementation for three-way oracle verification).
//!
//! L1 criterion = purity: the xoshiro RNG is deterministic pseudorandomness (the seed comes entirely from (sequence, checksum),
//! no external entropy source); encoding/decoding has no I/O, no global state, no side effects — functional core.
//!
//! Components (all aligned with keystone-ur semantics):
//! - [`Xoshiro256**`]: seed = SHA256(seed_bytes), bit-identical to rand_xoshiro 0.6
//! - `Weighted`: degree sampling via Vose's alias method (weight 1/i)
//! - [`Part`]: fountain fragment; wire shape = CBOR array(5) [seq, seqCount, msgLen, crc32, data]
//! - [`FountainEncoder`]: fragmentation + next_part / next_cyclic_part
//! - [`FountainDecoder`]: set-cover reassembly over received/decoded/buffer (greedy Gaussian elimination)
//!
//! Budget discipline (same origin as X1): decoder-side received/buffer entry counts are bounded by the `sequence_count` cap.

extern crate alloc;

use crate::encoding::sha256;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

// ─── Xoshiro256** ───────────────────────────────────────────────────

/// Implementation bit-identical to rand_xoshiro 0.6 `Xoshiro256StarStar`.
#[derive(Clone)]
pub(crate) struct Xoshiro256 {
    s: [u64; 4],
}

impl Xoshiro256 {
    /// keystone-ur semantics: the seed is first hashed with SHA256, then read as 4×u64 in BE.
    /// (keystone-ur uses bitcoin_hashes::sha256; shlosilo uses its own L1 sha256 — same algorithm)
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
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
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

    /// keystone-ur uses the f64 path (next_double); kept identical here for bit-exact oracle alignment.
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

    /// Degree sampling: weight 1/i (i = 1..=count), Vose's alias method, returns 1..=count
    fn choose_degree(&mut self, count: usize) -> usize {
        let weights: Vec<f64> = (1..=count).map(|x| 1.0 / x as f64).collect();
        let mut sampler = Weighted::new(&weights);
        sampler.next(self) + 1
    }
}

// ─── Weighted alias sampler ────────────────────────────────────────

/// Vose's alias method (aligned with keystone-ur sampler.rs, including the f64 path).
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
        // keystone-ur order: j from 1..=count, count-j; partition predicate w[j] < 1.0 → small
        // Equivalent implementation: for j in (0..count).rev() — keeps the same fill order as upstream
        for j in (0..count).rev() {
            if w[j] < 1.0 {
                small.push(j);
            } else {
                large.push(j);
            }
        }
        // Upstream: (1..=count).map(|j| count - j) = [count-1, count-2, .., 0] reversed;
        // after partition s/l keep that reversed order. The for j in (0..count).rev() above produces the same order.

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

/// Fountain fragment. Wire shape (aligned with keystone-ur Part::to_cbor):
/// CBOR array(5) = [sequence, sequence_count, message_length, checksum, data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Part {
    pub sequence: usize,
    pub sequence_count: usize,
    pub message_length: usize,
    pub checksum: u32,
    pub data: Vec<u8>,
}

impl Part {
    /// CBOR encoding (uses shlosilo's own cbor.rs; shape byte-identical to minicbor:
    /// 82: array(5); the four uints use the shortest arg encoding for their u32 range; data is a byte string)
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

    /// Fragment covered indexes (keystone-ur Part::indexes semantics)
    pub fn indexes(&self) -> Vec<usize> {
        choose_fragments(self.sequence, self.sequence_count, self.checksum)
    }

    pub fn is_simple(&self) -> bool {
        self.indexes().len() == 1
    }

    /// "seq-count" string (URI segment)
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

/// keystone-ur choose_fragments: when seq ≤ count, output the single original part;
/// otherwise seed = [seq BE u32][checksum BE u32] → SHA256 → xoshiro sampling.
pub(crate) fn choose_fragments(
    sequence: usize,
    fragment_count: usize,
    checksum: u32,
) -> Vec<usize> {
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

/// Fountain encoder (no side effects: all state is closed over self, output is a value)
pub(crate) struct FountainEncoder {
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

    /// XMR cyclic mode (aligned with keystone: after seq reaches count it loops back to 1, so software wallets can catch up)
    pub fn next_cyclic_part(&mut self) -> Part {
        if self.current_sequence == self.parts.len() {
            self.current_sequence = 1;
        } else {
            self.current_sequence += 1;
        }
        self.make_part(self.current_sequence)
    }
}

/// Fountain-layer errors (L1 panics never; error-code path)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FountainError {
    EmptyMessage,
    EmptyPart,
    InvalidFragmentLen,
    InconsistentPart,
    InvalidPadding,
    ExpectedItem,
    /// Budget exceeded (added in R3 remediation — keystone-ur has no such cap; a shlosilo discipline tightening)
    BudgetExceeded,
}

// ─── Decoder ───────────────────────────────────────────────────────

/// Fountain decoder: set-cover greedy reassembly (aligned with keystone-ur Decoder semantics)
#[derive(Default)]
pub(crate) struct FountainDecoder {
    received: BTreeSet<Vec<usize>>,
    decoded: BTreeMap<usize, Part>,
    buffer: BTreeMap<Vec<usize>, Part>,
    queue: VecDeque<(usize, Part)>,
    sequence_count: usize,
    message_length: usize,
    checksum: u32,
    fragment_length: usize,
    processed_parts_count: usize,
    /// Audit #5 open-02: cumulative XOR work (bytes)
    work_used: usize,
}

/// Decoder-side budget (same discipline origin as X1): cap = fragment count cap.
/// TxTemplate 16 KiB / minimum frame 200B → at most ~82 fragments; 256 leaves ample margin.
pub(crate) const MAX_SEQUENCE_COUNT: usize = 256;

/// Gate4 #4 (re-reviewed 2026-09-01): total received-frame budget per session.
/// BC-UR allows unlimited redundant frames, but decoder resources must be finite: received (buffer/queue share the same origin)
/// are all gated on the received set; sessions beyond this cap are treated as abnormal/attacks and fail with a stable error.
pub(crate) const MAX_TOTAL_FRAMES: usize = 4096;

/// Audit #5 P1-01 (open-02): elimination work budget — cumulative XOR byte cap.
/// Normal reassembly work is O(count × fragment) ≈ 256 × 200B = 51KB;
/// the 16MiB cap ≈ 300× normal work; a malicious XOR amplification attack (mass mixed
/// equations, repeated elimination) hits this wall before exhausting CPU.
pub(crate) const MAX_XOR_WORK_BYTES: usize = 16 * 1024 * 1024;

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
        let percent = self.processed_parts_count as f32 / (self.sequence_count as f32 * 1.75);
        let pct = (percent * 100.0) as usize;
        pct.min(99) as u8
    }

    /// Receive a fragment. Ok(true) = accepted new information; Ok(false) = duplicate/no new information.
    pub fn receive(&mut self, part: Part) -> Result<bool, FountainError> {
        if self.complete() {
            return Ok(false);
        }
        if part.sequence_count == 0 || part.data.is_empty() || part.message_length == 0 {
            return Err(FountainError::EmptyPart);
        }
        // X1 same-origin budget: sequence_count cap (prevents wire-controlled overrun from exhausting resources)
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
        // Gate4 #4: session frame budget — duplicates don't count (idempotent), new frames do
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
                let mut part = self
                    .buffer
                    .remove(&indexes)
                    .ok_or(FountainError::ExpectedItem)?;
                let mut new_indexes = indexes.clone();
                let to_remove = indexes
                    .iter()
                    .position(|&x| x == index)
                    .ok_or(FountainError::ExpectedItem)?;
                new_indexes.remove(to_remove);
                self.work_used += part.data.len();
                if self.work_used > MAX_XOR_WORK_BYTES {
                    return Err(FountainError::BudgetExceeded);
                }
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
            let decoded_part = self
                .decoded
                .get(&remove)
                .ok_or(FountainError::ExpectedItem)?;
            self.work_used += part.data.len();
            if self.work_used > MAX_XOR_WORK_BYTES {
                return Err(FountainError::BudgetExceeded);
            }
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

    /// Returns the reassembled message on completion (validates padding zero bytes + message_length truncation)
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

// sequence_id impl on Part (alloc::format — the lib already accepts alloc, consistent with cbor/unsigned_txset)

// --- oracle tests: keystone-ur official vectors + roundtrip ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// keystone-ur fountain.rs doctest vector 1:
    /// "Ten chars!" / max_len=4 → p1="Ten " p2="char" p3="s!\0\0"
    /// The first two frames are original parts; drop p3; frame 4 is still p3 (RNG picks a single segment);
    /// frame 5 = p1^p2^p3 (RNG picks 3 segments)
    #[test]
    fn keystone_doctest_ten_chars() {
        let data = b"Ten chars!";
        let mut enc = FountainEncoder::new(data, 4).unwrap();
        let p1 = enc.next_part();
        assert_eq!(p1.data, b"Ten ");
        let p2 = enc.next_part();
        assert_eq!(p2.data, b"char");
        // Drop p3
        let _p3 = enc.next_part();
        // The first frame after the RNG takes over is still p3
        let p3_again = enc.next_part();
        assert_eq!(p3_again.data, b"s!\0\0");
        // The next frame = p1 ^ p2 ^ p3
        let mixed = enc.next_part();
        let xor3 = {
            let mut x = p1.data.clone();
            xor_into(&mut x, &p2.data);
            xor_into(&mut x, &p3_again.data);
            x
        };
        assert_eq!(mixed.data, xor3);

        // decoder: receive p1, p2, drop p3, receive p3_again → already complete (mixed is a redundant frame)
        let mut dec = FountainDecoder::new();
        assert!(dec.receive(p1).unwrap());
        assert!(dec.receive(p2).unwrap());
        assert!(dec.receive(p3_again).unwrap());
        assert!(dec.complete());
        assert_eq!(dec.message().unwrap().as_deref(), Some(&data[..]));
        // Receiving a mixed frame after completion → Ok(false) (no crash, no duplicate processing)
        assert!(!dec.receive(mixed).unwrap());
    }

    /// keystone-ur sampler doctest vector: weights [1,2,4,8], seed "Wolf"
    /// The first 31 sampled values of the expected sequence
    #[test]
    fn keystone_sampler_wolf_vector() {
        let weights = vec![1.0, 2.0, 4.0, 8.0];
        let mut xoshiro = Xoshiro256::from_seed_bytes(b"Wolf");
        let mut sampler = Weighted::new(&weights);

        let expected = [
            3, 3, 3, 3, 3, 3, 3, 0, 2, 3, 3, 3, 3, 1, 2, 2, 1, 3, 3, 2, 3, 3, 1, 1, 2, 1, 1, 3, 1,
        ];
        for (i, &e) in expected.iter().enumerate() {
            assert_eq!(sampler.next(&mut xoshiro), e, "sample #{} mismatch", i);
        }
    }

    /// keystone-ur fragment_length doctest vector
    #[test]
    fn keystone_fragment_length_vector() {
        assert_eq!(fragment_length(12345, 1955), 1764);
        assert_eq!(fragment_length(12345, 30000), 12345);
    }

    /// keystone-ur bytewords statistics doctest:
    /// "Fifty chars"×5 = 55 bytes, max_len=5 → 11 fragments; over 100 frames the original-part ratio ≈ 39/100,
    /// average index count per frame ≈ 3.33
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

    /// roundtrip: a real XMR unsigned payload shape (2 KiB) + 200B fragments → full reassembly
    #[test]
    fn roundtrip_2k_payload_200b_fragments() {
        let payload: Vec<u8> = (0..2048).map(|i| (i * 7 % 251) as u8).collect();
        let mut enc = FountainEncoder::new(&payload, 200).unwrap();
        let mut dec = FountainDecoder::new();
        // Receive only 60% of the frames (simulating loss) — fountain redundancy should still reassemble
        let mut dropped = 0;
        for i in 0.. {
            if dec.complete() {
                break;
            }
            let p = enc.next_part();
            let keep = i % 5 != 0; // drop 20% of frames
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

    /// budget: sequence_count over cap is rejected
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

    /// Part CBOR shape vs keystone-ur minicbor: array(5) + 4 uint + bytes
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
    /// Audit #6 re-review P2-03 method 1: behavioral test of the fountain-layer XOR work budget.
    /// This module has been narrowed to pub(crate) (not a stable support surface); this test is crate-internal verification.
    /// Construction keys: keep 2 undecoded idx (62,63); the mixed part must contain 62 and not 63,
    /// the session never completes; each elimination removes = degree-1 decoded copies,
    /// and work_used accumulates until 16MiB triggers BudgetExceeded.
    #[test]
    fn xor_work_budget_enforced() {
        let frag = 1024 * 1024;
        let count = 64;
        let message = vec![0xABu8; frag * count];
        let mut enc = FountainEncoder::new(&message, frag).unwrap();
        let mut dec = FountainDecoder::new();
        // receive 62 simple parts (idx 0..=61 decoded; 62,63 undecoded)
        for _ in 0..count - 2 {
            dec.receive(enc.next_part()).unwrap();
        }
        assert_eq!(dec.decoded.len(), count - 2);
        let mut hit = false;
        let mut frames = 0usize;
        for seq in count + 1..=MAX_SEQUENCE_COUNT {
            let part = enc.make_part(seq);
            let idxs = part.indexes();
            if idxs.len() < 3 || !idxs.contains(&(count - 2)) || idxs.contains(&(count - 1)) {
                continue;
            }
            match dec.receive(part) {
                Err(FountainError::BudgetExceeded) => {
                    hit = true;
                    break;
                }
                Ok(_) => frames += 1,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
            assert!(
                dec.work_used <= MAX_XOR_WORK_BYTES,
                "work_used={} exceeded without BudgetExceeded",
                dec.work_used
            );
        }
        assert!(
            hit,
            "XOR work budget must trigger (frames={frames}, work_used={})",
            dec.work_used
        );
    }
}
