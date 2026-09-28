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
// Alloc surface: consumers behind alloc-fallback / cfg(test).
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

    /// keystone-ur `shuffled()` semantics: repeatedly draw an index into the REMAINING
    /// items, remove it and append to the output. (This is NOT Fisher-Yates — the same
    /// draws map to a different permutation — so the remove-and-append shape is kept
    /// bit-exact; Z2.4c-2 runs it on fixed arrays instead of Vec.) `out` receives the
    /// permutation of 0..count.
    fn shuffled_into(&mut self, count: usize, out: &mut [u8]) {
        let mut items = [0u8; 256];
        for (i, slot) in items[..count].iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut remaining = count;
        for slot in out[..count].iter_mut() {
            let index = self.next_int(0, (remaining - 1) as u64) as usize;
            let v = items[index];
            items.copy_within(index + 1..remaining, index);
            remaining -= 1;
            *slot = v;
        }
    }

    /// Degree sampling via Vose's alias table, returns 1..=count. The sampler is a pure
    /// function of the fragment count and consumes no RNG — owners hoist one per session
    /// (Z2.4c-2), and draws stay bit-identical to the old per-call construction.
    fn choose_degree(&mut self, sampler: &Weighted) -> usize {
        sampler.next(self) + 1
    }
}

// ─── Weighted alias sampler ────────────────────────────────────────

/// Vose's alias method (aligned with keystone-ur sampler.rs, including the f64 path).
/// Z2.4c-2: fixed inline tables (was Vec); count ≤ MAX_SEQUENCE_COUNT = 256 so the
/// alias index domain is u8 (0..=255).
pub(crate) struct Weighted {
    aliases: [u8; 256],
    probs: [f64; 256],
    len: usize,
}

impl Weighted {
    /// Sampler for the degree distribution w_i = 1/i (i = 1..=count) — the only
    /// distribution the fountain uses.
    pub(crate) fn new_inverse(count: usize) -> Self {
        let mut w = [0f64; 256];
        for (i, x) in w[..count].iter_mut().enumerate() {
            *x = 1.0 / (i + 1) as f64;
        }
        Self::from_weights(&w[..count])
    }

    pub(crate) fn from_weights(weights: &[f64]) -> Self {
        debug_assert!(!weights.is_empty());
        let count = weights.len();
        let summed: f64 = weights.iter().sum();
        debug_assert!(summed > 0.0);
        let mut w = [0f64; 256];
        for (dst, &src) in w[..count].iter_mut().zip(weights.iter()) {
            *dst = src * count as f64 / summed;
        }

        // partition: small/large
        let mut small = [0u8; 256];
        let mut small_len = 0usize;
        let mut large = [0u8; 256];
        let mut large_len = 0usize;
        // keystone-ur order: j from 1..=count, count-j; partition predicate w[j] < 1.0 → small
        // Equivalent implementation: for j in (0..count).rev() — keeps the same fill order as upstream
        for j in (0..count).rev() {
            if w[j] < 1.0 {
                small[small_len] = j as u8;
                small_len += 1;
            } else {
                large[large_len] = j as u8;
                large_len += 1;
            }
        }
        // Upstream: (1..=count).map(|j| count - j) = [count-1, count-2, .., 0] reversed;
        // after partition s/l keep that reversed order. The for j in (0..count).rev() above produces the same order.

        let mut probs = [0f64; 256];
        let mut aliases = [0u8; 256];

        while small_len > 0 && large_len > 0 {
            let a = small[small_len - 1] as usize;
            small_len -= 1;
            let g = large[large_len - 1] as usize;
            large_len -= 1;
            probs[a] = w[a];
            aliases[a] = g as u8;
            w[g] += w[a] - 1.0;
            if w[g] < 1.0 {
                small[small_len] = g as u8;
                small_len += 1;
            } else {
                large[large_len] = g as u8;
                large_len += 1;
            }
        }
        for k in 0..large_len {
            probs[large[k] as usize] = 1.0;
        }
        for k in 0..small_len {
            probs[small[k] as usize] = 1.0;
        }

        Self {
            aliases,
            probs,
            len: count,
        }
    }

    fn next(&self, rng: &mut Xoshiro256) -> usize {
        let r1 = rng.next_double();
        let r2 = rng.next_double();
        let n = self.len;
        let i = (n as f64 * r1) as usize;
        if r2 < self.probs[i] {
            i
        } else {
            self.aliases[i] as usize
        }
    }
}

// ─── Part ──────────────────────────────────────────────────────────

/// Fragment payload cap (Z2.4c-2 semantic limit): max_fragment_length must fit —
/// over-cap raises InvalidFragmentLen at encoder construction.
pub(crate) const PART_DATA_MAX: usize = 2048;

/// Fountain fragment. Wire shape (aligned with keystone-ur Part::to_cbor):
/// CBOR array(5) = [sequence, sequence_count, message_length, checksum, data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Part {
    pub sequence: usize,
    pub sequence_count: usize,
    pub message_length: usize,
    pub checksum: u32,
    pub data: heapless::Vec<u8, PART_DATA_MAX>,
}

impl Part {
    /// CBOR encoding (uses shlosilo's own cbor.rs; shape byte-identical to minicbor:
    /// 82: array(5); the four uints use the shortest arg encoding for their u32 range; data is a byte string)
    /// Wire CBOR into a caller buffer (Z2.4c): structural write, no intermediate fragments.
    pub fn to_cbor_into(&self, out: &mut [u8], n: &mut usize) -> crate::error::Result<()> {
        use crate::encoding::cbor::CborWriter;
        let mut w = CborWriter::new(out);
        w.array_head(5)?;
        w.uint(self.sequence as u64)?;
        w.uint(self.sequence_count as u64)?;
        w.uint(self.message_length as u64)?;
        w.uint(u64::from(self.checksum))?;
        w.bytes(&self.data)?;
        *n = w.pos();
        Ok(())
    }

    /// Test-only convenience (allocates). Production frame building uses `to_cbor_into`.
    #[cfg(test)]
    #[cfg(test)] // Z3.5 collection: test-only convenience
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

    /// Fragment covered indexes (keystone-ur Part::indexes semantics).
    /// Z2.4c-2: zero-heap — returns (index set as u8 array, degree). fragment_count ≤
    /// MAX_SEQUENCE_COUNT = 256 so the u8 domain 0..=255 is exact. Infallible by
    /// construction (degree ≤ sequence_count ≤ 256 = array length).
    pub fn indexes_raw(&self) -> ([u8; MAX_SEQUENCE_COUNT], usize) {
        let sampler = Weighted::new_inverse(self.sequence_count.max(1));
        let mut raw = [0u8; MAX_SEQUENCE_COUNT];
        let n = choose_fragments_into(
            self.sequence,
            self.sequence_count,
            self.checksum,
            &sampler,
            &mut raw,
        );
        (raw, n)
    }

    /// Test-only helper (production paths branch on the degree directly).
    #[cfg(test)]
    pub fn is_simple(&self) -> bool {
        self.indexes_raw().1 == 1
    }
}

static ZEROES: [u8; PART_DATA_MAX] = [0u8; PART_DATA_MAX];

fn xor_into(dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    for (d, &s) in dst.iter_mut().zip(src.iter()) {
        *d ^= s;
    }
}

/// keystone-ur choose_fragments: when seq ≤ count, output the single original part;
/// otherwise seed = [seq BE u32][checksum BE u32] → SHA256 → xoshiro sampling.
/// Z2.4c-2: writes the u8 index set into `out`, returns the degree.
pub(crate) fn choose_fragments_into(
    sequence: usize,
    fragment_count: usize,
    checksum: u32,
    sampler: &Weighted,
    out: &mut [u8],
) -> usize {
    if sequence <= fragment_count {
        out[0] = (sequence - 1) as u8;
        return 1;
    }
    let mut seed = [0u8; 8];
    seed[0..4].copy_from_slice(&(sequence as u32).to_be_bytes());
    seed[4..8].copy_from_slice(&checksum.to_be_bytes());
    let mut xoshiro = Xoshiro256::from_seed_bytes(&seed);
    let degree = xoshiro.choose_degree(sampler);
    let mut shuffled = [0u8; 256];
    xoshiro.shuffled_into(fragment_count, &mut shuffled[..fragment_count]);
    out[..degree].copy_from_slice(&shuffled[..degree]);
    degree
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

/// Fountain encoder (no side effects: all state is closed over self, output is a value).
/// Z2.4c-2: borrows the message (no fragment copy — fragments are sliced on demand;
/// the old `partition` materialized the whole padded message as Vec<Vec<u8>>) and hoists
/// the degree sampler (pure function of the fragment count).
pub(crate) struct FountainEncoder<'a> {
    message: &'a [u8],
    fragment_length: usize,
    fragment_count: usize,
    message_length: usize,
    checksum: u32,
    current_sequence: usize,
    sampler: Weighted,
}

impl<'a> FountainEncoder<'a> {
    pub fn new(message: &'a [u8], max_fragment_length: usize) -> Result<Self, FountainError> {
        if message.is_empty() {
            return Err(FountainError::EmptyMessage);
        }
        if max_fragment_length == 0 {
            return Err(FountainError::InvalidFragmentLen);
        }
        let fl = fragment_length(message.len(), max_fragment_length);
        // Z2.4c-2 semantic caps: fragment payload fits Part::data, fragment count fits
        // the decoder budget and the u8 index domain.
        if fl > PART_DATA_MAX {
            return Err(FountainError::InvalidFragmentLen);
        }
        let fragment_count = div_ceil(message.len(), fl);
        if fragment_count > MAX_SEQUENCE_COUNT {
            return Err(FountainError::InvalidFragmentLen);
        }
        Ok(Self {
            message,
            fragment_length: fl,
            fragment_count,
            message_length: message.len(),
            checksum: crate::encoding::bytewords::crc32(message),
            current_sequence: 0,
            sampler: Weighted::new_inverse(fragment_count),
        })
    }

    pub fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Fragment i of the virtual zero-padded message: the real (non-pad) slice only —
    /// XOR with the implicit zero pad tail is the identity, so mixing the real prefix
    /// reproduces the padded result byte-for-byte.
    fn fragment(&self, i: usize) -> &[u8] {
        let start = i * self.fragment_length;
        let end = core::cmp::min(start + self.fragment_length, self.message.len());
        &self.message[start..end]
    }

    fn make_part(&self, sequence: usize) -> Result<Part, FountainError> {
        let mut idx = [0u8; MAX_SEQUENCE_COUNT];
        let n = choose_fragments_into(
            sequence,
            self.fragment_count,
            self.checksum,
            &self.sampler,
            &mut idx,
        );
        let mut data = heapless::Vec::from_slice(&ZEROES[..self.fragment_length])
            .map_err(|_| FountainError::InvalidFragmentLen)?;
        for &item in &idx[..n] {
            let frag = self.fragment(item as usize);
            xor_into(&mut data[..frag.len()], frag);
        }
        Ok(Part {
            sequence,
            sequence_count: self.fragment_count,
            message_length: self.message_length,
            checksum: self.checksum,
            data,
        })
    }

    pub fn next_part(&mut self) -> Result<Part, FountainError> {
        self.current_sequence += 1;
        self.make_part(self.current_sequence)
    }

    /// XMR cyclic mode (aligned with keystone: after seq reaches count it loops back to 1, so software wallets can ca
    pub fn next_cyclic_part(&mut self) -> Result<Part, FountainError> {
        if self.current_sequence == self.fragment_count {
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
    /// Caller output buffer too small (Z2.4c-3)
    OutputTooSmall,
    /// Budget exceeded (added in R3 remediation — keystone-ur has no such cap; a shlosilo discipline tightening)
    BudgetExceeded,
}

// ─── Decoder ───────────────────────────────────────────────────────

/// Decoder-side budget (same discipline origin as X1): cap = fragment count cap.
/// TxTemplate 16 KiB / minimum frame 200B → at most ~82 fragments; 256 leaves ample margin.
pub(crate) const MAX_SEQUENCE_COUNT: usize = 256;

/// Gate4 #4 (re-reviewed 2026-09-01): total received-frame budget per session.
/// BC-UR allows unlimited redundant frames, but decoder resources must be finite: received (buffer/queue share the
/// are all gated on the received set; sessions beyond this cap are treated as abnormal/attacks and fail with a sta
pub(crate) const MAX_TOTAL_FRAMES: usize = 4096;

/// Audit #5 P1-01 (open-02): elimination work budget — cumulative XOR byte cap.
/// Normal reassembly work is O(count × fragment) ≈ 256 × 200B = 51KB;
/// the 16MiB cap ≈ 300× normal work; a malicious XOR amplification attack (mass mixed
/// equations, repeated elimination) hits this wall before exhausting CPU.
pub(crate) const MAX_XOR_WORK_BYTES: usize = 16 * 1024 * 1024;

/// Equation key: fragment index set (u8 domain — fragment_count ≤ MAX_SEQUENCE_COUNT = 256).
pub type IdxSet = heapless::Vec<u8, { MAX_SEQUENCE_COUNT }>;

/// Caller-provided workspace for the fountain decoder (Z2.4c-3 C-class policy).
/// Sizing guidance: `decoded` ≥ sequence_count; `buffer`/`queue`/`received` cover the
/// session frame budget in the worst case (flux-specific). Pool exhaustion surfaces as
/// BudgetExceeded (session-abnormal semantics, matching the budget family).
pub struct FountainWs<'a> {
    pub decoded: &'a mut [Option<(usize, Part)>],
    pub buffer: &'a mut [Option<(IdxSet, Part)>],
    pub queue: &'a mut [Option<(usize, Part)>],
    pub received: &'a mut [Option<IdxSet>],
}

/// Fountain decoder: set-cover greedy reassembly (aligned with keystone-ur Decoder semantics).
/// Z2.4c-3: retained state lives in caller-provided pool slices (was BTreeMap/BTreeSet/VecDeque);
/// pool-slot scans replace the transient key collects. Cascade order is pool-slot order rather
/// than strict FIFO — GF(2) elimination is commutative, so reassembly, dedup, progress and all
/// budget totals are unaffected.
pub(crate) struct FountainDecoder<'a> {
    decoded: &'a mut [Option<(usize, Part)>],
    buffer: &'a mut [Option<(IdxSet, Part)>],
    queue: &'a mut [Option<(usize, Part)>],
    received: &'a mut [Option<IdxSet>],
    decoded_count: usize,
    received_count: usize,
    sequence_count: usize,
    message_length: usize,
    checksum: u32,
    fragment_length: usize,
    processed_parts_count: usize,
    /// Audit #5 open-02: cumulative XOR work (bytes)
    work_used: usize,
}

impl<'a> FountainDecoder<'a> {
    /// Staging convenience: allocates and LEAKS pool backing on purpose (ffi staging /
    /// tests only — the handle owns it for its lifetime). Production flux builds `with_ws`
    /// over its own pools (zero-heap).
    pub fn new() -> FountainDecoder<'static> {
        use crate::types::caps as c;
        let decoded: &'static mut [Option<(usize, Part)>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_DECODED_SLOTS].into_boxed_slice());
        let buffer: &'static mut [Option<(IdxSet, Part)>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_BUFFER_SLOTS].into_boxed_slice());
        let queue: &'static mut [Option<(usize, Part)>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_QUEUE_SLOTS].into_boxed_slice());
        let received: &'static mut [Option<IdxSet>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_RECEIVED_SLOTS].into_boxed_slice());
        FountainDecoder::with_ws(FountainWs {
            decoded,
            buffer,
            queue,
            received,
        })
    }

    /// Build over caller-provided pools (all slots cleared on entry — reset hygiene).
    pub fn with_ws(ws: FountainWs<'a>) -> Self {
        for slot in ws.decoded.iter_mut() {
            *slot = None;
        }
        for slot in ws.buffer.iter_mut() {
            *slot = None;
        }
        for slot in ws.queue.iter_mut() {
            *slot = None;
        }
        for slot in ws.received.iter_mut() {
            *slot = None;
        }
        Self {
            decoded: ws.decoded,
            buffer: ws.buffer,
            queue: ws.queue,
            received: ws.received,
            decoded_count: 0,
            received_count: 0,
            sequence_count: 0,
            message_length: 0,
            checksum: 0,
            fragment_length: 0,
            processed_parts_count: 0,
            work_used: 0,
        }
    }

    /// Session reset (Audit #5 P1-01 over-budget discipline): clear pools + counters in place.
    pub fn clear(&mut self) {
        for slot in self.decoded.iter_mut() {
            *slot = None;
        }
        for slot in self.buffer.iter_mut() {
            *slot = None;
        }
        for slot in self.queue.iter_mut() {
            *slot = None;
        }
        for slot in self.received.iter_mut() {
            *slot = None;
        }
        self.decoded_count = 0;
        self.received_count = 0;
        self.sequence_count = 0;
        self.message_length = 0;
        self.checksum = 0;
        self.fragment_length = 0;
        self.processed_parts_count = 0;
        self.work_used = 0;
    }

    pub fn complete(&self) -> bool {
        self.message_length != 0 && self.decoded_count == self.sequence_count
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

        if self.received_count == 0 {
            self.sequence_count = part.sequence_count;
            self.message_length = part.message_length;
            self.checksum = part.checksum;
            self.fragment_length = part.data.len();
        } else if !self.validate(&part) {
            return Err(FountainError::InconsistentPart);
        }

        let (raw, rn) = part.indexes_raw();
        let mut key = IdxSet::new();
        key.extend_from_slice(&raw[..rn])
            .map_err(|_| FountainError::BudgetExceeded)?;
        if self.received.iter().flatten().any(|k| k == &key) {
            return Ok(false);
        }
        // Gate4 #4: session frame budget — duplicates don't count (idempotent), new frames do
        if self.received_count >= MAX_TOTAL_FRAMES {
            return Err(FountainError::BudgetExceeded);
        }
        let slot = self
            .received
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(FountainError::BudgetExceeded)?;
        *slot = Some(key);
        self.received_count += 1;

        if rn == 1 {
            self.process_simple(part)?;
        } else {
            self.process_complex(part, &raw[..rn])?;
        }
        self.processed_parts_count += 1;
        Ok(true)
    }

    pub fn validate(&self, part: &Part) -> bool {
        self.received_count != 0
            && part.sequence_count == self.sequence_count
            && part.message_length == self.message_length
            && part.checksum == self.checksum
            && part.data.len() == self.fragment_length
    }

    fn process_simple(&mut self, part: Part) -> Result<(), FountainError> {
        let (raw, _) = part.indexes_raw();
        let index = raw[0] as usize;
        let slot = self
            .decoded
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(FountainError::BudgetExceeded)?;
        *slot = Some((index, part.clone()));
        self.decoded_count += 1;
        let q = self
            .queue
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(FountainError::BudgetExceeded)?;
        *q = Some((index, part));
        self.process_queue()?;
        Ok(())
    }

    fn process_queue(&mut self) -> Result<(), FountainError> {
        while let Some(qpos) = self.queue.iter().position(|s| s.is_some()) {
            let (index, simple) = self.queue[qpos].take().ok_or(FountainError::ExpectedItem)?;
            let index_u8 = index as u8;
            for bpos in 0..self.buffer.len() {
                let hit = matches!(&self.buffer[bpos], Some((key, _)) if key.contains(&index_u8));
                if !hit {
                    continue;
                }
                let (key, mut part) = self.buffer[bpos]
                    .take()
                    .ok_or(FountainError::ExpectedItem)?;
                let mut new_key = IdxSet::new();
                for &i in key.iter() {
                    if i != index_u8 {
                        new_key.push(i).map_err(|_| FountainError::BudgetExceeded)?;
                    }
                }
                self.work_used += part.data.len();
                if self.work_used > MAX_XOR_WORK_BYTES {
                    return Err(FountainError::BudgetExceeded);
                }
                xor_into(&mut part.data, &simple.data);
                if new_key.len() == 1 {
                    let only = new_key[0] as usize;
                    let slot = self
                        .decoded
                        .iter_mut()
                        .find(|s| s.is_none())
                        .ok_or(FountainError::BudgetExceeded)?;
                    *slot = Some((only, part.clone()));
                    self.decoded_count += 1;
                    let q = self
                        .queue
                        .iter_mut()
                        .find(|s| s.is_none())
                        .ok_or(FountainError::BudgetExceeded)?;
                    *q = Some((only, part));
                } else {
                    self.buffer[bpos] = Some((new_key, part));
                }
            }
        }
        Ok(())
    }

    fn process_complex(&mut self, mut part: Part, raw: &[u8]) -> Result<(), FountainError> {
        let mut indexes = IdxSet::new();
        indexes
            .extend_from_slice(raw)
            .map_err(|_| FountainError::BudgetExceeded)?;
        // Pass 1: which indexes are already decoded (in derivation order — the XOR order below
        // matches the original Vec-based to_remove loop exactly). All-decoded is a no-op BEFORE
        // any work accounting (preserved from the original control flow).
        let mut to_remove = IdxSet::new();
        for &x in indexes.iter() {
            if self
                .decoded
                .iter()
                .flatten()
                .any(|(idx, _)| *idx == x as usize)
            {
                to_remove
                    .push(x)
                    .map_err(|_| FountainError::BudgetExceeded)?;
            }
        }
        if indexes.len() == to_remove.len() {
            return Ok(());
        }
        for &remove in to_remove.iter() {
            // order-preserving removal from the key set (Vec::remove semantics)
            let pos = indexes
                .iter()
                .position(|&x| x == remove)
                .ok_or(FountainError::ExpectedItem)?;
            for j in pos..indexes.len() - 1 {
                indexes[j] = indexes[j + 1];
            }
            indexes.pop();
            let decoded_part = self
                .decoded
                .iter()
                .flatten()
                .find(|(idx, _)| *idx == remove as usize)
                .map(|(_, p)| p)
                .ok_or(FountainError::ExpectedItem)?;
            self.work_used += part.data.len();
            if self.work_used > MAX_XOR_WORK_BYTES {
                return Err(FountainError::BudgetExceeded);
            }
            xor_into(&mut part.data, &decoded_part.data);
        }
        if indexes.len() == 1 {
            let only = indexes[0] as usize;
            let slot = self
                .decoded
                .iter_mut()
                .find(|s| s.is_none())
                .ok_or(FountainError::BudgetExceeded)?;
            *slot = Some((only, part.clone()));
            self.decoded_count += 1;
            let q = self
                .queue
                .iter_mut()
                .find(|s| s.is_none())
                .ok_or(FountainError::BudgetExceeded)?;
            *q = Some((only, part));
        } else {
            let slot = self
                .buffer
                .iter_mut()
                .find(|s| s.is_none())
                .ok_or(FountainError::BudgetExceeded)?;
            *slot = Some((indexes, part));
        }
        Ok(())
    }

    /// Reassembled message into a caller buffer (Z2.4c-3 C-class). `out` must hold
    /// fragment_length × sequence_count bytes (combined incl. zero pad); the payload is
    /// out[..message_length]. Returns Ok(None) while incomplete (same as the old Option).
    pub fn message_into(&self, out: &mut [u8]) -> Result<Option<usize>, FountainError> {
        if !self.complete() {
            return Ok(None);
        }
        let total = self.fragment_length * self.sequence_count;
        if out.len() < total {
            return Err(FountainError::OutputTooSmall);
        }
        for idx in 0..self.sequence_count {
            let part = self
                .decoded
                .iter()
                .flatten()
                .find(|(i, _)| *i == idx)
                .map(|(_, p)| p)
                .ok_or(FountainError::ExpectedItem)?;
            out[idx * self.fragment_length..(idx + 1) * self.fragment_length]
                .copy_from_slice(&part.data);
        }
        let pad = &out[self.message_length..total];
        if pad.iter().any(|&x| x != 0) {
            return Err(FountainError::InvalidPadding);
        }
        Ok(Some(self.message_length))
    }

    /// Test/legacy convenience (allocates). Production reassembly uses `message_into`.
    pub fn message(&self) -> Result<Option<Vec<u8>>, FountainError> {
        if !self.complete() {
            return Ok(None);
        }
        let mut combined = Vec::with_capacity(self.fragment_length * self.sequence_count);
        for idx in 0..self.sequence_count {
            let part = self
                .decoded
                .iter()
                .flatten()
                .find(|(i, _)| *i == idx)
                .map(|(_, p)| p)
                .ok_or(FountainError::ExpectedItem)?;
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
    // Alloc surface: consumers behind alloc-fallback / cfg(test).
    #[cfg(feature = "alloc-fallback")]
    use alloc::vec;

    /// keystone-ur fountain.rs doctest vector 1:
    /// "Ten chars!" / max_len=4 → p1="Ten " p2="char" p3="s!\0\0"
    /// The first two frames are original parts; drop p3; frame 4 is still p3 (RNG picks a single segment);
    /// frame 5 = p1^p2^p3 (RNG picks 3 segments)
    #[test]
    fn keystone_doctest_ten_chars() {
        let data = b"Ten chars!";
        let mut enc = FountainEncoder::new(data, 4).unwrap();
        let p1 = enc.next_part().unwrap();
        assert_eq!(p1.data.as_slice(), b"Ten ");
        let p2 = enc.next_part().unwrap();
        assert_eq!(p2.data.as_slice(), b"char");
        // Drop p3
        let _p3 = enc.next_part().unwrap();
        // The first frame after the RNG takes over is still p3
        let p3_again = enc.next_part().unwrap();
        assert_eq!(p3_again.data.as_slice(), b"s!\0\0");
        // The next frame = p1 ^ p2 ^ p3
        let mixed = enc.next_part().unwrap();
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
        let sampler = Weighted::from_weights(&weights);

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
            let p = enc.next_part().unwrap();
            if p.is_simple() {
                simple_count += 1;
            }
            idx_sum += p.indexes_raw().1;
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
            let p = enc.next_part().unwrap();
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
            data: heapless::Vec::from_slice(&[0u8; 16]).unwrap(),
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
            data: heapless::Vec::from_slice(&[0xab_u8; 4]).unwrap(),
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
    /// Z2.4c-2 adaptation: wire fragments are capped at PART_DATA_MAX (2 KiB), so a natural
    /// construction can no longer accumulate 16 MiB of XOR work inside the frame budget.
    /// Enforcement semantics are asserted white-box: a real elimination accumulates work
    /// (natural path), and a session pre-loaded just under the cap trips BudgetExceeded at
    /// the enforcement point on the next elimination.
    #[test]
    fn xor_work_budget_enforced() {
        let frag = 2048;
        let count = 8;
        let message = vec![0xABu8; frag * count];
        let enc = FountainEncoder::new(&message, frag).unwrap();
        let mut dec = FountainDecoder::new();

        // Buffer a mixed part covering idx 0 plus only-undecoded others (nothing decoded yet).
        let mut buffered = false;
        for seq in count + 1..=MAX_SEQUENCE_COUNT {
            let part = enc.make_part(seq).unwrap();
            let (raw, rn) = part.indexes_raw();
            if rn >= 2 && raw[..rn].contains(&0) && !raw[..rn].contains(&2) {
                assert!(dec.receive(part).unwrap());
                buffered = true;
                break;
            }
        }
        assert!(buffered, "no mixed part over idx 0 found");

        // Natural accumulation: decoding simple idx 0 eliminates through the buffer once.
        dec.receive(enc.make_part(1).unwrap()).unwrap();
        assert_eq!(
            dec.work_used, frag,
            "one elimination must account one fragment of work"
        );

        // White-box enforcement: preload just under the cap, buffer {2,3}, decode 2 -> the
        // elimination adds `frag` bytes and must trip BudgetExceeded at the > check.
        dec.work_used = MAX_XOR_WORK_BYTES - (frag / 2);
        let mut buffered2 = false;
        for seq in count + 1..=MAX_SEQUENCE_COUNT {
            let part = enc.make_part(seq).unwrap();
            let (raw, rn) = part.indexes_raw();
            let clean = raw[..rn].contains(&2)
                && raw[..rn].iter().all(|&i| {
                    i == 2
                        || !dec
                            .decoded
                            .iter()
                            .flatten()
                            .any(|(idx, _)| *idx == i as usize)
                });
            if rn >= 2 && clean {
                assert!(dec.receive(part).unwrap());
                buffered2 = true;
                break;
            }
        }
        assert!(buffered2, "no clean mixed part over idx 2 found");
        assert_eq!(
            dec.receive(enc.make_part(3).unwrap()),
            Err(FountainError::BudgetExceeded),
            "work budget must trip at the enforcement point"
        );
    }
}
