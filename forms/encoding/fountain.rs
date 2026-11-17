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

#[cfg(any(feature = "alloc-fallback", test))]
extern crate alloc;

use crate::encoding::sha256;
// Alloc surface: consumers behind alloc-fallback / cfg(test).
#[cfg(any(feature = "alloc-fallback", test))]
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
    fn shuffled_into(&mut self, count: usize, out: &mut [u16]) {
        let mut items = [0u16; MAX_SEQUENCE_COUNT];
        for (i, slot) in items[..count].iter_mut().enumerate() {
            *slot = i as u16;
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
///
/// Phase 6: the alias index domain is u16 and the tables are sized by the profile's
/// `ur_source_fragments_max`. Cost: 2 B + 8 B per entry (10 B), so 256 entries ≈ 2.5 KiB
/// and a 4,096-fragment profile ≈ 40 KiB - which is why the sampler is built per call
/// today and must move into the caller's workspace before any profile takes that step.
pub struct Weighted {
    aliases: [u16; MAX_SEQUENCE_COUNT],
    probs: [f64; MAX_SEQUENCE_COUNT],
    len: usize,
}

impl Weighted {
    /// Sampler for the degree distribution w_i = 1/i (i = 1..=count) — the only
    /// distribution the fountain uses.
    pub fn new_inverse(count: usize) -> Self {
        let mut w = [0f64; MAX_SEQUENCE_COUNT];
        for (i, x) in w[..count].iter_mut().enumerate() {
            *x = 1.0 / (i + 1) as f64;
        }
        Self::from_weights(&w[..count])
    }

    pub fn from_weights(weights: &[f64]) -> Self {
        debug_assert!(!weights.is_empty());
        let count = weights.len();
        let summed: f64 = weights.iter().sum();
        debug_assert!(summed > 0.0);
        let mut w = [0f64; MAX_SEQUENCE_COUNT];
        for (dst, &src) in w[..count].iter_mut().zip(weights.iter()) {
            *dst = src * count as f64 / summed;
        }

        // partition: small/large
        let mut small = [0u16; MAX_SEQUENCE_COUNT];
        let mut small_len = 0usize;
        let mut large = [0u16; MAX_SEQUENCE_COUNT];
        let mut large_len = 0usize;
        // keystone-ur order: j from 1..=count, count-j; partition predicate w[j] < 1.0 → small
        // Equivalent implementation: for j in (0..count).rev() — keeps the same fill order as upstream
        for j in (0..count).rev() {
            if w[j] < 1.0 {
                small[small_len] = j as u16;
                small_len += 1;
            } else {
                large[large_len] = j as u16;
                large_len += 1;
            }
        }
        // Upstream: (1..=count).map(|j| count - j) = [count-1, count-2, .., 0] reversed;
        // after partition s/l keep that reversed order. The for j in (0..count).rev() above produces the same order.

        let mut probs = [0f64; MAX_SEQUENCE_COUNT];
        let mut aliases = [0u16; MAX_SEQUENCE_COUNT];

        while small_len > 0 && large_len > 0 {
            let a = small[small_len - 1] as usize;
            small_len -= 1;
            let g = large[large_len - 1] as usize;
            large_len -= 1;
            probs[a] = w[a];
            aliases[a] = g as u16;
            w[g] += w[a] - 1.0;
            if w[g] < 1.0 {
                small[small_len] = g as u16;
                small_len += 1;
            } else {
                large[large_len] = g as u16;
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
    /// Write this part's covered fragment indices into `out`; returns the degree.
    ///
    /// The alias sampler is **the caller's**: building one per call costs 10 B × the
    /// fragment capacity on the stack (2.5 KiB at 256, ~40 KiB at 4,096), which is why the
    /// decoder keeps one in its workspace and the encoder keeps one in its own.
    pub fn indexes_into(&self, sampler: &Weighted, out: &mut [u16]) -> usize {
        choose_fragments_into(
            self.sequence,
            self.sequence_count,
            self.checksum,
            sampler,
            out,
        )
    }

    /// Convenience for tests and one-shot callers (builds a sampler on the stack).
    #[cfg(any(feature = "alloc-fallback", test))]
    pub fn indexes_raw(&self) -> ([u16; MAX_SEQUENCE_COUNT], usize) {
        let sampler = Weighted::new_inverse(self.sequence_count.max(1));
        let mut raw = [0u16; MAX_SEQUENCE_COUNT];
        let n = self.indexes_into(&sampler, &mut raw);
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
    out: &mut [u16],
) -> usize {
    if sequence <= fragment_count {
        out[0] = (sequence - 1) as u16;
        return 1;
    }
    let mut seed = [0u8; 8];
    seed[0..4].copy_from_slice(&(sequence as u32).to_be_bytes());
    seed[4..8].copy_from_slice(&checksum.to_be_bytes());
    let mut xoshiro = Xoshiro256::from_seed_bytes(&seed);
    let degree = xoshiro.choose_degree(sampler);
    let mut shuffled = [0u16; MAX_SEQUENCE_COUNT];
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
    /// CBOR shell prefix (bytes-type UR semantics: the fountain MESSAGE is the
    /// CBOR serialization = shell ++ content). Empty for bare callers.
    prefix: [u8; 8],
    prefix_len: usize,
    message: &'a [u8],
    fragment_length: usize,
    fragment_count: usize,
    message_length: usize,
    checksum: u32,
    current_sequence: usize,
    sampler: Weighted,
    /// Per-frame index scratch (workspace-inline; see `make_part`).
    idx_scratch: [u16; MAX_SEQUENCE_COUNT],
}

impl<'a> FountainEncoder<'a> {
    /// Bare (prefix-less) convenience constructor. The multipart path goes
    /// through `new_with_prefix`; this one stays for the unit tests and bare
    /// callers, so it is intentionally unreferenced in the non-test build.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(message: &'a [u8], max_fragment_length: usize) -> Result<Self, FountainError> {
        Self::new_with_prefix(&[], message, max_fragment_length)
    }

    /// Composite message = `prefix ++ message` (2026-10-12: bytes-type URs put
    /// the CBOR byte-string shell in front of the content -- Cake's real
    /// multipart xmr-output message carries it and monero_c's import side runs
    /// `decodeBytes` on the reassembled message).
    pub fn new_with_prefix(
        prefix: &[u8],
        message: &'a [u8],
        max_fragment_length: usize,
    ) -> Result<Self, FountainError> {
        if message.is_empty() && prefix.is_empty() {
            return Err(FountainError::EmptyMessage);
        }
        if prefix.len() > 8 {
            return Err(FountainError::InvalidFragmentLen);
        }
        if max_fragment_length == 0 {
            return Err(FountainError::InvalidFragmentLen);
        }
        let msg_len = prefix.len() + message.len();
        let fl = fragment_length(msg_len, max_fragment_length);
        // Z2.4c-2 semantic caps: fragment payload fits Part::data, fragment count fits
        // the decoder budget and the u8 index domain.
        if fl > PART_DATA_MAX {
            return Err(FountainError::InvalidFragmentLen);
        }
        let fragment_count = div_ceil(msg_len, fl);
        if fragment_count > MAX_SEQUENCE_COUNT {
            return Err(FountainError::InvalidFragmentLen);
        }
        let mut prefix_buf = [0u8; 8];
        prefix_buf[..prefix.len()].copy_from_slice(prefix);
        Ok(Self {
            prefix: prefix_buf,
            prefix_len: prefix.len(),
            message,
            fragment_length: fl,
            fragment_count,
            message_length: msg_len,
            checksum: crate::encoding::bytewords::crc32_concat(prefix, message),
            current_sequence: 0,
            sampler: Weighted::new_inverse(fragment_count),
            idx_scratch: [0u16; MAX_SEQUENCE_COUNT],
        })
    }

    /// The CBOR shell bytes this encoder prepends to the message (empty for
    /// bare-item UR types). Test-facing only: the multipart wrapper decides it,
    /// and only `ur_multipart`'s unit tests read it back.
    #[cfg(test)]
    pub(crate) fn message_prefix(&self) -> &[u8] {
        &self.prefix[..self.prefix_len]
    }

    pub fn fragment_count(&self) -> usize {
        self.fragment_count
    }

    /// Fragment i of the virtual zero-padded message: the real (non-pad) slice only —
    /// XOR with the implicit zero pad tail is the identity, so mixing the real prefix
    /// reproduces the padded result byte-for-byte.
    /// XOR fragment `i` of the virtual zero-padded (prefix ++ message) into
    /// `data` at offset 0 (region-wise: a fragment may span shell and content).
    fn xor_fragment_into(&self, i: usize, data: &mut [u8]) {
        let start = i * self.fragment_length;
        let end = core::cmp::min(start + self.fragment_length, self.message_length);
        let mut off = start;
        while off < end {
            let (chunk, at) = if off < self.prefix_len {
                let e = core::cmp::min(end, self.prefix_len);
                (&self.prefix[off..e], off)
            } else {
                let s = off - self.prefix_len;
                let e = core::cmp::min(end - self.prefix_len, self.message.len());
                (&self.message[s..e], off)
            };
            xor_into(&mut data[at - start..at - start + chunk.len()], chunk);
            off += chunk.len();
        }
    }

    fn make_part(&mut self, sequence: usize) -> Result<Part, FountainError> {
        // The index scratch is a field, not a local: at a 4,096-fragment profile a local
        // array would be 8 KiB of stack per frame (the encoder is workspace-placed).
        let mut idx = core::mem::replace(&mut self.idx_scratch, [0u16; MAX_SEQUENCE_COUNT]);
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
            self.xor_fragment_into(item as usize, &mut data);
        }
        self.idx_scratch = idx;
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

    /// XMR cyclic mode (aligned with keystone: after seq reaches count it loops back to 1, so software wallets can catch up)
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
/// Source fragments per session. **Capacity**, from the platform profile.
///
/// Phase 6: the index domain is u16 (no `as u8` truncation anywhere in the fountain), and
/// how many fragments a platform will carry is a separate, per-platform decision. Raising
/// this number also widens every index array and the alias sampler, so it is not free -
/// see the sampler budget note on [`Weighted`].
pub(crate) const MAX_SEQUENCE_COUNT: usize = crate::limits::UR_SOURCE_FRAGMENTS_MAX;

/// Gate4 #4 (re-reviewed 2026-09-01): total received-frame budget per session.
/// BC-UR allows unlimited redundant frames, but decoder resources must be finite: received (buffer/queue share the same origin)
/// are all gated on the received set; sessions beyond this cap are treated as abnormal/attacks and fail with a stable error.
pub(crate) const MAX_TOTAL_FRAMES: usize = 4096;

/// Audit #5 P1-01 (open-02): elimination work budget — cumulative XOR byte cap.
/// Normal reassembly work is O(count × fragment) ≈ 256 × 200B = 51KB;
/// the 16MiB cap ≈ 300× normal work; a malicious XOR amplification attack (mass mixed
/// equations, repeated elimination) hits this wall before exhausting CPU.
pub(crate) const MAX_XOR_WORK_BYTES: usize = 16 * 1024 * 1024;

/// Equation key: fragment index set (u8 domain — fragment_count ≤ MAX_SEQUENCE_COUNT = 256).
pub type IdxSet = heapless::Vec<u16, { MAX_SEQUENCE_COUNT }>;

/// Words in the fixed-width index-set key: one bit per possible source fragment.
///
/// `MAX_SEQUENCE_COUNT = 256` index values ⇒ 256 bits ⇒ 4 words. This replaces the
/// `IdxSet` (264 B: a 256-byte inline array plus length and padding) **in the dedup
/// pool only** - 4,096 slots of 264 B were 1,114,112 B of the 2.8 MB decode workspace,
/// spent on remembering which fragment combinations had already been seen.
///
/// Why not "one bit per sequence number" (512 B total): `choose_fragments` maps a
/// sequence to a set, and two different sequences CAN produce the same set. Dedup is
/// defined on set identity, so keying on the sequence would change behaviour. Keeping
/// the set, fixed-width, is the equivalence-preserving shrink.
pub(crate) const IDXKEY_WORDS: usize = MAX_SEQUENCE_COUNT.div_ceil(64);

/// Fixed-width index-set key (bitset + degree). Equality only - the decoder asks
/// "have I seen this combination", never "which fragments".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdxKey {
    words: [u64; IDXKEY_WORDS],
    /// Degree, kept so a corrupted/duplicate comparison can never collide a
    /// 0-degree key with the empty sentinel.
    degree: u8,
}

impl IdxKey {
    /// Build from the raw fragment indices (each < MAX_SEQUENCE_COUNT).
    pub fn from_indexes(raw: &[u16]) -> Self {
        let mut words = [0u64; IDXKEY_WORDS];
        for &i in raw {
            let (w, b) = (usize::from(i) / 64, usize::from(i) % 64);
            // Indices are produced by `choose_fragments_into` from a fragment_count that
            // is validated ≤ MAX_SEQUENCE_COUNT, so this cannot be out of range; the
            // guard keeps forms panic-free if that ever changes.
            if w < IDXKEY_WORDS {
                words[w] |= 1u64 << b;
            }
        }
        Self {
            words,
            degree: raw.len().min(u8::MAX as usize) as u8,
        }
    }
}

/// Largest fragment we will hold in an arena slot.
///
/// Phase 5c: this is a **platform value** now (`ur_inbound_fragment_max`), not the wire
/// cap. `Part.data` keeps its 2 KiB capacity because the same type carries our outbound
/// frames (`ur_encode_fragment_len <= ur_inbound_fragment_max`, enforced by build.rs);
/// the arena only has to fit what a **peer** sends. The wallets in our interop set send
/// 65 B fragments (Cake/Sparrow) and Keystone's default `max_fragment_length` is 200, so
/// 256 is 4x the largest observed and still 8x smaller than the old slot.
pub(crate) const FRAGMENT_MAX: usize = crate::limits::UR_INBOUND_FRAGMENT_MAX;

/// Message-arena size. `fragment_length × sequence_count` can exceed the payload by up
/// to one whole fragment (the sender pads the last one), and `sequence_count` tops out at
/// `MAX_SEQUENCE_COUNT`.
pub(crate) fn message_arena_len() -> usize {
    crate::limits::UR_PAYLOAD_MAX + MAX_SEQUENCE_COUNT
}

/// Source-fragment capacity in force for this build (the profile's value).
pub fn source_fragments_max() -> usize {
    MAX_SEQUENCE_COUNT
}

/// Equation-arena size: one fixed-width slot per buffer entry.
pub(crate) fn equation_arena_len(buffer_slots: usize) -> usize {
    buffer_slots * FRAGMENT_MAX
}

fn frag_at(buf: &[u8], index: usize, fl: usize) -> &[u8] {
    &buf[index * fl..index * fl + fl]
}

fn frag_at_mut(buf: &mut [u8], index: usize, fl: usize) -> &mut [u8] {
    let (o, e) = (index * fl, index * fl + fl);
    &mut buf[o..e]
}

/// Caller-provided workspace for the fountain decoder (Z2.4c-3 C-class policy).
///
/// Phase 5b: the pools hold **metadata only**. Fragment bytes live in two arenas:
///
/// - `message`: reassembled **original** fragments, fragment `i` at `i * fragment_length`.
///   That prefix *is* the combined message, so `message_into` is one copy, not a scatter.
/// - `equations`: not-yet-solved **XOR accumulations**, one fixed `FRAGMENT_MAX` slot per
///   buffer entry.
///
/// They stay separate on purpose (design note §6.2): a solved original has a known
/// position, an unsolved equation does not, so they cannot share storage.
///
/// Sizing: `message` ≥ `MULTIPART_PAYLOAD_MAX_LEN + MAX_SEQUENCE_COUNT` (fragment padding
/// can add up to one whole fragment), `equations` = buffer slots × `FRAGMENT_MAX`.
/// Sizing guidance: `decoded` ≥ sequence_count; `buffer`/`queue`/`received` cover the
/// session frame budget in the worst case (flux-specific). Pool exhaustion surfaces as
/// BudgetExceeded (session-abnormal semantics, matching the budget family).
pub struct FountainWs<'a> {
    /// Recovered fragment indices (their bytes are in `message`).
    pub decoded: &'a mut [Option<usize>],
    /// Unsolved equation: (fragment index set, data length); bytes at slot × FRAGMENT_MAX.
    pub buffer: &'a mut [Option<(IdxSet, usize)>],
    /// Indices whose cascade has not been applied yet.
    pub queue: &'a mut [Option<usize>],
    pub received: &'a mut [Option<IdxKey>],
    pub message: &'a mut [u8],
    pub equations: &'a mut [u8],
    /// Per-session alias sampler scratch (built once when the first part fixes the
    /// fragment count) and the index scratch `indexes_into` writes into.
    pub index_scratch: &'a mut [u16],
}

/// Fountain decoder: set-cover greedy reassembly (aligned with keystone-ur Decoder semantics).
/// Z2.4c-3: retained state lives in caller-provided pool slices (was BTreeMap/BTreeSet/VecDeque);
/// pool-slot scans replace the transient key collects. Cascade order is pool-slot order
/// rather than strict FIFO — GF(2) elimination is commutative, so reassembly, dedup, progress and all
/// budget totals are unaffected.
pub(crate) struct FountainDecoder<'a> {
    decoded: &'a mut [Option<usize>],
    buffer: &'a mut [Option<(IdxSet, usize)>],
    queue: &'a mut [Option<usize>],
    received: &'a mut [Option<IdxKey>],
    message: &'a mut [u8],
    equations: &'a mut [u8],
    index_scratch: &'a mut [u16],
    /// Built once per session (10 B × fragment capacity would be stack-resident if it were
    /// constructed per part). Empty until the first part fixes `sequence_count`.
    sampler: Weighted,
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
    #[cfg(any(feature = "alloc-fallback", test))]
    pub fn new() -> FountainDecoder<'static> {
        use crate::types::caps as c;
        let decoded: &'static mut [Option<usize>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_DECODED_SLOTS].into_boxed_slice());
        let buffer: &'static mut [Option<(IdxSet, usize)>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_BUFFER_SLOTS].into_boxed_slice());
        let queue: &'static mut [Option<usize>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_QUEUE_SLOTS].into_boxed_slice());
        let received: &'static mut [Option<IdxKey>] =
            alloc::boxed::Box::leak(alloc::vec![None; c::UR_WS_RECEIVED_SLOTS].into_boxed_slice());
        let message: &'static mut [u8] =
            alloc::boxed::Box::leak(alloc::vec![0u8; message_arena_len()].into_boxed_slice());
        let equations: &'static mut [u8] = alloc::boxed::Box::leak(
            alloc::vec![0u8; equation_arena_len(c::UR_WS_BUFFER_SLOTS)].into_boxed_slice(),
        );
        let index_scratch: &'static mut [u16] =
            alloc::boxed::Box::leak(alloc::vec![0u16; MAX_SEQUENCE_COUNT].into_boxed_slice());
        FountainDecoder::with_ws(FountainWs {
            decoded,
            buffer,
            queue,
            received,
            message,
            equations,
            index_scratch,
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
            message: ws.message,
            equations: ws.equations,
            index_scratch: ws.index_scratch,
            sampler: Weighted::new_inverse(1),
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

    /// Fragment length fixed by the first accepted part (0 before that).
    pub fn fragment_length(&self) -> usize {
        self.fragment_length
    }

    pub fn complete(&self) -> bool {
        // `>=`, not `==`: a single feed can resolve several slots through the
        // reduction cascade when combo parts arrive before their systematics,
        // so decoded_count can JUMP OVER the exact target — an equality check
        // never fires again and the session wedges at the 99% progress cap
        // (the 2026-10-08 device hunt: combo-first orders wedge, clean orders
        // complete; host repro = rotation/reverse feed patterns).
        self.message_length != 0 && self.decoded_count >= self.sequence_count
    }

    /// Completion fraction, 0..=99 (100 is expressed by [`complete`]).
    ///
    /// Measured as **solved fragments / fragment count**: the old formula counted
    /// received parts against `1.75 × count`, so a 2-fragment message sat at 57%
    /// after the first accepted frame and never moved again, and a 6-fragment one
    /// parked at 99% long before completion (2026-11-05 field report: the bar read
    /// as "stuck"). Solved fragments only grow when the reduction actually makes
    /// progress, which is what the operator needs to see.
    pub fn progress(&self) -> u8 {
        if self.sequence_count == 0 {
            return 0;
        }
        let pct = (self.decoded_count * 100) / self.sequence_count;
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
        // The arena slot is FRAGMENT_MAX wide; an oversized fragment must be refused
        // here rather than truncated into a neighbour's slot.
        if part.data.len() > FRAGMENT_MAX {
            return Err(FountainError::InvalidFragmentLen);
        }
        // Budget-family caps (the pinned contract for sequence_count is BudgetExceeded):
        // the message arena is sized for UR_PAYLOAD_MAX, so a larger claim cannot land.
        if part.sequence_count > MAX_SEQUENCE_COUNT
            || part.message_length > crate::limits::UR_PAYLOAD_MAX
        {
            return Err(FountainError::BudgetExceeded);
        }
        if self.received_count >= MAX_TOTAL_FRAMES {
            return Err(FountainError::BudgetExceeded);
        }

        if self.received_count == 0 {
            self.sequence_count = part.sequence_count;
            self.message_length = part.message_length;
            self.checksum = part.checksum;
            self.fragment_length = part.data.len();
            // One sampler per session: building it per part would put its tables on the
            // stack (see `Weighted`), which is a device bomb at large capacities.
            self.sampler = Weighted::new_inverse(self.sequence_count.max(1));
        } else if !self.validate(&part) {
            return Err(FountainError::InconsistentPart);
        }

        if self.index_scratch.len() < self.sequence_count {
            return Err(FountainError::BudgetExceeded);
        }
        let rn = part.indexes_into(&self.sampler, self.index_scratch);
        // Fixed-width key (5a): same set identity, 33 B instead of 264 B.
        let key = IdxKey::from_indexes(&self.index_scratch[..rn]);
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
            // Degree 1 can come from a systematic frame (index = sequence-1) *or* from a
            // mixed frame whose draw collapsed to one fragment -- so the index is read
            // from the sampler output, never inferred from `sequence`.
            let index = self.index_scratch[0] as usize;
            self.process_simple(part, index)?;
        } else {
            let indexes: IdxSet = IdxSet::from_slice(&self.index_scratch[..rn])
                .map_err(|_| FountainError::BudgetExceeded)?;
            self.process_complex(part, indexes)?;
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

    fn decoded_contains(&self, index: usize) -> bool {
        self.decoded.iter().flatten().any(|i| *i == index)
    }

    /// Store a solved original fragment in the message arena.
    fn store_original(&mut self, index: usize, data: &[u8]) -> Result<(), FountainError> {
        let fl = self.fragment_length;
        if data.len() != fl || (index + 1) * fl > self.message.len() {
            return Err(FountainError::OutputTooSmall);
        }
        frag_at_mut(self.message, index, fl).copy_from_slice(data);
        Ok(())
    }

    fn process_simple(&mut self, part: Part, index: usize) -> Result<(), FountainError> {
        // Idempotence guard: the cascade may have already resolved this index
        // (a reduced combo landing before its systematic). A second entry
        // would inflate decoded_count and fill a slot with a duplicate.
        if self.decoded_contains(index) {
            return Ok(());
        }
        self.store_original(index, &part.data)?;
        let slot = self
            .decoded
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(FountainError::BudgetExceeded)?;
        *slot = Some(index);
        self.decoded_count += 1;
        let q = self
            .queue
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(FountainError::BudgetExceeded)?;
        *q = Some(index);
        self.process_queue()?;
        Ok(())
    }

    fn process_queue(&mut self) -> Result<(), FountainError> {
        while let Some(qpos) = self.queue.iter().position(|s| s.is_some()) {
            let index = self.queue[qpos].take().ok_or(FountainError::ExpectedItem)?;
            let index_idx = index as u16;
            let fl = self.fragment_length;
            for bpos in 0..self.buffer.len() {
                let hit = matches!(&self.buffer[bpos], Some((key, _)) if key.contains(&index_idx));
                if !hit {
                    continue;
                }
                let (key, len) = self.buffer[bpos]
                    .take()
                    .ok_or(FountainError::ExpectedItem)?;
                let mut new_key = IdxSet::new();
                for &i in key.iter() {
                    if i != index_idx {
                        new_key.push(i).map_err(|_| FountainError::BudgetExceeded)?;
                    }
                }
                self.work_used += len;
                if self.work_used > MAX_XOR_WORK_BYTES {
                    return Err(FountainError::BudgetExceeded);
                }
                // equation XOR the solved original: two disjoint arenas.
                let base = bpos * FRAGMENT_MAX;
                let (equations, message) = (&mut *self.equations, &*self.message);
                xor_into(&mut equations[base..base + fl], frag_at(message, index, fl));
                if new_key.len() == 1 {
                    let only = new_key[0] as usize;
                    if self.decoded_contains(only) {
                        continue;
                    }
                    // Move the solved bytes from the equation arena to the message arena.
                    // Two disjoint fields, so no temporary buffer (and none would be
                    // available: this path also builds without an allocator).
                    if (only + 1) * fl > self.message.len() {
                        return Err(FountainError::OutputTooSmall);
                    }
                    let base = bpos * FRAGMENT_MAX;
                    {
                        let src = &self.equations[base..base + fl];
                        let msg_off = only * fl;
                        self.message[msg_off..msg_off + fl].copy_from_slice(src);
                    }
                    let slot = self
                        .decoded
                        .iter_mut()
                        .find(|s| s.is_none())
                        .ok_or(FountainError::BudgetExceeded)?;
                    *slot = Some(only);
                    self.decoded_count += 1;
                    let q = self
                        .queue
                        .iter_mut()
                        .find(|s| s.is_none())
                        .ok_or(FountainError::BudgetExceeded)?;
                    *q = Some(only);
                } else {
                    self.buffer[bpos] = Some((new_key, len));
                }
            }
        }
        Ok(())
    }

    fn process_complex(
        &mut self,
        mut part: Part,
        mut indexes: IdxSet,
    ) -> Result<(), FountainError> {
        let fl = self.fragment_length;
        // Pass 1: which indexes are already decoded (in derivation order — the XOR order below
        // matches the original Vec-based to_remove loop exactly). All-decoded is a no-op BEFORE
        // any work accounting (preserved from the original control flow).
        let mut to_remove = IdxSet::new();
        for &x in indexes.iter() {
            if self.decoded.iter().flatten().any(|i| *i == x as usize) {
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
            self.work_used += part.data.len();
            if self.work_used > MAX_XOR_WORK_BYTES {
                return Err(FountainError::BudgetExceeded);
            }
            xor_into(&mut part.data, frag_at(self.message, remove as usize, fl));
        }
        if indexes.len() == 1 {
            let only = indexes[0] as usize;
            if self.decoded_contains(only) {
                return Ok(());
            }
            self.store_original(only, &part.data)?;
            let slot = self
                .decoded
                .iter_mut()
                .find(|s| s.is_none())
                .ok_or(FountainError::BudgetExceeded)?;
            *slot = Some(only);
            self.decoded_count += 1;
            let q = self
                .queue
                .iter_mut()
                .find(|s| s.is_none())
                .ok_or(FountainError::BudgetExceeded)?;
            *q = Some(only);
        } else {
            let bpos = self
                .buffer
                .iter()
                .position(|s| s.is_none())
                .ok_or(FountainError::BudgetExceeded)?;
            let base = bpos * FRAGMENT_MAX;
            if base + part.data.len() > self.equations.len() {
                return Err(FountainError::OutputTooSmall);
            }
            self.buffer[bpos] = Some((indexes, part.data.len()));
            self.equations[base..base + part.data.len()].copy_from_slice(&part.data);
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
        // Every index below sequence_count has been solved into its own slot, so the
        // arena prefix is already the combined message (phase 5b: one copy, no scatter).
        if self.message.len() < total {
            return Err(FountainError::ExpectedItem);
        }
        out[..total].copy_from_slice(&self.message[..total]);
        let pad = &out[self.message_length..total];
        if pad.iter().any(|&x| x != 0) {
            return Err(FountainError::InvalidPadding);
        }
        Ok(Some(self.message_length))
    }

    /// Message length without materializing (v1 contract 4).
    /// Buffer CAPACITY `message_into` needs (message + fragment padding) —
    /// the number the BufferTooSmall path reports for retry (contract 4).
    /// The delivered length is `message_length` (padding excluded).
    pub fn message_len(&self) -> Option<usize> {
        if self.complete() {
            Some(self.fragment_length * self.sequence_count)
        } else {
            None
        }
    }

    /// Test/legacy convenience (allocates). Production paths use `message_into`.
    #[cfg(any(feature = "alloc-fallback", test))]
    pub fn message(&self) -> Result<Option<Vec<u8>>, FountainError> {
        if !self.complete() {
            return Ok(None);
        }
        let total = self.fragment_length * self.sequence_count;
        let combined = self
            .message
            .get(..total)
            .ok_or(FountainError::ExpectedItem)?;
        let pad = combined
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
    #[cfg(any(feature = "alloc-fallback", test))]
    use alloc::vec;

    /// Progress semantics: solved fragments divided by fragment count, not the number
    /// of received parts.
    ///
    /// Field report (2026-11-05): "a 2-fragment message sticks at 57%" and "a
    /// 6-fragment one sits at 99% for five minutes" -- the old formula
    /// processed/(count x 1.75) saturates before completion for any message, so the
    /// operator reads "stuck" instead of "N fragments still missing".
    #[test]
    fn progress_tracks_solved_fragments() {
        // 8 bytes / 4 bytes per fragment = 2 fragments
        let data = b"abcdefgh";
        let mut enc = FountainEncoder::new(data, 4).unwrap();
        let mut dec = FountainDecoder::new();
        let p1 = enc.next_part().unwrap();
        assert_eq!(
            dec.progress(),
            0,
            "no frame fed yet, so there must be no progress"
        );
        assert!(dec.receive(p1).unwrap());
        assert_eq!(dec.progress(), 50, "1 of 2 fragments solved = 50%");
        let p2 = enc.next_part().unwrap();
        assert!(dec.receive(p2).unwrap());
        assert_eq!(
            dec.progress(),
            99,
            "capped at 99 when all fragments are in (100 is expressed by complete)"
        );
        assert!(dec.complete());
    }

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
        // Phase 5c: the arena slot is the profile's inbound ceiling, so the synthetic
        // fragment must fit inside it (the budget math below is fragment-size agnostic).
        let frag = core::cmp::min(2048, FRAGMENT_MAX);
        let count = 8;
        let message = vec![0xABu8; frag * count];
        let mut enc = FountainEncoder::new(&message, frag).unwrap();
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
                    i == 2 || !dec.decoded.iter().flatten().any(|idx| *idx == i as usize)
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
