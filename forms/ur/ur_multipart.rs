//! UR multipart state machine (R3 route A revised, 2026-08-31) — L2 boundary adapter layer
//!
//! L1 `encoding::fountain` provides pure-function fragmentation/reassembly; this module adds:
//! - UR string frame wrapping (`ur:<type>/<seq>-<count>/<bytewords-minimal>`, aligned with BCR-2020-06)
//! - Stateful `&mut self` Encoder/Decoder (alloc allowed, **never crosses FFI** — the FFI side uses typed handles)
//! - Budget guards: payload limit / frame string limit / total frame limit on the decode side
//!
//! The single-frame channel (small transactions emitted directly as one large QR) keeps using `ur_encode::encode` — this module only handles multipart.

extern crate alloc;

use crate::encoding::bytewords;
use crate::encoding::fountain::{
    FountainDecoder, FountainEncoder, FountainWs, Part, MAX_SEQUENCE_COUNT,
};
use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err(kind: ShlosiloErrorKind) -> ShlosiloError {
    ShlosiloError::new(kind)
}

/// P1-02 (audit #4): wire u64 → usize fallible conversion — anything above usize::MAX is rejected outright,
/// forbidding silent `as usize` truncation (dangerous semantics on 32-bit Thumb targets).
fn wire_len(n: u64) -> Result<usize> {
    usize::try_from(n)
        .ok()
        .filter(|&v| v <= MULTIPART_FRAME_MAX_LEN * 4)
        .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadTooLarge))
}

/// Multipart payload limit — aligned with TxTemplate 16 KiB (same source as the v2-security §4 size guardrail)
pub const MULTIPART_PAYLOAD_MAX_LEN: usize = 16384;
/// Single-frame string limit: bytewords ≈ 2×data; data ≤ fragment (≤ payload) → 2×16 KiB margin
pub const MULTIPART_FRAME_MAX_LEN: usize = 40960;
/// Single-frame payload limit (the single-frame large-QR channel goes through ur_encode::encode; only fragmentation here)
pub const DEFAULT_FRAGMENT_LEN: usize = 200;
/// Z2.4c-4: part-CBOR decode scratch (fragment payload + CBOR wrapper headroom)
pub(crate) const PART_CBOR_SCRATCH_MAX: usize = crate::encoding::fountain::PART_DATA_MAX + 64;

// ─── Encoder ───────────────────────────────────────────────────────

/// Stateful multipart encoder. `next_frame_into()` produces URI frame text into a
/// caller buffer; XMR re-scan scenarios use `next_cyclic_frame_into()`.
pub struct UrMultipartEncoder<'a> {
    inner: FountainEncoder<'a>,
    /// Z2.4c: fixed-cap (registry type tokens are short ascii-alnum/hyphen strings)
    type_name: heapless::String<32>,
}

impl<'a> UrMultipartEncoder<'a> {
    pub fn new(type_name: &str, payload: &'a [u8], max_fragment_len: usize) -> Result<Self> {
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
        let mut type_name_buf = heapless::String::new();
        type_name_buf
            .push_str(type_name)
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        Ok(Self {
            inner: FountainEncoder::new(payload, max_fragment_len)
                .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?,
            type_name: type_name_buf,
        })
    }

    pub fn fragment_count(&self) -> usize {
        self.inner.fragment_count()
    }

    /// Next frame URI (`ur:<type>/<seq>-<count>/<bytewords>`) into a caller buffer (Z2.4c
    /// C-class policy); returns the length written. `scratch` holds the intermediate part
    /// CBOR (caller-sized ≥ part wire size); overflow anywhere raises an explicit error.
    pub fn next_frame_into(&mut self, scratch: &mut [u8], out: &mut [u8]) -> Result<usize> {
        let part = self
            .inner
            .next_part()
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        self.frame_of_into(&part, scratch, out)
    }

    /// XMR cyclic re-scan frame (seq wraps back to 1 at the top)
    pub fn next_cyclic_frame_into(&mut self, scratch: &mut [u8], out: &mut [u8]) -> Result<usize> {
        let part = self
            .inner
            .next_cyclic_part()
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
        self.frame_of_into(&part, scratch, out)
    }

    fn frame_of_into(&self, part: &Part, scratch: &mut [u8], out: &mut [u8]) -> Result<usize> {
        let mut cn = 0usize;
        part.to_cbor_into(scratch, &mut cn)?;
        let mut n = 0usize;
        {
            use crate::types::push::{push_byte, push_dec, push_slice};
            push_slice(out, &mut n, b"ur:")?;
            push_slice(out, &mut n, self.type_name.as_bytes())?;
            push_byte(out, &mut n, b'/')?;
            push_dec(out, &mut n, part.sequence as u64)?;
            push_byte(out, &mut n, b'-')?;
            push_dec(out, &mut n, part.sequence_count as u64)?;
            push_byte(out, &mut n, b'/')?;
        }
        bytewords::encode_minimal_into(&scratch[..cn], out, &mut n)?;
        if n > MULTIPART_FRAME_MAX_LEN {
            return Err(err(ShlosiloErrorKind::EncodingBufferOverflow));
        }
        Ok(n)
    }

    /// Test/legacy convenience (allocates). Production paths use `next_frame_into`.
    pub fn next_frame(&mut self) -> Result<alloc::string::String> {
        let mut scratch = alloc::vec![0u8; MULTIPART_PAYLOAD_MAX_LEN + 32];
        let mut out = alloc::vec![0u8; MULTIPART_FRAME_MAX_LEN];
        let n = self.next_frame_into(&mut scratch, &mut out)?;
        alloc::string::String::from_utf8(out[..n].to_vec())
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))
    }

    /// Test/legacy convenience (allocates). Production paths use `next_cyclic_frame_into`.
    pub fn next_cyclic_frame(&mut self) -> Result<alloc::string::String> {
        let mut scratch = alloc::vec![0u8; MULTIPART_PAYLOAD_MAX_LEN + 32];
        let mut out = alloc::vec![0u8; MULTIPART_FRAME_MAX_LEN];
        let n = self.next_cyclic_frame_into(&mut scratch, &mut out)?;
        alloc::string::String::from_utf8(out[..n].to_vec())
            .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))
    }
}

// ─── Frame parsing (pure functions, for Decoder and tests) ──────────────────────────

/// Parse one frame URI → (type, seq, seq_count, part CBOR bytes)
/// Shape: `ur:<type>/<seq>-<count>/<body>`; single frame (no seq segment) returns Err(NotMultipart)
pub(crate) fn parse_frame<'a>(uri: &'a str, scratch: &'a mut [u8]) -> Result<Frame<'a>> {
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
    // seq-count segment optional: absent → single frame
    match rest.split_once('/') {
        None => Err(err(ShlosiloErrorKind::EncodingInvalidFormat)), // single frames go through ur_decode::decode
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
            // P0-B (2026-09-01): seq > count is a standard fountain mixed redundancy frame
            // (BC-UR semantics: sequence_count = original fragment count, seq starting at count+1 is redundancy),
            // no longer rejected — otherwise the decoder would reject its own encoder\'s redundancy frames.
            // The seq limit is only a resource budget (guards unbounded growth during long scans), not protocol semantics.
            // Audit #5 P1-01: two layers of budget unified — seq ≤ MAX_SEQUENCE_COUNT
            // (fountain redundancy frames have seq ≤ count ≤ 256; the old 1024 vs 4096 was inconsistent)
            if seq == 0 || count == 0 || count > MAX_SEQUENCE_COUNT || seq > MAX_SEQUENCE_COUNT {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            let n = bytewords::decode_minimal_into(body, scratch)?;
            Ok(Frame {
                type_name,
                sequence: seq,
                sequence_count: count,
                part_cbor: &scratch[..n],
            })
        }
    }
}

/// A parsed frame
pub(crate) struct Frame<'a> {
    pub type_name: &'a str,
    pub sequence: usize,
    pub sequence_count: usize,
    pub part_cbor: &'a [u8],
}

/// Part CBOR decoding (aligned with the to_cbor shape; reuses the X1-hardened cbor decoder)
pub(crate) fn part_from_cbor(bytes: &[u8]) -> Result<Part> {
    let item = crate::encoding::cbor::decode(bytes)
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    let arr = item
        .as_array()
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    if arr.len() != 5 {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    // P1-02 (audit #4): wire u64 → usize/u32 all fallible, silent narrowing forbidden
    // (dangerous truncation semantics on 32-bit Thumb); message_length is bounded by the payload budget
    let sequence = wire_len(
        arr.get(0)
            .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))??
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )?;
    let sequence_count = wire_len(
        arr.get(1)
            .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))??
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )?;
    let message_length = wire_len(
        arr.get(2)
            .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))??
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )?;
    let checksum = u32::try_from(
        arr.get(3)
            .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))??
            .as_uint()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?,
    )
    .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    let data = arr
        .get(4)
        .ok_or_else(|| err(ShlosiloErrorKind::UrPayloadInvalidCbor))??
        .as_bytes()
        .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))?;
    // P0-B: allow sequence > sequence_count (fountain mixed redundancy frames); limit same as parse_frame
    if sequence == 0
        || sequence_count == 0
        || sequence_count > MAX_SEQUENCE_COUNT
        || sequence > MAX_SEQUENCE_COUNT
    {
        return Err(err(ShlosiloErrorKind::UrPayloadInvalidCbor));
    }
    // P1-02: message_length budget — enforced on the decoder side (before the fix only the encoder side checked)
    if message_length == 0 || message_length > MULTIPART_PAYLOAD_MAX_LEN {
        return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
    }
    // P1-02: fragment/count/message mutually validated —
    // fragment data must not exceed the budget; when seq>=1, message >= (count-1)*data + 1 (the last piece may be shorter),
    // and message <= count*data (padding allowed, but too small means the wire lied)
    let dlen = data.len();
    if dlen == 0 || dlen > MULTIPART_PAYLOAD_MAX_LEN {
        return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
    }
    // Single piece completes: data.len() must be >= message_length (holds when the last piece is shorter than a fragment)
    // Multiple pieces: message_length <= count * dlen (count pieces × dlen each covers everything)
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
        data: heapless::Vec::from_slice(data)
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadTooLarge))?,
    })
}

// ─── Decoder ───────────────────────────────────────────────────────

/// Stateful multipart decoder. Feed frames one by one with `receive_frame()`, drive the UI with `progress()`,
/// after `complete()` take the result via `payload()` (read-only borrow — clone/copy within budget when the caller needs ownership).
/// Audit #5 P1-01: cumulative retained memory budget for the session — when the total bytes of Part.data across
/// decoded/buffer/queue exceed this value = abnormal session, reset to clear (an attacker cannot hold memory long-term).
/// The payload itself is <= 16 KiB; a 2× margin covers fountain elimination intermediate states.
pub const MULTIPART_SESSION_RETAINED_MAX: usize = MULTIPART_PAYLOAD_MAX_LEN * 2;

pub struct UrMultipartDecoder<'a> {
    inner: FountainDecoder<'a>,
    type_name: Option<heapless::String<32>>,
    /// Audit #5: cumulative retained bytes (accumulated data length per frame)
    retained_bytes: usize,
}

impl<'a> UrMultipartDecoder<'a> {
    /// Staging convenience: pools allocated + leaked on purpose (ffi staging / tests only).
    pub fn new() -> Self {
        Self::with_ws_of(FountainDecoder::new())
    }

    /// Zero-heap construction over caller-provided pools (Z2.4c-3 flux surface).
    pub fn with_ws(ws: FountainWs<'a>) -> Self {
        Self::with_ws_of(FountainDecoder::with_ws(ws))
    }

    fn with_ws_of(inner: FountainDecoder<'a>) -> Self {
        Self {
            inner,
            type_name: None,
            retained_bytes: 0,
        }
    }

    /// Audit #5 P1-01: over-budget reset — clears all session state (type memory discarded as well),
    /// an attack session cannot occupy memory long-term. The caller must re-scan from the start.
    fn reset(&mut self) {
        self.inner.clear();
        self.type_name = None;
        self.retained_bytes = 0;
    }

    /// Receive one frame URI. Ok(true) = new information, Ok(false) = duplicate/no new information.
    /// Type consistency check: mixed frames across types are rejected.
    /// Receive one frame URI into caller scratch (Z2.4c-4 C-class: `scratch` holds the
    /// intermediate part CBOR, ≥ PART_CBOR_SCRATCH_MAX).
    pub fn receive_frame_with(&mut self, uri: &str, scratch: &mut [u8]) -> Result<bool> {
        let frame = parse_frame(uri, scratch)?;
        match &self.type_name {
            None => {
                let mut tn = heapless::String::new();
                tn.push_str(frame.type_name)
                    .map_err(|_| err(ShlosiloErrorKind::EncodingInvalidFormat))?;
                self.type_name = Some(tn);
            }
            Some(t) if t != frame.type_name => {
                return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
            }
            _ => {}
        }
        let part = part_from_cbor(frame.part_cbor)?;
        // seq metadata consistency (fountain also validates internally; blocking here earlier gives more precise error semantics)
        if part.sequence_count != frame.sequence_count || part.sequence != frame.sequence {
            return Err(err(ShlosiloErrorKind::EncodingInvalidFormat));
        }
        let last_part_data_len = part.data.len();
        // Audit #6 P1-02: feed the fountain first to decide new/duplicate — only bookkeeping for unique equations that actually enter
        // the retained collections (duplicate frames do not count,
        // fixing the availability DoS of "repeated scanning exhausting the 32 KiB counter triggering reset").
        // BudgetExceeded (XOR work) uniformly resets/poisons the session.
        match self.inner.receive(part) {
            Ok(true) => {
                self.retained_bytes += last_part_data_len;
                if self.retained_bytes > MULTIPART_SESSION_RETAINED_MAX {
                    self.reset();
                    return Err(err(ShlosiloErrorKind::UrPayloadTooLarge));
                }
                Ok(true)
            }
            Ok(false) => Ok(false), // duplicate frame: no bookkeeping
            Err(crate::encoding::fountain::FountainError::BudgetExceeded) => {
                // XOR work exceeded: reset the session; subsequent calls fail stably until restarted
                self.reset();
                Err(err(ShlosiloErrorKind::UrPayloadTooLarge))
            }
            Err(_) => Err(err(ShlosiloErrorKind::EncodingInvalidFormat)),
        }
    }

    /// Receive one frame URI.
    ///
    /// Test/legacy convenience (allocates). Production paths use `receive_frame_with`.
    pub fn receive_frame(&mut self, uri: &str) -> Result<bool> {
        let mut scratch = alloc::vec![0u8; PART_CBOR_SCRATCH_MAX];
        self.receive_frame_with(uri, &mut scratch)
    }

    pub fn progress(&self) -> u8 {
        self.inner.progress()
    }

    pub fn complete(&self) -> bool {
        self.inner.complete()
    }

    /// P0-C (2026-09-01): UR type of the completed frame sequence (recorded from the first frame; mixed frames across types already rejected).
    /// L3 routes typed sign based on this; None = no frames received yet.
    pub fn ur_type(&self) -> Option<&str> {
        self.type_name.as_deref()
    }

    /// Payload after completion into a caller buffer (Z2.4c-3 C-class); `out` must hold
    /// fragment_length × sequence_count bytes; returns Some(message_length) when complete.
    pub fn payload_into(&self, out: &mut [u8]) -> Result<Option<usize>> {
        self.inner
            .message_into(out)
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))
    }

    /// Payload after completion (None = incomplete)
    ///
    /// Test/legacy convenience (allocates). Production paths use `payload_into`.
    pub fn payload(&self) -> Result<Option<alloc::vec::Vec<u8>>> {
        self.inner
            .message()
            .map_err(|_| err(ShlosiloErrorKind::UrPayloadInvalidCbor))
    }
}

impl Default for UrMultipartDecoder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests: BCR-2020-06 oracle + roundtrip + budget ─────────────────

#[cfg(test)]
mod tests {
    /// Test helper: parse into a leaked scratch (tests may retain the Frame).
    fn parse_frame_t<'a>(uri: &'a str) -> Result<Frame<'a>> {
        let scratch: &'static mut [u8] =
            alloc::boxed::Box::leak(alloc::vec![0u8; PART_CBOR_SCRATCH_MAX].into_boxed_slice());
        parse_frame(uri, scratch)
    }

    use super::*;
    use alloc::vec::Vec;

    /// P0-B regression (2026-09-01 re-review): upstream keystone-ur 0.1.1 mixed redundancy frames (seq > count)
    /// must be accepted by this decoder — the golden vector was generated by the keystone-ur Encoder (see the pitfall notes).
    #[test]
    fn p0b_keystone_upstream_mixed_frames_accepted() {
        // keystone-ur: payload "12345678", max_fragment_len=4 → 2 fragments; seq 3/4/5 = mixed frames
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

    /// P0-B acceptance: recovering the complete payload from seq>count mixed frames alone after losing the systematic frames
    #[test]
    fn p0b_loss_recovery_via_mixed_frames_only() {
        // keystone-ur: 64B payload, max_fragment_len=8 → 8 fragments; BIG9..12 = mixed frames
        // Lost the two systematic frames BIG3/BIG6, recovered by feeding only the BIG9-12 mixed frames
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
        // Systematic frames: 1,2,4,5,7,8 (losing 3 and 6)
        for (_, uri) in all
            .iter()
            .take(8)
            .filter(|(s, _)| !(*s == "3-8" || *s == "6-8"))
        {
            dec.receive_frame(uri).unwrap();
        }
        assert!(!dec.complete());
        // Only mixed frames 9-18 (Gaussian elimination reduces unknowns by X² per step; a few extra frames must all be collected)
        for (_, uri) in all.iter().skip(8) {
            dec.receive_frame(uri).unwrap();
        }
        assert!(dec.complete());
        let msg = dec.payload().unwrap().unwrap();
        assert_eq!(msg.len(), 64);
        // Upstream payload = (0..64).map(|i| (i*7 % 251) as u8)
        for (i, b) in msg.iter().enumerate() {
            assert_eq!(*b, (i as u32 * 7 % 251) as u8, "byte {i}");
        }
    }

    /// P0-B: the first fountain redundancy frame (seq=count+1) of our own encoder must be accepted by our own decoder
    #[test]
    fn p0b_own_encoder_mixed_frame_roundtrip() {
        let payload: Vec<u8> = (0..2048).map(|i| (i * 13 % 251) as u8).collect();
        let mut enc =
            UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN).unwrap();
        let n = enc.fragment_count();
        let mut dec = UrMultipartDecoder::new();
        // Feed count+1 frames first (including the count+1-th redundancy frame)
        for _ in 0..n + 1 {
            dec.receive_frame(&enc.next_frame().unwrap()).unwrap();
        }
        assert!(dec.complete());
        assert_eq!(dec.payload().unwrap().as_deref(), Some(payload.as_slice()));
    }

    /// keystone-ur ur.rs doctest vector (single-frame semantics cross-check — consistency of our fragmentation layer\'s frame shape)
    #[test]
    fn frame_format_matches_bcr() {
        // 4-byte payload, 2 fragments → the first frame should be ur:bytes/1-2/<bytewords>
        let mut enc = UrMultipartEncoder::new("bytes", b"12345678", 4).unwrap();
        assert_eq!(enc.fragment_count(), 2);
        let f1 = enc.next_frame().unwrap();
        assert!(f1.starts_with("ur:bytes/1-2/"), "frame={f1}");
        let f2 = enc.next_frame().unwrap();
        assert!(f2.starts_with("ur:bytes/2-2/"), "frame={f2}");
    }

    /// End-to-end: 2 KiB payload → 200B fragments → frame by frame (out of order + lost frames + duplicate frames) → reassembly
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

        // Out of order + lose 1 frame + duplicate frames + fountain redundancy backfill
        let mut dec = UrMultipartDecoder::new();
        let mut feed: Vec<&str> = frames.iter().map(|s| s.as_str()).collect();
        feed.reverse(); // out of order
                        // Drop one frame (the tail), backfilled later with cyclic redundancy
        let dropped = feed.pop().unwrap();

        // Feed frames out of order (losing 1 frame) — fountain redundancy may complete midway, do not assume it must be incomplete
        let mut cyclic =
            UrMultipartEncoder::new("xmr-txunsigned", &payload, DEFAULT_FRAGMENT_LEN).unwrap();
        for f in &feed {
            let _ = dec.receive_frame(f).unwrap();
        }
        // When frames are missing, backfill with cyclic redundancy until complete
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

    /// Mixed frames across types rejected
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

    /// seq/count domain validation: 0 / over-limit count / seq>count legal (P0-B semantics)
    ///
    /// False-positive test rewritten (audit #4 engineering item 4): the original test asserted with `ur:bytes/3-2/aaaa`
    /// that seq>count was rejected — but `aaaa` is invalid bytewords (4 chars < the 5-byte minimum),
    /// so the Err actually came from body decoding, never proving the sequence policy, and the assertion direction was
    /// the opposite of the fixed P0-B semantics (seq>count = fountain redundancy frame, legal).
    /// Now valid bytewords bodies pin each case separately: seq>count → Ok, genuinely illegal domain → Err.
    #[test]
    fn invalid_seq_domain_rejected() {
        use alloc::format;
        // Valid body: Part CBOR [seq, count, msg_len, checksum, data]
        // (bytewords-minimal encoded, shape aligned with part_from_cbor\'s expectation)
        use crate::encoding::bytewords;
        let part_cbor = crate::encoding::cbor::encode_array(&[
            crate::encoding::cbor::encode_uint(1),
            crate::encoding::cbor::encode_uint(2),
            crate::encoding::cbor::encode_uint(4),
            crate::encoding::cbor::encode_uint(0xdeadbeef),
            crate::encoding::cbor::encode_bytes(b"abcd"),
        ]);
        let body = bytewords::encode_minimal(&part_cbor);

        // seq > count: standard fountain redundancy frame → Ok (P0-B semantics; the pre-fix false-positive test asserted the opposite)
        let uri_redundant = format!("ur:bytes/3-2/{}", body);
        let frame = parse_frame_t(&uri_redundant)
            .expect("seq>count with valid body must parse (fountain redundant frame)");
        assert_eq!(frame.sequence, 3);
        assert_eq!(frame.sequence_count, 2);

        // seq=0 → Err (genuinely illegal domain)
        assert!(parse_frame_t(&format!("ur:bytes/0-2/{}", body)).is_err());
        // count over limit (> MAX_SEQUENCE_COUNT=256) → Err
        assert!(parse_frame_t(&format!("ur:bytes/1-999/{}", body)).is_err());
        // Invalid bytewords body (the real failure cause of the original test) → Err, but a body error, not a seq error
        assert!(parse_frame_t("ur:bytes/3-2/aaaa").is_err());
        // Single-frame shape (no seq segment) → Err (single frames should go through ur_decode::decode)
        assert!(parse_frame_t("ur:bytes/aaaa").is_err());
        assert!(parse_frame_t("not-a-ur").is_err());
    }

    /// Payload over budget rejected (16 KiB + 1)
    #[test]
    fn payload_over_budget_rejected() {
        let big: Vec<u8> = (0..MULTIPART_PAYLOAD_MAX_LEN + 1).map(|_| 0u8).collect();
        assert!(UrMultipartEncoder::new("bytes", &big, DEFAULT_FRAGMENT_LEN).is_err());
    }

    /// Type character domain validation
    #[test]
    fn invalid_type_rejected() {
        assert!(UrMultipartEncoder::new("bad type!", b"data", 4).is_err());
        assert!(UrMultipartEncoder::new("", b"data", 4).is_err());
    }
}
