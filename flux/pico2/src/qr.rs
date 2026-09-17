//! QR decoding for the camera path (P3): adaptive binarization + rqrr.
//!
//! The binarizer is the block-adaptive one validated on the host
//! (tests/qr_decode_host.rs): rqrr's own row-average threshold measurably
//! loses frames that ours recovers on identical pixels, so the device owns
//! the thresholding and hands rqrr a bitmap (`prepare_from_bitmap`).

extern crate alloc;

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// Adaptive-threshold block size (8x8, zxing HybridBinarizer style).
const BS: usize = 8;

/// Block-adaptive binarization: per-block means, smoothed over a 5x5
/// neighborhood of block means; `pixel < local mean` = black.
/// `gray` is `w*h` bytes row-major. Returns `w*h` flags (true = black).
pub fn binarize_adaptive(w: usize, h: usize, gray: &[u8]) -> Vec<bool> {
    let bw = w.div_ceil(BS);
    let bh = h.div_ceil(BS);
    let mut means = alloc::vec![0u32; bw * bh];
    for by in 0..bh {
        for bx in 0..bw {
            let mut acc = 0u32;
            let mut n = 0u32;
            for y in by * BS..((by + 1) * BS).min(h) {
                for x in bx * BS..((bx + 1) * BS).min(w) {
                    acc += gray[y * w + x] as u32;
                    n += 1;
                }
            }
            means[by * bw + bx] = acc / n.max(1);
        }
    }
    let mut smoothed = alloc::vec![0u32; bw * bh];
    for by in 0..bh {
        for bx in 0..bw {
            let mut acc = 0u32;
            let mut n = 0u32;
            for dy in -2i32..=2 {
                for dx in -2i32..=2 {
                    let yy = by as i32 + dy;
                    let xx = bx as i32 + dx;
                    if yy >= 0 && xx >= 0 && (yy as usize) < bh && (xx as usize) < bw {
                        acc += means[yy as usize * bw + xx as usize];
                        n += 1;
                    }
                }
            }
            smoothed[by * bw + bx] = acc / n.max(1);
        }
    }
    let mut out = alloc::vec![false; w * h];
    for y in 0..h {
        for x in 0..w {
            let t = smoothed[(y / BS) * bw + x / BS];
            out[y * w + x] = (gray[y * w + x] as u32) < t;
        }
    }
    out
}

/// quirc-based decoding (port of quirc - the decoder the reference
/// implementation uses). It takes the grayscale luma plane directly: quirc
/// does its own Otsu thresholding plus component-based grid detection, which
/// is measurably more robust on real camera frames than rqrr's detector
/// (host-verified against the synthetic degradation ladder: quircs decodes a
/// blur+noise case that rqrr rejects).
///
/// One instance should be reused across frames: `identify` keeps its
/// working buffers (a 240x320 frame needs ~154 KB for the pixel map).
pub struct QuircDecoder {
    inner: quircs::Quirc,
}

impl Default for QuircDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QuircDecoder {
    pub fn new() -> Self {
        Self {
            inner: quircs::Quirc::default(),
        }
    }

    /// Decode from the luma plane. Returns the same `ScanOutcome` shape as
    /// `decode_bits` so the console can report the two uniformly.
    pub fn decode(&mut self, w: usize, h: usize, gray: &[u8]) -> ScanOutcome {
        let codes = self.inner.identify(w, h, gray);
        let mut grids = 0usize;
        let mut payloads = Vec::new();
        let mut error = None;
        for code in codes {
            grids += 1;
            match code {
                Ok(c) => match c.decode() {
                    Ok(d) => payloads.push(String::from_utf8_lossy(&d.payload).into_owned()),
                    Err(e) => {
                        if error.is_none() {
                            error = Some(format!("{e}"));
                        }
                    }
                },
                Err(e) => {
                    if error.is_none() {
                        error = Some(format!("{e}"));
                    }
                }
            }
        }
        ScanOutcome {
            grids,
            payloads,
            error,
        }
    }
}

/// Outcome of one decode attempt over a binarized frame.
pub struct ScanOutcome {
    /// Number of QR grids the detector found.
    pub grids: usize,
    /// Decoded payloads (one per successfully decoded grid).
    pub payloads: Vec<String>,
    /// First decode error, when grids were found but none decoded.
    pub error: Option<String>,
}

/// Run rqrr's detection + decoding over a binarized frame (`bits` true = black).
pub fn decode_bits(w: usize, h: usize, bits: &[bool]) -> ScanOutcome {
    let mut img = rqrr::PreparedImage::prepare_from_bitmap(w, h, |x, y| bits[y * w + x]);
    let grids = img.detect_grids();
    let mut payloads = Vec::new();
    let mut error = None;
    for g in &grids {
        match g.decode() {
            Ok((_meta, s)) => payloads.push(s),
            Err(e) => {
                if error.is_none() {
                    error = Some(format!("{e:?}"));
                }
            }
        }
    }
    ScanOutcome {
        grids: grids.len(),
        payloads,
        error,
    }
}
