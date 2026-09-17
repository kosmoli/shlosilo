//! Minimal mono UI for the pico2 rig: 1bpp canvas, ASCII 8x16 text, QR
//! rendering, and the two-button (O = confirm / X = back) touch zones.
//!
//! Design constraints (project-level, user-decided): no LVGL; minimal
//! single-colour look (fluorescent green on black); text + QR only; two
//! buttons (O confirm / X back); ASCII-only (the font subset is 95
//! glyphs, see `font.rs`).
//!
//! Layout: a 1bpp framebuffer (320x480 / 8 = 19,200 B, in .bss) is drawn
//! with cheap bit ops and flushed to the panel as RGB565 via
//! `lcd::blit_1bpp`. The bottom band is the button area: left half = X
//! (back), right half = O (confirm) - large touch targets, driven by the
//! calibrated touch mapping (`touch::to_screen`).
//!
//! QR: `qrcodegen-no-heap` (Nayuki; MIT) with two static 3918-byte
//! buffers (version-40 worst case). Rendered as dark modules on a lit
//! green block (inverted video inside the QR only) so ordinary scanners
//! see dark-on-light contrast. Validated on the host: encode + decode
//! round-trips pass for UR-like payloads up to 800 B (independent
//! decoder).
//!
//! The interactive loop is a deferred job (`ui run [secs]`); a bounded
//! window keeps the console usable between sessions.

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_time::{Instant, Timer};
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};

use crate::font::{FONT_8X16, GLYPH_W};

/// Framebuffer geometry.
pub const FB_W: usize = 320;
pub const FB_H: usize = 480;
pub const FB_STRIDE: usize = FB_W / 8;
pub const FB_BYTES: usize = FB_STRIDE * FB_H;

/// Ink colour (RGB565): fluorescent green, matching the panel test look.
pub const INK: u16 = 0x07E0;

/// Button band: rows below this are the touch zones.
pub const ZONE_Y: i32 = FB_H as i32 - 88;
/// Boundary between the X (left) and O (right) zones.
pub const ZONE_SPLIT_X: i32 = FB_W as i32 / 2;

static mut FB: [u8; FB_BYTES] = [0u8; FB_BYTES];

/// QR encode buffers (version-40 worst case, static to avoid heap churn).
const QR_BUF_LEN: usize = Version::MAX.buffer_len();
static mut QR_TMP: [u8; QR_BUF_LEN] = [0u8; QR_BUF_LEN];
static mut QR_OUT: [u8; QR_BUF_LEN] = [0u8; QR_BUF_LEN];

/// Tap counter for the last interactive run (console reads it after).
pub static TAPS: AtomicU32 = AtomicU32::new(0);

fn fb() -> &'static mut [u8; FB_BYTES] {
    // SAFETY: the UI is the single consumer of this buffer; console jobs
    // are serialized (one deferred job at a time), and nothing else
    // touches FB.
    unsafe { &mut *core::ptr::addr_of_mut!(FB) }
}

// ---------------------------------------------------------------------------
// Canvas primitives
// ---------------------------------------------------------------------------

/// Set or clear one pixel (silently ignores out-of-bounds coordinates).
pub fn px(x: i32, y: i32, ink: bool) {
    if x < 0 || y < 0 || x >= FB_W as i32 || y >= FB_H as i32 {
        return;
    }
    let (x, y) = (x as usize, y as usize);
    let idx = y * FB_STRIDE + x / 8;
    let bit = 0x80u8 >> (x % 8);
    let buf = fb();
    if ink {
        buf[idx] |= bit;
    } else {
        buf[idx] &= !bit;
    }
}

/// Fill the whole canvas.
pub fn clear(ink: bool) {
    let buf = fb();
    buf.fill(if ink { 0xFF } else { 0x00 });
}

/// Axis-aligned rectangle; `filled` = solid ink, else 1px outline.
pub fn rect(x: i32, y: i32, w: i32, h: i32, ink: bool, filled: bool) {
    if w <= 0 || h <= 0 {
        return;
    }
    if filled {
        for yy in y..y + h {
            for xx in x..x + w {
                px(xx, yy, ink);
            }
        }
    } else {
        for xx in x..x + w {
            px(xx, y, ink);
            px(xx, y + h - 1, ink);
        }
        for yy in y..y + h {
            px(x, yy, ink);
            px(x + w - 1, yy, ink);
        }
    }
}

/// Draw text at (x, y); `scale` = integer pixel multiplier (1 = 8x16).
/// Non-ASCII bytes render as '?'. Returns the x advance in pixels.
pub fn text(x: i32, y: i32, s: &str, scale: i32, ink: bool) -> i32 {
    let mut cx = x;
    for b in s.bytes() {
        let ch = if (0x20..=0x7E).contains(&b) { b } else { b'?' };
        let glyph = &FONT_8X16[(ch - 0x20) as usize];
        for (row, &bits) in glyph.iter().enumerate() {
            for col in 0..GLYPH_W {
                if bits & (0x80 >> col) != 0 {
                    if scale == 1 {
                        px(cx + col as i32, y + row as i32, ink);
                    } else {
                        rect(
                            cx + col as i32 * scale,
                            y + row as i32 * scale,
                            scale,
                            scale,
                            ink,
                            true,
                        );
                    }
                }
            }
        }
        cx += GLYPH_W as i32 * scale;
    }
    cx - x
}

/// Width of a string at the given scale.
pub fn text_w(s: &str, scale: i32) -> i32 {
    s.len() as i32 * GLYPH_W as i32 * scale
}

/// Draw text horizontally centred on the screen.
pub fn text_center(y: i32, s: &str, scale: i32, ink: bool) {
    text((FB_W as i32 - text_w(s, scale)) / 2, y, s, scale, ink);
}

// ---------------------------------------------------------------------------
// QR
// ---------------------------------------------------------------------------

/// Render `content` as a QR code centred in the area above the button
/// band: dark modules as cleared pixels on a lit green block (inverted
/// video inside the QR only, so scanners get dark-on-light contrast).
/// Picks the largest integer module scale that fits. Returns the chosen
/// (version, module size, scale) on success.
pub fn qr(content: &str) -> Result<(u8, i32, i32), ()> {
    // SAFETY: single UI consumer; the buffers are scratch for one encode.
    let (tmp, out) = unsafe {
        (
            &mut *core::ptr::addr_of_mut!(QR_TMP),
            &mut *core::ptr::addr_of_mut!(QR_OUT),
        )
    };
    let qr = QrCode::encode_text(
        content,
        tmp,
        out,
        QrCodeEcc::Low,
        Version::MIN,
        Version::MAX,
        None,
        false,
    )
    .map_err(|_| ())?;
    let size = qr.size();
    // Quiet zone: 4 modules of LIGHT (lit green) around the code per the
    // spec - the black screen behind is "dark", so the margin must be
    // drawn, not left black.
    let qz = 4;
    let total = size + 2 * qz;
    let top = 110;
    let avail_w = FB_W as i32 - 16;
    let avail_h = (ZONE_Y - 24) - top; // keep clear of the button band
    let mut scale = (avail_w / total).min(avail_h / total);
    if scale < 1 {
        scale = 1;
    }
    let dim = total * scale;
    let bx = (FB_W as i32 - dim) / 2;
    let by = top + (avail_h - dim) / 2;
    // Lit block behind the code (quiet zone included).
    rect(bx, by, dim, dim, true, true);
    // Dark modules: clear pixels.
    for my in 0..size {
        for mx in 0..size {
            if qr.get_module(mx, my) {
                let px_x = bx + (mx + qz) * scale;
                let px_y = by + (my + qz) * scale;
                rect(px_x, px_y, scale, scale, false, true);
            }
        }
    }
    Ok((qr.version().value(), size, scale))
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Welcome,
    Detail,
    Qr,
}

#[derive(Clone, Copy)]
pub enum Action {
    Ok,
    Back,
}

impl Page {
    /// The page reached from `self` under `action` (X on the welcome page
    /// stays put).
    pub fn step(self, action: Action) -> Page {
        match (self, action) {
            (Page::Welcome, Action::Ok) => Page::Detail,
            (Page::Welcome, Action::Back) => Page::Welcome,
            (Page::Detail, Action::Ok) => Page::Qr,
            (Page::Detail, Action::Back) => Page::Welcome,
            (Page::Qr, Action::Ok) => Page::Welcome,
            (Page::Qr, Action::Back) => Page::Detail,
        }
    }
}

/// Demo payload for the QR page (a UR-shaped string).
const DEMO_UR: &str = "ur:xmr-txunsigned/hdclaxisyagdbdhsvarersbykegssnhesonthdetkokklomsprldoseymnpansbnwynyioaahdcxaorptnpmcmdibgcevegaetftloemsfhphdcflkswfsgmdyidchkndyprswsnfewpaycysssefxgwamtaaddyoeadlecsdwykaeykaeykaewkaewkaxahaemnvsmn";

/// Orientation reference pattern (bring-up tool). Renders the four edge
/// labels UP / DOWN / LEFT / RIGHT plus an asymmetric "L" marker at the
/// top-left corner and a centre crosshair.
///
/// Purpose: the person holding the panel must be able to *read off* which
/// physical edge is which, so that instructions like "swipe from the LEFT
/// label to the RIGHT label" are unambiguous regardless of how the board
/// is held - and so that any display mirror/flip is immediately visible
/// (mirrored lettering reads backwards; a 180-degree flip puts DOWN at
/// the top). Directions for touch calibration are always given in terms
/// of these labels, never in terms of an assumed physical frame.
pub fn orientation_pattern() {
    clear(false);
    // Border frame.
    rect(0, 0, FB_W as i32, FB_H as i32, true, false);
    // Edge labels.
    text_center(10, "UP", 1, true);
    text_center(FB_H as i32 - 26, "DOWN", 1, true);
    text(10, FB_H as i32 / 2 - 8, "LEFT", 1, true);
    let rw = text_w("RIGHT", 1);
    text(FB_W as i32 - rw - 10, FB_H as i32 / 2 - 8, "RIGHT", 1, true);
    // Asymmetric "L" marker at the top-left: block + bar to the right +
    // bar downward. Mirrored or flipped lettering also mirrors/flips it,
    // which is a second, independent orientation check.
    rect(24, 44, 16, 16, true, true);
    rect(42, 48, 40, 8, true, true);
    rect(28, 62, 8, 40, true, true);
    // Centre crosshair.
    rect(FB_W as i32 / 2 - 14, FB_H as i32 / 2, 29, 1, true, true);
    rect(FB_W as i32 / 2, FB_H as i32 / 2 - 14, 1, 29, true, true);
    flush();
}

/// Status line shared by all pages (top-left, small).
fn draw_status() {
    text(4, 4, "shlosilo", 1, true);
    let ver = "pico2";
    text(FB_W as i32 - text_w(ver, 1) - 4, 4, ver, 1, true);
    rect(0, 22, FB_W as i32, 1, true, true);
}

/// The two button zones: big glyphs, split line, and a hint line.
fn draw_zones(ok_label: &str, back_label: &str) {
    rect(0, ZONE_Y - 2, FB_W as i32, 1, true, true);
    rect(ZONE_SPLIT_X, ZONE_Y, 1, FB_H as i32 - ZONE_Y, true, true);
    // Big glyphs (scale 3) roughly centred in each zone.
    let gy = ZONE_Y + 8;
    text(ZONE_SPLIT_X / 2 - 12, gy, "X", 3, true);
    text(ZONE_SPLIT_X + ZONE_SPLIT_X / 2 - 12, gy, "O", 3, true);
    // Labels under the glyphs.
    let lx = (ZONE_SPLIT_X - text_w(back_label, 1)) / 2;
    text(lx, ZONE_Y + 62, back_label, 1, true);
    let ox = ZONE_SPLIT_X + (ZONE_SPLIT_X - text_w(ok_label, 1)) / 2;
    text(ox, ZONE_Y + 62, ok_label, 1, true);
}

/// UR carousel: render ONE animation frame. Same geometry as the QR page
/// plus a frame-counter line; the X zone stops the carousel, the O zone
/// is inert (label left blank).
///
/// Used by the `ui ur` job: the payload is split by the core's
/// `UrMultipartEncoder` (fountain frames, 200 B fragments) and each frame
/// is drawn briefly, cycling - which is how anything larger than a single
/// QR can be handed to a scanning wallet (a 3458-byte XMR signature is
/// well past the ~2953-byte single-frame v40/ECC-L ceiling).
pub fn qr_carousel_frame(content: &str, seq: usize, total: usize) -> Result<(), ()> {
    clear(false);
    draw_status();
    {
        let mut buf = [0u8; 32];
        let mut w = crate::sign_smoke::BufWriter::new(&mut buf);
        let _ = write!(w, "UR frame {seq}/{total}");
        text_center(40, w.as_str(), 1, true);
    }
    qr(content)?;
    draw_zones("", "exit");
    flush();
    Ok(())
}

/// Draw a page into the framebuffer (no flush).
pub fn draw(page: Page, qr_text: Option<&str>) -> Result<(), ()> {
    clear(false);
    draw_status();
    match page {
        Page::Welcome => {
            text_center(120, "SHLOSILO", 3, true);
            text_center(180, "pico2 ui base", 1, true);
            text_center(240, "XMR / BTC / ETH signer", 1, true);
            draw_zones("continue", "back");
        }
        Page::Detail => {
            text(8, 40, "XMR transaction", 1, true);
            rect(8, 60, FB_W as i32 - 16, 1, true, true);
            let rows = [
                ("amount", "0.000270000000 XMR"),
                ("fee", "0.000012340000 XMR"),
                ("inputs", "2"),
                ("to", "4844Nk4X..."),
            ];
            let mut y = 80;
            for (k, v) in rows {
                text(8, y, k, 1, true);
                text(120, y, v, 1, true);
                y += 26;
            }
            rect(8, 200, FB_W as i32 - 16, 1, true, true);
            text(8, 216, "verify on device", 1, true);
            draw_zones("sign", "back");
        }
        Page::Qr => {
            text_center(40, "scan with wallet", 1, true);
            let content = qr_text.unwrap_or(DEMO_UR);
            qr(content)?;
            draw_zones("next", "back");
        }
    }
    Ok(())
}

/// Flush the framebuffer to the panel (full frame, ~50 ms).
pub fn flush() {
    let buf = fb();
    crate::panel::with_panel(|p| {
        p.lcd.blit_1bpp(buf, FB_STRIDE, FB_H, FB_W, INK);
    });
}

/// Draw + flush one page.
pub fn show(page: Page, qr_text: Option<&str>) -> Result<(), ()> {
    draw(page, qr_text)?;
    flush();
    Ok(())
}

// ---------------------------------------------------------------------------
// Interactive loop (deferred console job)
// ---------------------------------------------------------------------------

/// Poll interval: fast enough for button feel, light enough for the
/// bit-banged touch transport.
const POLL_MS: u64 = 40;

/// Interactive demo: poll the touch, switch pages on O/X zone taps, and
/// stop after `secs`. Returns the number of accepted taps.
pub async fn run(secs: u32) -> u32 {
    TAPS.store(0, Ordering::Relaxed);
    let mut page = Page::Welcome;
    if show(page, None).is_err() {
        log::info!("[err] ui: QR encode failed on the welcome path");
    }
    let t0 = Instant::now();
    let mut was_down = false;
    let mut taps = 0u32;
    log::info!("[ui] interactive for {secs}s: tap X (left) / O (right); start page = welcome");
    while (Instant::now() - t0).as_secs() < u64::from(secs) {
        Timer::after_millis(POLL_MS).await;
        let pt = crate::panel::with_panel(|p| p.touch.read_point());
        let Some(Ok(pt)) = pt else { continue };
        let down = pt.fingers > 0;
        if down && !was_down {
            // Edge: one action per press.
            let (sx, sy) = crate::touch::to_screen(pt.x, pt.y);
            if sy as i32 >= ZONE_Y {
                let action = if (sx as i32) < ZONE_SPLIT_X {
                    Action::Back
                } else {
                    Action::Ok
                };
                page = page.step(action);
                taps += 1;
                TAPS.store(taps, Ordering::Relaxed);
                let name = match page {
                    Page::Welcome => "welcome",
                    Page::Detail => "detail",
                    Page::Qr => "qr",
                };
                log::info!(
                    "[ui] tap #{taps} at ({sx},{sy}) -> {} -> page {name}",
                    match action {
                        Action::Ok => "O",
                        Action::Back => "X",
                    }
                );
                if show(page, None).is_err() {
                    log::info!("[err] ui: QR encode failed");
                }
            }
        }
        was_down = down;
    }
    log::info!("[ui] done: {taps} tap(s)");
    taps
}
