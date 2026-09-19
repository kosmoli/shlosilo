#!/usr/bin/env python3
"""Host preview for the forgebox product UI - render before you flash.

Renders the welcome / scan / payload pages at the EXACT firmware coordinates,
using the same font blob as the firmware (parsed from src/ui/ui_font.c) and the
same layout constants (parsed from src/ui/ui_layout.h). Layout errors are
caught on the host with zero flash cycles (precedent: the pico2 preview caught
two real layout bugs in one pass).

Output: one PNG with all three pages side by side (default
/tmp/forgebox_ui_preview.png). Falls back to ffmpeg, then to a PPM.

Usage:
    python3 flux/forgebox/scripts/preview_ui.py [out.png]
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
UI_DIR = REPO / "flux/forgebox/src/ui"
FONT_C = UI_DIR / "ui_font.c"
LAYOUT_H = UI_DIR / "ui_layout.h"

INK = (0x00, 0xFF, 0x00)
BG = (0x00, 0x00, 0x00)

# Sample content for the scan page live lines (mirrors real firmware values).
SCAN_SAMPLE = {
    "status": "scanning...",
    "info": ["frames=123", "cam 43 dec 45 vR 53 vW 0 ms", "focus 51 res 0"],
}

# Payload sample: exercises word wrap, a hard-break token and a newline.
PAYLOAD_SAMPLE = (
    ("SHLOSILO-FORGEBOX-OK-2026 " * 6)
    + "\n"
    + "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmay"
    + "mwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxad"
    + "aaadrpceaadt"
)


def parse_font(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    glyphs = {}
    pat = re.compile(
        r"\{\s*((?:0x[0-9A-Fa-f]{2}\s*,\s*)*0x[0-9A-Fa-f]{2})\s*\}\s*,"
        r"\s*/\*\s*0x([0-9A-Fa-f]{2})\s*\*/"
    )
    for m in pat.finditer(text):
        data = bytes(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{2})", m.group(1)))
        if len(data) != 16:
            raise SystemExit(f"bad glyph 0x{m.group(2)}: {len(data)} bytes")
        glyphs[int(m.group(2), 16)] = data
    if len(glyphs) != 95:
        raise SystemExit(f"expected 95 glyphs, parsed {len(glyphs)}")
    return glyphs


def parse_layout(path: Path) -> dict:
    """Parse `#define NAME <int|"string">` lines."""
    layout = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r'\s*#define\s+([A-Z0-9_]+)\s+(.+?)\s*$', line)
        if not m:
            continue
        name, raw = m.group(1), m.group(2).strip()
        if raw.startswith('"') and raw.endswith('"'):
            layout[name] = raw[1:-1]
        else:
            try:
                layout[name] = int(raw, 0)
            except ValueError:
                pass  # expression or function-like define; not needed here
    return layout


def git_hash() -> str:
    """Current commit, with the same -dirty suffix rule as the firmware."""
    try:
        h = subprocess.run(["git", "rev-parse", "--short=7", "HEAD"],
                           cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain"],
                               cwd=REPO, capture_output=True, text=True, check=True).stdout.strip()
        return f"{h}-dirty" if dirty else h
    except Exception:
        return "nogit"


class Canvas:
    def __init__(self, w: int, h: int):
        self.w, self.h = w, h
        self.buf = bytearray(w * h * 3)

    def _blit(self, x: int, y: int):
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 3
            self.buf[i] = INK[0]
            self.buf[i + 1] = INK[1]
            self.buf[i + 2] = INK[2]

    def toggle(self, x: int, y: int):
        """XOR a pixel (the firmware's toggle_px)."""
        if 0 <= x < self.w and 0 <= y < self.h:
            i = (y * self.w + x) * 3
            if self.buf[i] or self.buf[i + 1] or self.buf[i + 2]:
                self.buf[i] = self.buf[i + 1] = self.buf[i + 2] = 0
            else:
                self.buf[i], self.buf[i + 1], self.buf[i + 2] = INK

    def fill_rect(self, x0: int, y0: int, x1: int, y1: int):
        for y in range(y0, y1 + 1):
            for x in range(x0, x1 + 1):
                self._blit(x, y)

    def rect_outline(self, x0: int, y0: int, x1: int, y1: int, t: int = 1):
        for k in range(t):
            for x in range(x0 + k, x1 - k + 1):
                self._blit(x, y0 + k)
                self._blit(x, y1 - k)
            for y in range(y0 + k, y1 - k + 1):
                self._blit(x0 + k, y)
                self._blit(x1 - k, y)

    def text(self, x: int, y: int, s: str, scale: int) -> int:
        for ch in s:
            o = ord(ch)
            g = FONT.get(o if 0x20 <= o <= 0x7E else ord("?")) or FONT[ord("?")]
            for row in range(16):
                bits = g[row]
                for col in range(8):
                    if bits & (0x80 >> col):
                        for dy in range(scale):
                            for dx in range(scale):
                                self._blit(x + col * scale + dx, y + row * scale + dy)
            x += 8 * scale
        return x

    @staticmethod
    def text_w(s: str, scale: int) -> int:
        return 8 * scale * len(s)

    def text_center(self, y: int, s: str, scale: int) -> None:
        x = (self.w - self.text_w(s, scale)) // 2
        check(x >= 0 and x + self.text_w(s, scale) <= self.w,
              f"text overflows horizontally: {s!r}")
        self.text(x, y, s, scale)


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise SystemExit(f"LAYOUT ERROR: {msg}")


def label_xy(bx0: int, bx1: int, by0: int, by1: int, s: str, scale: int):
    w = Canvas.text_w(s, scale)
    h = 16 * scale
    return bx0 + (bx1 - bx0 + 1 - w) // 2, by0 + (by1 - by0 + 1 - h) // 2


def draw_common(c: Canvas, L: dict, with_footer: bool = True) -> None:
    # Buttons: outlined rect + centered text label.
    for x0, x1, label in (
        (L["UI_BTN_L_X0"], L["UI_BTN_L_X1"], L["UI_BTN_LABEL_LEFT"]),
        (L["UI_BTN_R_X0"], L["UI_BTN_R_X1"], L["UI_BTN_LABEL_RIGHT"]),
    ):
        c.rect_outline(x0, L["UI_BTN_Y0"], x1, L["UI_BTN_Y1"], L["UI_BTN_T"])
        lx, ly = label_xy(x0, x1, L["UI_BTN_Y0"], L["UI_BTN_Y1"],
                          label, L["UI_BTN_LABEL_SCALE"])
        check(lx >= x0 and lx + Canvas.text_w(label, L["UI_BTN_LABEL_SCALE"]) <= x1 + 1,
              f"button label {label!r} does not fit its button")
        c.text(lx, ly, label, L["UI_BTN_LABEL_SCALE"])

    # Separator above the button band.
    c.fill_rect(L["UI_LINE_X0"], L["UI_LINE_Y"], L["UI_LINE_X1"], L["UI_LINE_Y"])

    if not with_footer:
        return  # the scan page uses this strip for its status/info lines

    # Footer: 3 diagnostic lines (sample content; runtime strings in firmware).
    foot = [
        (L["UI_FOOTER_L1_Y"], f"fw v1.0.0 {git_hash()}"),
        (L["UI_FOOTER_L2_Y"], "touch 0x38 ok=1"),
        (L["UI_FOOTER_L3_Y"], "last: continue -> scan (240,744)"),
    ]
    for y, line in foot:
        check(Canvas.text_w(line, 1) <= L["UI_FB_W"] - 2 * L["UI_FOOTER_X"],
              f"footer line too long: {line!r}")
        c.text(L["UI_FOOTER_X"], y, line, 1)


def page_welcome(c: Canvas, L: dict) -> None:
    c.text_center(L["UI_W_TITLE_Y"], L["UI_TXT_TITLE"], L["UI_W_TITLE_SCALE"])
    c.text_center(L["UI_W_SUB_Y"], L["UI_TXT_SUB"], L["UI_W_SUB_SCALE"])
    c.text_center(L["UI_W_BIG_Y"], L["UI_TXT_BIG"], L["UI_W_BIG_SCALE"])
    c.text_center(L["UI_W_HINT_Y"], L["UI_TXT_HINT"], L["UI_W_HINT_SCALE"])


def fake_qr_matrix(n: int = 21):
    """A deterministic 21x21 QR-like matrix (finder patterns + noise fill)."""
    m = [[False] * n for _ in range(n)]
    seed = 20260918

    def rnd():
        nonlocal seed
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        return seed

    for r in range(n):
        for c in range(n):
            if rnd() % 2 == 0:
                m[r][c] = True

    def finder(r0, c0):
        for r in range(7):
            for c in range(7):
                ring = r in (0, 6) or c in (0, 6)
                core = 2 <= r <= 4 and 2 <= c <= 4
                m[r0 + r][c0 + c] = ring or core

    finder(0, 0)
    finder(0, n - 7)
    finder(n - 7, 0)
    return m


def page_scan(c: Canvas, L: dict) -> None:
    c.text_center(L["UI_S_TITLE_Y"], L["UI_TXT_SCAN"], L["UI_S_TITLE_SCALE"])
    c.text_center(L["UI_S_SUB_Y"], L["UI_TXT_SCAN_SUB"], L["UI_S_SUB_SCALE"])
    c.rect_outline(L["UI_S_BOX_X0"], L["UI_S_BOX_Y0"], L["UI_S_BOX_X1"], L["UI_S_BOX_Y1"],
                   L["UI_S_BOX_T"])

    # Mock binarized camera frame: the firmware rotates the sensor frame 90
    # deg CCW into a PORTRAIT area (240x320), then stamps speckle + QR + reticle.
    x0, y0 = L["UI_S_PV_X0"], L["UI_S_PV_Y0"]
    w, h = L["UI_S_PV_W"], L["UI_S_PV_H"]
    seed = 987654321
    for yy in range(h):
        for xx in range(w):
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
            if seed % 100 < 2:                      # ~2% speckle (sensor noise)
                c._blit(x0 + xx, y0 + yy)

    m = fake_qr_matrix()
    scale = 8
    qs = 21 * scale
    qx = x0 + (w - qs) // 2
    qy = y0 + (h - qs) // 2
    for r in range(21):
        for col in range(21):
            if m[r][col]:
                c.fill_rect(qx + col * scale, qy + r * scale,
                            qx + col * scale + scale - 1, qy + r * scale + scale - 1)

    # Centering reticle (XOR dashes, same as the firmware).
    cx, cy = x0 + w // 2, y0 + h // 2
    for d in range(4, 29):
        c.toggle(cx - d, cy)
        c.toggle(cx + d, cy)
        c.toggle(cx, cy - d)
        c.toggle(cx, cy + d)

    # 1px frame marking the camera view area.
    c.rect_outline(x0 - 1, y0 - 1, x0 + w, y0 + h, 1)

    # Status + info strip BELOW the box (the footer yields this area on this
    # page, mirroring the firmware).
    c.text_center(L["UI_S_STATUS_Y"], SCAN_SAMPLE["status"], L["UI_S_STATUS_SCALE"])
    for y_key, line in zip(("UI_S_INFO1_Y", "UI_S_INFO2_Y", "UI_S_INFO3_Y"),
                           SCAN_SAMPLE["info"]):
        if line:
            c.text_center(L[y_key], line, 1)


def wrap_payload(text: str, chars: int, max_lines: int):
    """Mirror of the firmware wrap (src/ui/ui_wrap.c::ui_wrap_text).

    Keep this in lockstep with the C implementation and cross-check with
    scripts/test_wrap.py (C vs Python diff) before flashing.
    """
    lines = []
    pos = 0
    n = len(text)
    while pos < n and len(lines) < max_lines:
        end = pos
        last_space = 0
        limit = pos + chars
        nl = False
        while end < n and end < limit:
            ch = text[end]
            if ch in "\n\r":
                nl = True
                break
            end += 1
            if ch == " ":
                last_space = end
        if nl:
            lines.append(text[pos:end])
            pos = end + 1
            while pos < n and text[pos] in "\n\r":
                pos += 1
        else:
            emit_end = end
            if end < n and last_space > pos:
                emit_end = last_space
            lines.append(text[pos:emit_end])
            pos = emit_end
    truncated = pos < n
    return lines, truncated


def page_payload(c: Canvas, L: dict) -> None:
    c.text_center(L["UI_P_TITLE_Y"], L["UI_TXT_RESULT"], L["UI_P_TITLE_SCALE"])
    c.text_center(L["UI_P_INFO_Y"], f"{len(PAYLOAD_SAMPLE)} chars", 1)

    lines, truncated = wrap_payload(PAYLOAD_SAMPLE, L["UI_P_CHARS_PER_LINE"],
                                    L["UI_P_MAX_LINES"])
    y = L["UI_P_TEXT_Y0"]
    for line in lines:
        c.text(L["UI_P_TEXT_X"], y, line, 1)
        y += L["UI_P_LINE_H"]
    if truncated:
        c.text(L["UI_P_TEXT_X"], y, "...", 1)
    print(f"payload wrap: {len(lines)} lines, truncated={truncated}")


def save_png(c: Canvas, out_path: Path) -> None:
    ppm = out_path.with_suffix(".ppm")
    with open(ppm, "wb") as f:
        f.write(b"P6\n%d %d\n255\n" % (c.w, c.h))
        f.write(bytes(c.buf))
    try:
        from PIL import Image  # noqa: WPS433 (optional dependency)
        Image.frombytes("RGB", (c.w, c.h), bytes(c.buf)).save(out_path)
        print(f"PNG (PIL)      -> {out_path}")
        return
    except ImportError:
        pass
    ff = shutil.which("ffmpeg")
    if ff:
        subprocess.run([ff, "-y", "-loglevel", "error", "-i", str(ppm), str(out_path)],
                       check=True)
        print(f"PNG (ffmpeg)   -> {out_path}")
        return
    print(f"no PIL/ffmpeg; PPM left at {ppm}")


def main() -> None:
    global FONT
    FONT = parse_font(FONT_C)
    L = parse_layout(LAYOUT_H)

    req = ["UI_FB_W", "UI_FB_H", "UI_BTN_Y0", "UI_TXT_TITLE", "UI_TXT_SCAN",
           "UI_S_STATUS_Y", "UI_S_INFO1_Y", "UI_P_TEXT_X",
           "UI_P_TEXT_Y0", "UI_P_CHARS_PER_LINE"]
    missing = [k for k in req if k not in L]
    if missing:
        raise SystemExit(f"layout header missing constants: {missing}")

    pages = []
    for fn in (page_welcome, page_scan, page_payload):
        c = Canvas(L["UI_FB_W"], L["UI_FB_H"])
        fn(c, L)
        draw_common(c, L, with_footer=(fn is not page_scan))
        pages.append(c)

    gap = 20
    out = Canvas(len(pages) * L["UI_FB_W"] + (len(pages) - 1) * gap, L["UI_FB_H"])
    for i, c in enumerate(pages):
        ox = i * (L["UI_FB_W"] + gap)
        row_bytes = L["UI_FB_W"] * 3
        for y in range(L["UI_FB_H"]):
            src = c.buf[y * row_bytes:(y + 1) * row_bytes]
            dst0 = (y * out.w + ox) * 3
            out.buf[dst0:dst0 + row_bytes] = src

    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/forgebox_ui_preview.png")
    save_png(out, out_path)
    print(f"pages: welcome / scan / payload, buttons L({L['UI_BTN_L_X0']},{L['UI_BTN_Y0']})"
          f"-({L['UI_BTN_L_X1']},{L['UI_BTN_Y1']}) R({L['UI_BTN_R_X0']},{L['UI_BTN_Y0']})"
          f"-({L['UI_BTN_R_X1']},{L['UI_BTN_Y1']})")


if __name__ == "__main__":
    main()
