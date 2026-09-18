#!/usr/bin/env python3
"""Host preview for the forgebox product UI (D1) — render before you flash.

Renders the welcome/scan pages at the EXACT firmware coordinates, using the
same font blob as the firmware (parsed from src/ui/ui_font.c) and the same
layout constants (parsed from src/ui/ui_layout.h). Layout errors are caught on
the host with zero flash cycles (precedent: the pico2 preview caught two real
layout bugs in one pass).

Output: one PNG with both pages side by side (default /tmp/forgebox_ui_preview.png).
Falls back to ffmpeg for PNG conversion, then to leaving a PPM behind.

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
            g = FONT.get(ord(ch)) or FONT[ord("?")]
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


def label_xy(bx0: int, bx1: int, by0: int, by1: int, s: str, scale: int):
    w = Canvas.text_w(s, scale)
    h = 16 * scale
    return bx0 + (bx1 - bx0 + 1 - w) // 2, by0 + (by1 - by0 + 1 - h) // 2


def draw_common(c: Canvas, L: dict) -> None:
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

    # Footer: 3 diagnostic lines (sample content; runtime strings in firmware).
    # Sample content mirrors the firmware footer; the hash comes from git so
    # the preview stays truthful (same -dirty rule as the firmware identity).
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


def page_scan(c: Canvas, L: dict) -> None:
    c.text_center(L["UI_S_TITLE_Y"], L["UI_TXT_SCAN"], L["UI_S_TITLE_SCALE"])
    c.text_center(L["UI_S_SUB_Y"], L["UI_TXT_SCAN_SUB"], L["UI_S_SUB_SCALE"])
    c.rect_outline(L["UI_S_BOX_X0"], L["UI_S_BOX_Y0"], L["UI_S_BOX_X1"], L["UI_S_BOX_Y1"],
                   L["UI_S_BOX_T"])
    c.text_center(L["UI_S_NOTE_Y"], L["UI_TXT_SCAN_NOTE"], L["UI_S_NOTE_SCALE"])


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

    req = ["UI_FB_W", "UI_FB_H", "UI_BTN_Y0", "UI_TXT_TITLE", "UI_TXT_SCAN"]
    missing = [k for k in req if k not in L]
    if missing:
        raise SystemExit(f"layout header missing constants: {missing}")

    pages = []
    for fn in (page_welcome, page_scan):
        c = Canvas(L["UI_FB_W"], L["UI_FB_H"])
        fn(c, L)
        draw_common(c, L)
        pages.append(c)

    out = Canvas(2 * L["UI_FB_W"] + 20, L["UI_FB_H"])
    for i, c in enumerate(pages):
        ox = i * (L["UI_FB_W"] + 20)
        row_bytes = L["UI_FB_W"] * 3
        for y in range(L["UI_FB_H"]):
            src = c.buf[y * row_bytes:(y + 1) * row_bytes]
            dst0 = (y * out.w + ox) * 3
            out.buf[dst0:dst0 + row_bytes] = src

    out_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/forgebox_ui_preview.png")
    save_png(out, out_path)
    print(f"pages: welcome@{0}..{L['UI_FB_W']}  scan@{L['UI_FB_W'] + 20}..")
    print(f"buttons: L({L['UI_BTN_L_X0']},{L['UI_BTN_Y0']})-({L['UI_BTN_L_X1']},{L['UI_BTN_Y1']})"
          f"  R({L['UI_BTN_R_X0']},{L['UI_BTN_Y0']})-({L['UI_BTN_R_X1']},{L['UI_BTN_Y1']})")


if __name__ == "__main__":
    main()
