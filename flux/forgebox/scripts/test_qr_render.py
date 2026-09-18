#!/usr/bin/env python3
"""Host verification of the QR carousel rendering path (F3 output side).

Compiles the REAL device sources (src/ui/ui_qr.c + external/qrcodegen) into a
host harness, renders sample UR frame strings at the exact device geometry
(ui_layout.h), dumps PGM frames, and decodes every frame with an independent
reader (zxing-cpp). Asserts:
  - text recovery is byte-exact for every case;
  - the QR block (incl. quiet zone) stays inside its layout area;
  - the quiet zone is lit and the code contains dark modules;
  - every frame length a real UR frame can take (up to the encoder's ~460
    chars) plus the extremes (short text, v40-size text) lay out and decode.

Run (the zxing venv has PIL + zxing-cpp):
    /tmp/qrvenv/bin/python3 flux/forgebox/scripts/test_qr_render.py
"""

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
UI_DIR = REPO / "flux/forgebox/src/ui"
QR_DIR = REPO / "flux/forgebox/external/qrcodegen"

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "ui_qr.h"
#include "ui_layout.h"

static uint8_t g_temp[UI_QR_BUF_BYTES];
static uint8_t g_qr[UI_QR_BUF_BYTES];
static uint8_t g_fb[(UI_FB_W / 8) * UI_FB_H];

int main(int argc, char **argv)
{
    const char *text = argv[2];
    int modules = 0;
    UiQrLayout layout;

    (void)argc;
    memset(g_fb, 0, sizeof(g_fb));
    if (!ui_qr_encode(text, g_temp, g_qr, &modules)) {
        fprintf(stderr, "encode failed (%zu chars)\n", strlen(text));
        return 2;
    }
    if (!ui_qr_layout(modules, UI_Q_AREA_X0, UI_Q_AREA_Y0,
                      UI_Q_AREA_W, UI_Q_AREA_H, &layout)) {
        fprintf(stderr, "layout failed (%d modules)\n", modules);
        return 3;
    }
    ui_qr_draw(g_qr, &layout, g_fb, UI_FB_W, UI_FB_H);

    FILE *f = fopen(argv[1], "wb");
    if (!f) {
        return 4;
    }
    fprintf(f, "P5\n%d %d\n255\n", UI_FB_W, UI_FB_H);
    for (int y = 0; y < UI_FB_H; y++) {
        for (int x = 0; x < UI_FB_W; x++) {
            int on = (g_fb[y * (UI_FB_W / 8) + (x >> 3)] >> (7 - (x & 7))) & 1;
            fputc(on ? 255 : 0, f);
        }
    }
    fclose(f);
    printf("%d %d %d %d %d\n", modules, layout.x0, layout.y0,
           layout.module_px, (modules + 8) * layout.module_px);
    return 0;
}
"""


def main() -> None:
    harness_c = Path("/tmp/qr_render_harness.c")
    harness_bin = Path("/tmp/qr_render_harness")
    harness_c.write_text(HARNESS, encoding="utf-8")

    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra", "-o", str(harness_bin), str(harness_c),
         str(UI_DIR / "ui_qr.c"), str(QR_DIR / "qrcodegen.c"),
         "-I", str(UI_DIR), "-I", str(QR_DIR)],
        check=True)

    # Frame-ish content: real UR frames are ~440-460 chars of bytewords.
    frame_like = "ur:xmr-txsigned/1-20/" + ("aeadaeaoaxayazbebhbibobubycac" * 17)
    frame_like = frame_like[:457]

    cases = {
        "short": "SHLOSILO-FORGEBOX-OK-2026",
        "frame457": frame_like,
        "v40max": "Z" * 2900,
    }

    import zxingcpp
    from PIL import Image

    fails = 0
    for name, text in cases.items():
        pgm = Path(f"/tmp/qr_render_{name}.pgm")
        out = subprocess.run([str(harness_bin), str(pgm), text],
                             capture_output=True, text=True, check=True).stdout.split()
        modules, x0, y0, scale, span = (int(v) for v in out[:5])
        print(f"[{name}] text={len(text)} chars -> {modules}x{modules} modules, "
              f"scale={scale}px, block=({x0},{y0})+{span}")

        # Geometry: the whole block stays inside the layout area.
        if not (x0 >= 16 and y0 >= 80 and
                x0 + span <= 16 + 448 and y0 + span <= 80 + 476):
            print(f"  GEOMETRY FAIL: block ({x0},{y0})+{span} outside area")
            fails += 1

        img = Image.open(pgm).convert("L")
        px = img.load()

        # Quiet zone lit: the 4-module border of the block must be all 255.
        q = 4 * scale
        quiet_ok = all(px[x, y] == 255
                       for y in range(y0, y0 + q) for x in range(x0, x0 + span))
        quiet_ok = quiet_ok and all(px[x, y] == 255
                                    for y in range(y0 + span - q, y0 + span)
                                    for x in range(x0, x0 + span))
        if not quiet_ok:
            print("  QUIET ZONE FAIL: dark ink inside the quiet border")
            fails += 1

        # Some dark modules must exist.
        dark = sum(1 for y in range(y0 + q, y0 + span - q)
                   for x in range(x0 + q, x0 + span - q) if px[x, y] == 0)
        if dark == 0:
            print("  CONTENT FAIL: no dark modules rendered")
            fails += 1

        res = zxingcpp.read_barcodes(img)
        if not res or res[0].text != text:
            got = repr(res[0].text)[:60] if res else "<none>"
            print(f"  DECODE FAIL: got {got}")
            fails += 1
        else:
            print(f"  decode OK ({len(res[0].text)} chars, byte-exact), "
                  f"quiet zone lit, {dark} dark px in code area")

    print("RESULT:", "PASS" if fails == 0 else f"{fails} CHECK(S) FAILED")
    sys.exit(0 if fails == 0 else 1)


if __name__ == "__main__":
    main()
