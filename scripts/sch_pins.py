#!/usr/bin/env python3
"""RP2350A-Linux-Pro schematic pin forensics (text-layer coordinate method).

The vendor schematic PDF (Altium export) carries every net/pin label with
coordinates in its text layer. On each signal row, the MCU-side "GPIOxx"
label and the peripheral-side functional net label sit on the SAME y row
(within ~0.5 pt). This tool reports those pairings so pin maps can be
verified without trusting a single visual read.

Usage:
  sch_pins.py nets LCD_SCK TP_SDA CSI_D0 [...]   net -> nearest GPIO tokens
  sch_pins.py band X0 X1 Y0 Y1                   dump all tokens in a band
  sch_pins.py gpios                              list all GPIO-ish tokens

PDF path: $SCH_PDF, or the default vendor clone path below.
Requires: poppler-utils (pdftotext).
"""
import os
import re
import subprocess
import sys

DEFAULT_PDF = os.path.expanduser(
    "~/codebases/spotpear-rp2350/rp2350a-linux-pro.pdf"
)
GPIO_RE = re.compile(r"^(GPIO\d+|GP\d+|IO\d+)$")


def ensure_bbox(pdf, bbox):
    if not os.path.exists(bbox) or os.path.getmtime(bbox) < os.path.getmtime(pdf):
        subprocess.run(["pdftotext", "-bbox", pdf, bbox], check=True)
    return bbox


def load_words(bbox):
    html = open(bbox, encoding="utf-8", errors="replace").read()
    words = []
    for m in re.finditer(
        r'<word xMin="([\d.\-]+)" yMin="([\d.\-]+)" '
        r'xMax="([\d.\-]+)" yMax="([\d.\-]+)">(.*?)</word>',
        html,
        re.S,
    ):
        x1, y1, x2, y2 = (float(m.group(i)) for i in range(1, 5))
        words.append(((x1 + x2) / 2, (y1 + y2) / 2, m.group(5)))
    return words


def cmd_nets(words, nets):
    gpios = [w for w in words if GPIO_RE.match(w[2])]
    for t in nets:
        occ = [w for w in words if w[2] == t]
        if not occ:
            print(f"\n{t}: NOT FOUND")
            continue
        print(f"\n{t}: {len(occ)} occurrence(s)")
        for i, (x, y, _) in enumerate(occ):
            print(f"  occ[{i}] at ({x:.1f},{y:.1f})")
            scored = sorted(
                (((gx - x) ** 2 + (gy - y) ** 2) ** 0.5, gt, gx, gy)
                for gx, gy, gt in gpios
            )[:4]
            for d, gt, gx, gy in scored:
                print(f"      {gt:<10} ({gx:6.1f},{gy:6.1f})  d={d:.1f}")


def cmd_band(words, x0, x1, y0, y1):
    for x, y, t in sorted(words, key=lambda w: (w[1], w[0])):
        if x0 <= x <= x1 and y0 <= y <= y1:
            print(f"  y={y:6.1f} x={x:6.1f}  {t}")


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        return 1
    pdf = os.environ.get("SCH_PDF", DEFAULT_PDF)
    if not os.path.exists(pdf):
        print(f"PDF not found: {pdf} (set $SCH_PDF)", file=sys.stderr)
        return 1
    bbox = ensure_bbox(pdf, "/tmp/sch_pins.bbox.xhtml")
    words = load_words(bbox)
    mode = argv[0]
    if mode == "nets":
        cmd_nets(words, argv[1:])
    elif mode == "band":
        x0, x1, y0, y1 = (float(v) for v in argv[1:5])
        cmd_band(words, x0, x1, y0, y1)
    elif mode == "gpios":
        for x, y, t in sorted(
            (w for w in words if GPIO_RE.match(w[2])), key=lambda w: w[1]
        ):
            print(f"  {t:<10} ({x:7.1f},{y:7.1f})")
    else:
        print(__doc__)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
