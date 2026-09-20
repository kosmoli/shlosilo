#!/usr/bin/env python3
"""MT9V034 bring-up pass on the pico2 bench firmware (first hardware run).

Provenance: 2026-09-20 session - the MT9V034 (mono global shutter) arrived;
this automates the bring-up sequence from the handover page. Wiring: see
docs/pico2-hardware-pinmap.md plus the handover wiring table (adapter pin
number = board P1 pin number 1:1; VCC from the board's 3V3 point, never
the socket's 2V8/1V2 rails).

Sequence:
  1. `version`               must report build=bench
  2. `cam sensor mt`         select MT9V034 (SCCB 0x48), re-arms capture
  3. `cam reg 0`             R0x00 chip version - expect 0x1324 (SCCB proof)
  4. `cam reinit`            two-write window config + readback line
  5. `cam reg 0x7f 0x2800`   vertical-shade test pattern ON (bit13|bit11)
  6. `cam grab 1`            per-frame byte stats
  7. `cam dump 1 0`          full-res 640x480 frame -> PGM via cam_dump.py
  8. shear measurement       row-to-row drift within one pattern period
  9. `cam reg 0x7f 0`        test pattern OFF

Interpretation: shear ~0.000 px/row = the PIO keeps up with 24 MB/s
(24 MHz PIXCLK, 1 B/px). Systematic drift (~1 px/row) = PCLK edges are
missed -> switch to column binning (R0x0D bit2 -> 12 MB/s) and re-measure.
The test-pattern period is not documented up front, so the correlation
window is a parameter (--bar, default 32 px).
"""
import argparse
import os
import subprocess
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cam_console import Console  # noqa: E402


def read_pgm(path):
    data = open(path, "rb").read()
    i = data.index(b"255\n") + 4
    hdr = data[:i].split()
    w, h = int(hdr[1]), int(hdr[2])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // w
    return body[: rows * w].reshape(rows, w).astype(float)


def shear(path, bar):
    """Mean signed drift per row (in sensor px) within +-bar/2 of zero."""
    img = read_pgm(path)
    rows, w = img.shape
    drifts = []
    for y in range(rows - 1):
        a, b = img[y], img[y + 1]
        best, bs = None, 0
        for s in range(-bar // 2, bar // 2 + 1):
            if s >= 0:
                x, z = a[s:], b[: w - s]
            else:
                x, z = a[: w + s], b[-s:]
            if len(x) < w // 2:
                continue
            d = np.abs(x - z).mean()
            if best is None or d < best:
                best, bs = d, -s
        drifts.append(bs)
    return float(np.mean(drifts)), float(np.sum(drifts)), rows


def show(out: bytes) -> str:
    text = out.decode("utf-8", "replace")
    for ln in text.splitlines():
        if any(k in ln for k in ("[cam]", "[err]", "[hb]")):
            print("  ", ln)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bar", type=int, default=32, help="correlation window (px)")
    ap.add_argument("--skip-dump", action="store_true")
    ap.add_argument("--pgm", default="/tmp/mt_bringup.pgm")
    args = ap.parse_args()

    c = Console()
    print("console:", c.dev)
    c.sync()

    print("== 1. flavor ==")
    show(c.cmd("version", 2.0))

    print("== 2. select MT9V034 ==")
    show(c.cmd("cam sensor mt", 1.5))
    show(c.cmd("cam sensor", 1.0))

    print("== 3. chip version (expect 0x1324) ==")
    show(c.cmd("cam reg 0", 1.5))

    print("== 4. init (window 640x480) ==")
    show(c.cmd("cam reinit", 3.0))

    print("== 5. test pattern ON (vertical shades) ==")
    show(c.cmd("cam reg 0x7f 0x2800", 1.5))
    show(c.cmd("cam reg 0x7f", 1.0))

    print("== 6. frame stats ==")
    show(c.cmd("cam grab 1", 10.0))

    if not args.skip_dump:
        print("== 7. dump (full res) + shear ==")
        c.close()
        dump_script = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "cam_dump.py"
        )
        r = subprocess.run(
            ["python3", dump_script, "1", "0", args.pgm],
            capture_output=True,
            text=True,
            timeout=240,
        )
        tail = r.stdout.strip().splitlines()
        print("  ", tail[-1] if tail else "(no dump output)")
        if r.returncode != 0:
            print(r.stderr.strip(), file=sys.stderr)
        else:
            try:
                mean_d, total, rows = shear(args.pgm, args.bar)
                print(
                    f"   shear: {mean_d:+.3f} px/row "
                    f"(total {total:+.0f} px over {rows} rows, bar {args.bar})"
                )
                print(
                    "   (0.000 = PIO keeps up; systematic ~1/row = PCLK edges missed "
                    "-> try R0x0D column binning)"
                )
            except Exception as e:  # noqa: BLE001
                print(f"   shear failed: {e}", file=sys.stderr)
        c = Console()
        c.sync()

    print("== 8. test pattern OFF ==")
    show(c.cmd("cam reg 0x7f 0", 1.5))
    show(c.cmd("cam reg 0x7f", 1.0))

    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
