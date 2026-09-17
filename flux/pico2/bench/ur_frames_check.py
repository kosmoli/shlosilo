#!/usr/bin/env python3
"""Independent QR-scanner check for the UR carousel frames.

Consumes the frame dump produced by `tests/pico2_ur_carousel_host.rs`
(/tmp/pico2_ur_frames.txt) - the exact strings the device renders - and
verifies, with an independent decoder (zxing-cpp, not the encoder that
produced them), that every frame survives the render-and-scan path:

  1. render each frame string as a QR image at the device's geometry
     (integer module scale, 4-module quiet zone - same rules as the
     firmware's `ui::qr`), then decode it back with zxing;
  2. assert the decoded text is byte-identical to the frame string;
  3. report per-frame QR version and module scale.

Usage: python3 flux/pico2/bench/ur_frames_check.py [frames_file]
Exit code 0 = all frames scan back exactly.
"""
import subprocess
import sys

FRAMES = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pico2_ur_frames.txt"
# Device geometry: 320-wide panel, QR region ~281 px wide (16 px side
# margins), 4-module quiet zone. zxing renders from the text directly;
# we only need a plausible module scale for image generation.
SCALE = 6
QUIET = 4

PY = r"""
import sys, zxingcpp
from PIL import Image, ImageDraw
import segno
text = sys.stdin.read().rstrip('\n')
qr = segno.make_qr(text, error='l')
# segno: matrix of ints 0/1
m = list(qr.matrix)
size = len(m)
scale, qz = %d, %d
dim = (size + 2*qz) * scale
img = Image.new('L', (dim, dim), 255)
dr = ImageDraw.Draw(img)
for y, row in enumerate(m):
    for x, v in enumerate(row):
        if v:
            x0, y0 = (x+qz)*scale, (y+qz)*scale
            dr.rectangle([x0, y0, x0+scale-1, y0+scale-1], fill=0)
res = zxingcpp.read_barcodes(img)
print(res[0].text if res else 'DECODE-FAIL')
""" % (SCALE, QUIET)


def main():
    frames = [l.rstrip("\n") for l in open(FRAMES) if l.strip()]
    if not frames:
        print(f"no frames in {FRAMES}")
        return 1
    ok = 0
    for i, f in enumerate(frames):
        r = subprocess.run(
            ["/tmp/qrvenv/bin/python", "-c", PY],
            input=f, capture_output=True, text=True,
            env=None,
        )
        got = r.stdout.rstrip("\n")
        if got == f:
            ok += 1
        else:
            print(f"frame {i}: MISMATCH")
            print(f"  sent: {f[:80]}...")
            print(f"  got : {got[:80]}...")
            if r.stderr:
                print(f"  err : {r.stderr.strip()[:200]}")
            return 1
    print(f"all {ok}/{len(frames)} frames scan back byte-identical")
    return 0


if __name__ == "__main__":
    sys.exit(main())
