#!/usr/bin/env python3
"""Brute-force decode attempt: try many preprocessing × decoder combos on
the captured PGM frames and report which (if any) reads a QR.

Preprocessing tried: none, 2x/3x upscale (bilinear), unsharp mask, both.
Decoders: zxing-cpp (robust, independent) and rqrr via the Rust tool
pgm_decode (with its two binarization modes).
"""
import glob
import os
import subprocess
import sys

import numpy as np
from PIL import Image, ImageFilter, ImageOps

FRAMES = sys.argv[1:] or sorted(glob.glob('/tmp/dist_*.pgm')) + sorted(glob.glob('/tmp/fsweep_*.pgm'))


def zxing_decode(img: Image.Image):
    """zxing-cpp via the venv python (subprocess to keep this script stdlib+np)."""
    tmp = '/tmp/_zx.png'
    img.save(tmp)
    code = (
        'import zxingcpp,sys;from PIL import Image;'
        'r=zxingcpp.read_barcodes(Image.open(sys.argv[1]),try_rotate=True,try_downscale=True);'
        'print(r[0].text if r else "")'
    )
    out = subprocess.run(['/tmp/qrvenv/bin/python', '-c', code, tmp],
                         capture_output=True, text=True, timeout=60)
    return out.stdout.strip()


def rqrr_decode(path):
    out = subprocess.run(['/tmp/qrcheck/target/release/pgm_decode', path],
                         capture_output=True, text=True, timeout=60)
    text = out.stdout
    ok = 'OK' in text and 'fail' not in text.split('\n')[1] if '\n' in text else False
    return text.strip().replace('\n', ' | ')


def variants(img: Image.Image):
    yield 'none', img
    yield 'up2', img.resize((img.width * 2, img.height * 2), Image.BILINEAR)
    yield 'up3', img.resize((img.width * 3, img.height * 3), Image.BILINEAR)
    yield 'sharp', img.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=2))
    yield 'up2+sharp', img.resize((img.width * 2, img.height * 2), Image.BILINEAR).filter(
        ImageFilter.UnsharpMask(radius=2, percent=150, threshold=2))
    # contrast stretch
    yield 'autocontrast', ImageOps.autocontrast(img)


print(f'frames: {len(FRAMES)}')
hits = []
for f in FRAMES:
    if not os.path.exists(f):
        continue
    img = Image.open(f).convert('L')
    line = f'{os.path.basename(f)}:'
    for name, v in variants(img):
        try:
            z = zxing_decode(v)
        except Exception as e:
            z = f'<err {e}>'
        if z:
            line += f'  ZXING[{name}]="{z}"'
            hits.append((f, name, z))
    # rqrr on the raw file and on the up2 variant
    try:
        r = rqrr_decode(f)
        if 'OK' in r:
            line += f'  RQRR: {r[:60]}'
            hits.append((f, 'rqrr-raw', r))
    except Exception as e:
        line += f' rqrr-err:{e}'
    print(line, flush=True)

print()
if hits:
    print('=== DECODES FOUND ===')
    for f, n, t in hits:
        print(f'  {f} [{n}] -> {t}')
else:
    print('=== no decoder read any frame ===')
