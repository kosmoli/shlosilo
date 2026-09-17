#!/usr/bin/env python3
"""Exposure sweep: switch the OV5640 to manual AEC/AGC and try several
exposure/gain settings, measuring frame sharpness for each. Long auto
exposure (the AEC saturates: measured 0x3750 = 14160) smears any hand
motion over the whole frame; a short manual exposure should sharpen it if
motion blur is the limiter.

Register map: 0x3503 bit0=AEC manual, bit1=AGC manual;
0x3500/01/02 = exposure (24-bit), 0x350A/0B = gain (16-bit).
"""
import glob
import os
import select
import subprocess
import sys
import time
import tty

import numpy as np

DEVS = sorted(glob.glob('/dev/ttyACM*')) or sorted(glob.glob('/dev/ttyUSB*'))
DEV = DEVS[0]
print('console:', DEV)


def open_fd():
    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    return fd


fd = open_fd()


def drain(t=0.3):
    out = b''
    try:
        while True:
            r, _, _ = select.select([fd], [], [], t)
            if not r:
                break
            d = os.read(fd, 4096)
            if not d:
                break
            out += d
    except Exception:
        pass
    return out


def cmd(c, wait=0.8):
    os.write(fd, (c + '\n').encode())
    deadline = time.time() + wait
    buf = b''
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            d = os.read(fd, 4096)
            if d:
                buf += d
    return buf


def rd(reg):
    out = cmd(f'cam reg 0x{reg:04x}')
    for ln in out.decode('utf-8', 'replace').splitlines():
        if '=' in ln and 'reg' in ln:
            return int(ln.split('=')[-1].strip(), 16)
    return None


def wr(reg, val):
    cmd(f'cam reg 0x{reg:04x} 0x{val:02x}', 0.5)


def set_exposure(exp24, gain16):
    wr(0x3503, 0x03)  # AEC + AGC manual
    wr(0x3500, (exp24 >> 16) & 0xFF)
    wr(0x3501, (exp24 >> 8) & 0xFF)
    wr(0x3502, exp24 & 0xFF)
    wr(0x350A, (gain16 >> 8) & 0xFF)
    wr(0x350B, gain16 & 0xFF)


def read_pgm(path):
    data = open(path, 'rb').read()
    i = data.index(b'255\n') + 4
    hdr = data[:i].split()
    w = int(hdr[1])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // w
    return body[:rows * w].reshape(rows, w).astype(float)


def lapvar(img, frac=0.7):
    h, w = img.shape
    y0, y1 = int(h * (1 - frac) / 2), int(h * (1 + frac) / 2)
    x0, x1 = int(w * (1 - frac) / 2), int(w * (1 + frac) / 2)
    c = img[y0:y1, x0:x1]
    lap = c[:-2, 1:-1] + c[2:, 1:-1] + c[1:-1, :-2] + c[1:-1, 2:] - 4 * c[1:-1, 1:-1]
    return float(lap.var()), float(c.mean()), float(c.std())


drain(0.5)
os.write(fd, b'\n')
time.sleep(0.3)
drain(0.3)

print('AEC state: 0x3503 =', hex(rd(0x3503) or 0), ' exposure =',
      hex(((rd(0x3500) or 0) << 16) | ((rd(0x3501) or 0) << 8) | (rd(0x3502) or 0)),
      ' gain =', hex(((rd(0x350A) or 0) << 8) | (rd(0x350B) or 0)))

# (label, exposure, gain)
combos = [
    ('auto', None, None),
    ('exp=0x060000 g=0x0100', 0x060000, 0x0100),
    ('exp=0x020000 g=0x0200', 0x020000, 0x0200),
    ('exp=0x008000 g=0x0400', 0x008000, 0x0400),
    ('exp=0x001000 g=0x0800', 0x001000, 0x0800),
]

for label, exp, gain in combos:
    if exp is None:
        wr(0x3503, 0x00)  # back to auto
    else:
        set_exposure(exp, gain)
    time.sleep(1.5)  # settle

    os.close(fd)
    out = subprocess.run(
        ['python3', '/home/komo/works/shlosilo-poc4/flux/pico2/bench/cam_dump.py',
         '2', '0', f'/tmp/exp_{label.split()[0]}.pgm'],
        capture_output=True, text=True, timeout=120)
    fd = open_fd()
    drain(0.5)
    p = f'/tmp/exp_{label.split()[0]}.pgm'
    if os.path.exists(p):
        img = read_pgm(p)
        v, m, s = lapvar(img)
        print(f'{label:24s}: lapvar {v:8.0f}  mean {m:5.1f}  std {s:5.1f}  -> {p}')
    else:
        print(f'{label}: capture failed ({out.stderr.strip()[:60]})')
    time.sleep(1.0)

# restore auto
wr(0x3503, 0x00)
print('restored auto exposure (0x3503=0x00)')
os.close(fd)
