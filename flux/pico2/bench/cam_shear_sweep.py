#!/usr/bin/env python3
"""Measure the capture shear vs XCLK using the OV5640 internal color-bar
test pattern (enabled separately via `cam reg 0x503d 0x80`).

The bars are 30 px wide (strong edges every 2 bars = 60 px). If the capture
is sound, each row shows the same bar phase; a PIO that misses PCLK edges
shifts each row progressively. We measure the row-to-row phase drift by
cross-correlating consecutive rows within one bar period (30 px).
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
fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)


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


def cmd(c, wait=1.0):
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


def read_pgm(path):
    data = open(path, 'rb').read()
    i = data.index(b'255\n') + 4
    hdr = data[:i].split()
    w, h = int(hdr[1]), int(hdr[2])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // w
    return body[:rows * w].reshape(rows, w).astype(float)


def shear(path, bar=30):
    """Mean signed drift per row (in sensor px), measured within one bar."""
    img = read_pgm(path)
    rows, w = img.shape
    drifts = []
    for y in range(rows - 1):
        a, b = img[y], img[y + 1]
        best, bs = None, 0
        for s in range(-bar // 2, bar // 2 + 1):
            if s >= 0:
                x, z = a[s:], b[:w - s]
            else:
                x, z = a[:w + s], b[-s:]
            if len(x) < w // 2:
                continue
            d = np.abs(x - z).mean()
            if best is None or d < best:
                best, bs = d, -s
        drifts.append(bs)
    return float(np.mean(drifts)), float(np.sum(drifts)), rows


drain(0.5)
os.write(fd, b'\n')
time.sleep(0.3)
drain(0.3)

print('== enabling OV5640 color-bar test pattern ==')
cmd('cam reg 0x503d 0x80', 1.0)
cmd('cam reg 0x503d', 0.8)

# make sure the sensor is streaming normally before the sweep
cmd('cam xclk 10000', 0.8)

for khz in [3000, 6000, 8000, 10000, 12000]:
    cmd(f'cam xclk {khz}', 1.0)
    time.sleep(1.5)  # AEC settle
    fd_backup = fd
    os.close(fd)
    out = subprocess.run(
        ['python3', '/home/komo/works/shlosilo-poc4/flux/pico2/bench/cam_dump.py',
         '2', '0', f'/tmp/shear_{khz}.pgm'],
        capture_output=True, text=True, timeout=120)
    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    drain(0.5)
    try:
        mean_d, total, rows = shear(f'/tmp/shear_{khz}.pgm')
        print(f'XCLK {khz/1000:5.1f} MHz: shear {mean_d:+.3f} px/row '
              f'(total {total:+.0f} px over {rows} rows)')
    except Exception as e:
        print(f'XCLK {khz}: failed: {e}')

os.close(fd)
