#!/usr/bin/env python3
"""Verify the digital-zoom (crop window) implementation is sane:
capture at zoom 1 and zoom 2 and compare - zoom 2 must be a magnified
central crop of the same scene, and both must be uncorrupted images.
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
if not DEVS:
    sys.exit('no console')
DEV = DEVS[0]
print('console:', DEV)
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


def w(b, tries=60):
    for _ in range(tries):
        try:
            os.write(fd, b)
            return True
        except BlockingIOError:
            time.sleep(0.05)
    return False


def cmd(c, wait=1.5):
    w(c.encode() + b'\n')
    deadline = time.time() + wait
    buf = b''
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                d = os.read(fd, 4096)
            except (BlockingIOError, OSError):
                continue
            if d:
                buf += d
    for ln in buf.decode('utf-8', 'replace').splitlines():
        if '[cam]' in ln or '[err]' in ln:
            print('  ', ln)
    return buf


def read_pgm(path):
    data = open(path, 'rb').read()
    i = data.index(b'255\n') + 4
    hdr = data[:i].split()
    ww = int(hdr[1])
    body = np.frombuffer(data[i:], dtype=np.uint8)
    rows = body.size // ww
    return body[:rows * ww].reshape(rows, ww).astype(float)


def grab(path, stride='2'):
    os.close(fd) if False else None
    r = subprocess.run(
        ['python3', '/home/komo/works/shlosilo-poc4/flux/pico2/bench/cam_dump.py',
         stride, '0', path],
        capture_output=True, text=True, timeout=150)
    return os.path.exists(path), r.stdout.strip().splitlines()[-1] if r.stdout else ''


drain(0.5)
w(b'\n')
time.sleep(0.3)
drain(0.3)

print('== ensure clean state: zoom 1 ==')
cmd('cam zoom 1', 1.5)
time.sleep(2.0)

print('== capture at zoom 1 ==')
ok1, msg1 = grab('/tmp/z1.pgm')
print('  ', msg1)

print('== set zoom 2 ==')
cmd('cam zoom 2', 1.5)
time.sleep(2.5)  # AEC settle

print('== capture at zoom 2 ==')
ok2, msg2 = grab('/tmp/z2.pgm')
print('  ', msg2)

if ok1 and ok2:
    a = read_pgm('/tmp/z1.pgm')
    b = read_pgm('/tmp/z2.pgm')
    print(f'zoom1: {a.shape} mean {a.mean():.1f} std {a.std():.1f}')
    print(f'zoom2: {b.shape} mean {b.mean():.1f} std {b.std():.1f}')
    # If zoom2 is a true central crop, its central region should correlate
    # with the central region of zoom1 (allowing for AEC differences).
    h, wd = a.shape
    c1 = a[h // 4: 3 * h // 4, wd // 4: 3 * wd // 4]
    c2 = b[h // 4: 3 * h // 4, wd // 4: 3 * wd // 4]
    if c1.std() > 1 and c2.std() > 1:
        corr = np.corrcoef(c1.ravel(), c2.ravel())[0, 1]
        print(f'central-region correlation zoom1 vs zoom2: {corr:+.3f}')
        print('(a true zoom should give a HIGH correlation of the central area)')
    # save side-by-side for visual check
    from PIL import Image
    side = np.concatenate([a, np.full((h, 4), 128.0), b], axis=1)
    Image.fromarray(side.astype(np.uint8)).resize(
        (side.shape[1] * 3, side.shape[0] * 3), Image.LANCZOS).save('/tmp/zoom_compare.png')
    print('saved /tmp/zoom_compare.png (zoom1 | zoom2)')

os.close(fd)
