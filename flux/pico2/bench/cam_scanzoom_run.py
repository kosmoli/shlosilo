#!/usr/bin/env python3
"""Run `cam scanzoom [n]` on the device and live-log every decode attempt.

One operator pose; the firmware sweeps zoom x1 -> x2 -> x3 by itself (the
crop window is centred, so the framing survives the zoom). Prints decode
hits immediately, and a per-frame diagnostics line so a near-miss is visible.

Usage: cam_scanzoom_run.py [n_frames_per_zoom] [window_secs]
"""
import glob
import os
import select
import sys
import time
import tty

N = sys.argv[1] if len(sys.argv) > 1 else "8"
WINDOW = int(sys.argv[2]) if len(sys.argv) > 2 else 240

devs = sorted(glob.glob('/dev/ttyACM*')) or sorted(glob.glob('/dev/ttyUSB*'))
if not devs:
    sys.exit('no console')
DEV = devs[0]
print('console:', DEV, flush=True)
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


def w(data, tries=60):
    for _ in range(tries):
        try:
            os.write(fd, data)
            return True
        except BlockingIOError:
            time.sleep(0.05)
    return False


drain(0.6)
w(b'\n')
time.sleep(0.3)
drain(0.3)

print(f'starting cam scanzoom {N} (zoom sweep x1 -> x2 -> x3)', flush=True)
w(f'cam scanzoom {N}\n'.encode())

t0 = time.time()
buf = b''
hits = []
decoded_lines = []
while time.time() - t0 < WINDOW:
    r, _, _ = select.select([fd], [], [], 0.4)
    if r:
        try:
            d = os.read(fd, 4096)
        except (BlockingIOError, OSError):
            continue
        if d:
            txt = d.decode('utf-8', 'replace')
            for line in txt.splitlines():
                if '[cam]' not in line:
                    continue
                el = time.time() - t0
                if 'DECODED' in line:
                    print(f'  t={el:5.1f}s *** {line}', flush=True)
                    decoded_lines.append(line)
                elif 'no decode' in line:
                    # only every 3rd diagnostics line, to keep the log readable
                    pass
                else:
                    print(f'  t={el:5.1f}s {line}', flush=True)
                if 'scanzoom done' in line:
                    print('--- scanzoom finished ---', flush=True)
                    os.close(fd)
                    if decoded_lines:
                        print()
                        print('=== DECODES ===')
                        for dl in decoded_lines:
                            print(dl)
                    else:
                        print('(no decode in this run)')
                    sys.exit(0)

os.close(fd)
print('--- window elapsed without "scanzoom done" ---')
if decoded_lines:
    print('=== DECODES ===')
    for dl in decoded_lines:
        print(dl)
else:
    print('(no decode in this run)')
