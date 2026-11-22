#!/usr/bin/env python3
"""Slow-feed XMR acceptance for the pico2 static pool.

The upstream bring-up driver feeds 38 frames at 0.2 s spacing and treats "write failed" as a
device fault. It is not one: as soon as the request is accepted the device enters the signing
stretch, the executor stalls and USB stops being serviced, so host writes fail with EIO. This
script feeds slowly, stops the moment the request is accepted, then waits out the sign and reads
the heap peak - which is the evidence the static pool exists for.

Usage: xmr_hw_slow.py [--dev /dev/ttyACM0] [--frames /tmp/xmr_2in_frames.txt] [--gap 1.2]
"""
import argparse
import os
import re
import select
import sys
import termios
import time
import tty

ap = argparse.ArgumentParser()
ap.add_argument("--dev", default="/dev/ttyACM0")
ap.add_argument("--frames", default="/tmp/xmr_2in_frames.txt")
ap.add_argument("--gap", type=float, default=1.2)
ap.add_argument("--sign-timeout", type=float, default=180.0)
ap.add_argument("--dev-entropy", default="4a9291a702c0ba28aa285882efde4f2c9237556ceb685570d595fd6586074530")
ap.add_argument("--fixed-entropy", default="77" * 32)
args = ap.parse_args()

frames = [l.strip() for l in open(args.frames) if l.strip()]
print(f"{len(frames)} frames loaded")

fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
log = []


def pump(seconds: float) -> str:
    end = time.time() + seconds
    out = b""
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                out += os.read(fd, 8192)
            except BlockingIOError:
                continue
    text = out.decode("utf-8", "replace")
    log.append(text)
    return text


def say(cmd: str, wait: float = 1.5) -> str:
    os.write(fd, (cmd + "\r").encode())
    return pump(wait)


pump(2)
print(say("version", 2).strip().splitlines()[-1:])
print(say("faultclr", 1.5).strip()[-120:])
print(say("heap reset", 2).strip().splitlines()[-1:])
say(f"entropy {args.dev_entropy}", 1.5)
say(f"xmrseed {args.fixed_entropy}", 1.5)

accepted = False
for i, fr in enumerate(frames, 1):
    try:
        os.write(fd, (fr + "\r").encode())
    except OSError as e:
        # Expected at the moment of acceptance: the sign stretch stalls the executor, so USB
        # stops being serviced and the host write fails with EIO. That IS the "signing" signal.
        print(f"frame {i}: host write failed ({e.strerror}) = device stalled into the sign")
        accepted = True
        break
    txt = pump(args.gap)
    for line in txt.splitlines():
        if any(k in line for k in ("[ur] complete", "[xmr] request", "[err]")):
            print(f"frame {i}: {line.strip()}")
        if "[xmr] request" in line:
            accepted = True
    if accepted:
        break

if not accepted:
    print("FAIL: request never accepted")
    sys.exit(10)

# The stall also takes the CDC interface down; wait for it to come back before reading the log.
try:
    os.close(fd)
except OSError:
    pass
print("waiting for the console to come back...")
deadline_port = time.time() + 120
while time.time() < deadline_port:
    if os.path.exists(args.dev):
        break
    time.sleep(1)
time.sleep(2)
try:
    fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
except OSError as e:
    print(f"FAIL: console did not come back: {e}")
    sys.exit(13)

print("request accepted; waiting for the sign (executor stalls, console silent)...")
deadline = time.time() + args.sign_timeout
signed = None
while time.time() < deadline:
    txt = pump(2.0)
    m = re.search(r"\[xmr\] signed ok: (\d+) bytes in (\d+) ms sha256=([0-9a-f]{64})", txt)
    if m:
        signed = m.groups()
        print(f"SIGNED: {m.group(0)}")
        break
    if "[err] xmr" in txt:
        print("FAIL:", [l for l in txt.splitlines() if "[err] xmr" in l])
        sys.exit(11)

if signed is None:
    print("FAIL: no signed line inside the timeout")
    sys.exit(12)

print(pump(1.5).strip()[-200:])
print(say("heap", 2.5).strip().splitlines()[-1:])
open("/tmp/p2_xmr_slow.log", "w").write("".join(log))
print("transcript: /tmp/p2_xmr_slow.log")
print("ACCEPTANCE_SIGN_OK")
