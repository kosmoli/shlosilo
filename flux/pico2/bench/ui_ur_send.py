#!/usr/bin/env python3
"""Feed a real signed-txset fixture to the pico2 UR carousel.

Reads a binary fixture, encodes it as one hex line and sends
`ui ur <hex>` over the console; the device splits it into fountain
frames and cycles them as QR codes. Then tails the console for the
carousel log.

Usage: ui_ur_send.py [fixture_path] [watch_seconds]
  default fixture: tests/fixtures/signed_txset_1in_fresh.bin (3986 B)
"""
import os
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
FIX = sys.argv[1] if len(sys.argv) > 1 else "tests/fixtures/signed_txset_1in_fresh.bin"
WATCH = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0

data = open(FIX, "rb").read()
hexstr = data.hex()
line = f"ui ur {hexstr}\n"
print(f"fixture {FIX}: {len(data)} B -> {len(hexstr)} hex chars (line cap 8192)")

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)


def drain(t=0.3):
    out = b""
    try:
        while True:
            r, _, _ = select.select([fd], [], [], t)
            if not r:
                break
            d = os.read(fd, 8192)
            if not d:
                break
            out += d
    except Exception:
        pass
    return out


drain(0.5)
os.write(fd, b"\n")
time.sleep(0.3)
drain(0.2)

# One write; the USB stack splits it into packets, the device assembles
# the line byte-by-byte (stale-line timer is 1 s of idle, far longer
# than this transfer).
os.write(fd, line.encode())
print("sent; watching carousel log (X tap on the device stops it early)")

buf = b""
end = time.time() + WATCH
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        d = os.read(fd, 8192)
        if d:
            buf += d

os.close(fd)
text = buf.decode("utf-8", "replace")
for l in text.splitlines():
    if "[ui]" in l or "[err]" in l:
        print(l)
print(f"(captured {len(buf)} bytes)")
