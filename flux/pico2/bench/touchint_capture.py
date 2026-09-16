#!/usr/bin/env python3
"""Capture the TP_INT (GP17) activity window while the user touches the panel.

Sends `touchint <ms>` over the pico2 USB console and records everything the
device emits until the job reports done (or a hard timeout), to
/tmp/touchint-user-capture.txt. Run in the background so the chat turn can
tell the user to touch the screen.
"""
import os
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
OUT = "/tmp/touchint-user-capture.txt"
WINDOW_MS = 240_000  # 4 minutes

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)

# drain whatever is pending
try:
    while True:
        r, _, _ = select.select([fd], [], [], 0.2)
        if not r:
            break
        if not os.read(fd, 8192):
            break
except Exception:
    pass

os.write(fd, b"\n")  # first-command quirk guard
time.sleep(0.2)
os.write(fd, f"touchint {WINDOW_MS}\n".encode())

buf = b""
deadline = time.time() + WINDOW_MS / 1000 + 20
done = False
while time.time() < deadline and not done:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        chunk = os.read(fd, 8192)
        if chunk:
            buf += chunk
            if b"[tint] done" in chunk:
                done = True

os.close(fd)
with open(OUT, "wb") as f:
    f.write(buf)
print(f"captured {len(buf)} bytes -> {OUT} (done={done})")
