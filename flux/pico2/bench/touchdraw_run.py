#!/usr/bin/env python3
"""Launch touchdraw on the pico2 and tail its log until the job ends.

touchdraw runs as a deferred job inside the firmware (the USB task), so
the host just sends the command and listens; the job reports
`[tdraw] done: N dot(s) painted` when its window closes.
"""
import os
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"
SECS = sys.argv[1] if len(sys.argv) > 1 else "90"

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


drain(0.4)
os.write(fd, b"\n")
time.sleep(0.25)
drain(0.2)
os.write(fd, f"touchdraw {SECS}\n".encode())

deadline = time.time() + float(SECS) + 20
done = False
buf = b""
while time.time() < deadline and not done:
    r, _, _ = select.select([fd], [], [], 0.5)
    if r:
        d = os.read(fd, 8192)
        if d:
            buf += d
            if b"[tdraw] done" in d:
                done = True

os.close(fd)
text = buf.decode("utf-8", "replace")
for line in text.splitlines():
    if "[tdraw]" in line or "[err]" in line:
        print(line)
print(f"(captured {len(buf)} bytes, done={done})")
