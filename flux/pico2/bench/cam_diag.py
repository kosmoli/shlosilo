#!/usr/bin/env python3
"""Full camera diagnostic sequence over the pico2 console.

Runs, in order: cam id, cam pins, cam rx (both bytes), cam grab,
then (if a capture succeeds) cam dump.

Each step prints the [cam]/[err] lines it produced, so the failure mode is
visible without a flash-capture window.
"""
import os
import select
import sys
import time
import tty

# Auto-detect: the console can re-enumerate as ttyACM0/ACM1/... (e.g. after
# a board reset), and hardcoding the node breaks the script silently.
def _find_dev():
    import glob as _glob
    for d in sorted(_glob.glob("/dev/ttyACM*")) + sorted(_glob.glob("/dev/ttyUSB*")):
        return d
    raise SystemExit("no serial console found (/dev/ttyACM*)")


DEV = _find_dev()


def main() -> int:
    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)

    def drain(t=0.4):
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

    def cmd(c, wait=2.5, until=None):
        os.write(fd, (c + "\n").encode())
        deadline = time.time() + wait
        buf = b""
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.3)
            if r:
                d = os.read(fd, 8192)
                if d:
                    buf += d
                    if until and until in d:
                        break
                    deadline = min(deadline, time.time() + wait)
        text = buf.decode("utf-8", "replace")
        for line in text.splitlines():
            if "[cam]" in line or "[err]" in line:
                print("   " + line)
        return text

    drain(0.5)
    os.write(fd, b"\n")
    time.sleep(0.3)
    drain(0.3)

    print("== cam id ==")
    cmd("cam id", 2)
    print("== cam pins ==")
    cmd("cam pins", 3)
    print("== cam rx 1000 ==")
    cmd("cam rx 1000", 5, until=b"rx probe")
    print("== cam grab 1 ==")
    cmd("cam grab 1", 8, until=b"frame")
    print("== cam grab 1 (2nd try) ==")
    cmd("cam grab 1", 8, until=b"frame")
    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
