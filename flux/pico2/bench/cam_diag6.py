#!/usr/bin/env python3
"""Camera round 6: verify the IN_COUNT root-cause fix.

Boot config now sets SM0's IN window to GP0..GP10 (IN_BASE=0, IN_COUNT=11),
matching the vendor SDK's effective config (IN_COUNT stays 32 there). The
live A/B: `cam incount 8` (old, broken) vs `cam incount 11` (fixed).
"""
import os
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"


def main() -> int:
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

    def cmd(c, wait=2.0, until=None, show=("[cam]", "[err]")):
        os.write(fd, (c + "\n").encode())
        deadline = time.time() + wait
        buf = b""
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.25)
            if r:
                d = os.read(fd, 8192)
                if d:
                    buf += d
                    if until and until in d:
                        break
                    deadline = time.time() + wait
        for line in buf.decode("utf-8", "replace").splitlines():
            if any(s in line for s in show):
                print("   " + line)
        return buf

    drain(0.5)
    os.write(fd, b"\n")
    time.sleep(0.3)
    drain(0.3)

    print("== 1. current IN window + boot-state probe ==")
    cmd("cam incount", 2)
    cmd("cam rx 300", 4, until=b"rx probe")

    print("== 2. live A/B: set count=8 (the old broken config) ==")
    cmd("cam incount 8", 2)
    cmd("cam rx 300", 4, until=b"rx probe")

    print("== 3. live A/B: restore count=11 (the fix) ==")
    cmd("cam incount 11", 2)
    cmd("cam rx 300", 4, until=b"rx probe")

    print("== 4. capture test ==")
    cmd("cam grab 2", 10, until=b"frame(s) captured")

    print("== 5. SM state + edges (cross-check) ==")
    cmd("cam sm", 2)
    cmd("cam edges 200", 3)

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
