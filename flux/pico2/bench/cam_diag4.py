#!/usr/bin/env python3
"""Camera round 4: the PIO's own pin view + full SM decode.

The decisive question: the CPU-side pad reads show VSYNC/HREF/PCLK activity
but SM0 sits at pc=3 (its VSYNC-high wait) and never pushes. This script
asks the PIO directly what it sees on the pins (SM1 runs `mov isr, pins`).
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

    print("== 1. SM state (decoded) ==")
    cmd("cam sm", 2)

    print("== 2. PIO's own pin view (SM1: mov isr,pins) ==")
    cmd("cam piosample 16", 3, until=b"OR=")

    print("== 3. SM1 plumbing self-test (bounded) ==")
    cmd("cam selftest 20", 3, until=b"self-test")

    print("== 4. CPU pad view + edges (same moment) ==")
    cmd("cam pins", 2.5)
    cmd("cam edges 300", 4)

    print("== 5. rx probe + capture ==")
    cmd("cam rx 400", 4, until=b"rx probe")
    cmd("cam grab 1", 8, until=b"frame")

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
