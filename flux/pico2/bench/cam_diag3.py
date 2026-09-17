#!/usr/bin/env python3
"""Camera deep-dive round 3: the full PWDN-fix verification + diagnostics.

Runs after the PWDN power-up fix: checks whether frames now flow, and if
not, exercises every probe (SM state, self-test, edges, reinit).
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

    def cmd(c, wait=2.0, until=None):
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
            if "[cam]" in line or "[err]" in line:
                print("   " + line)
        return buf

    drain(0.5)
    os.write(fd, b"\n")
    time.sleep(0.3)
    drain(0.3)

    print("== 1. status (id + readback) ==")
    cmd("cam id", 2)

    print("== 2. pad samples + edges (are frames flowing now?) ==")
    cmd("cam pins", 2.5)
    cmd("cam edges 300", 4)

    print("== 3. rx probe (any PIO output?) ==")
    cmd("cam rx 600", 5, until=b"rx probe")

    print("== 4. PIO state machine dump ==")
    cmd("cam sm", 2)

    print("== 5. PIO plumbing self-test (SM1) ==")
    cmd("cam selftest 20", 2)

    print("== 6. capture attempt ==")
    cmd("cam grab 1", 8, until=b"frame")

    print("== 7. reinit then capture again ==")
    cmd("cam reinit", 6, until=b"reinit done")
    cmd("cam grab 1", 8, until=b"frame")

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
