#!/usr/bin/env python3
"""Camera round 5: is the PIO's blindness to GP8-11 real or a sampler artifact?

Sequence:
 1. cam pads      -> pad/IO registers for GP0-11 (IE/ISO/FUNCSEL/INOVER truth)
 2. cam piosample -> the `mov isr, pins` view (reference)
 3. cam in8       -> the `in pins` + IN_BASE=8 view (same path as the capture
                     program's data reads): GP8-15
 4. controlled: drop XCLK to 10 kHz (no aliasing possible) and re-run both
    samplers + the CPU-side `pins` for a three-way comparison at the same
    instant.
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

    print("== 1. pad/IO registers (GP0-11) ==")
    cmd("cam pads 12", 3)

    print("== 2. PIO mov-isr-pins view ==")
    cmd("cam piosample 8", 3, until=b"OR=")

    print("== 3. PIO in-pins view of GP8-15 ==")
    cmd("cam in8 8", 3, until=b"OR=")

    print("== 4. controlled: XCLK -> 10 kHz ==")
    cmd("cam xclk 10", 1)
    cmd("cam pins", 2.5)
    cmd("cam piosample 8", 3, until=b"OR=")
    cmd("cam in8 8", 3, until=b"OR=")

    print("== 5. restore XCLK 37 MHz, check edges ==")
    cmd("cam xclk 37000", 1)
    cmd("cam edges 200", 3)

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
