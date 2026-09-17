#!/usr/bin/env python3
"""Camera deep-dive: SCCB register readback + PWDN sweep.

Reads the key config registers (did our writes land?), then drives PWDN
low/high/high-Z while sampling the DVP pads and the PIO FIFO after each
state - the decisive experiment for "sensor silent" without a reflash.
"""
import os
import select
import sys
import time
import tty

DEV = "/dev/ttyACM0"

REGS = [
    0x3008,  # system control: 0x02 = streaming
    0x3034,
    0x3035,  # PLL dividers
    0x3036,
    0x3037,
    0x3108,  # root divider
    0x3808,  # output width hi
    0x3809,  # output width lo
    0x380C,  # HTS hi
    0x380D,
    0x4300,  # format
    0x4740,  # clock polarity
    0x5001,  # ISP control
    0x460C,  # VFIFO
    0x3824,  # PCLK ratio
    0x3039,  # PLL bypass ctrl
]


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

    def cmd(c, wait=2.0, until=None):
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
        for line in buf.decode("utf-8", "replace").splitlines():
            if "[cam]" in line or "[err]" in line:
                print("   " + line)
        return buf

    drain(0.5)
    os.write(fd, b"\n")
    time.sleep(0.3)
    drain(0.3)

    print("== SCCB readback ==")
    for r in REGS:
        cmd(f"cam reg 0x{r:04x}", 1.0)

    for state, label in [("0", "PWDN low (driven)"), ("1", "PWDN high (driven)"), ("z", "PWDN high-Z")]:
        print(f"== {label} ==")
        cmd(f"cam pwdn {state}", 1.0)
        time.sleep(0.3)
        cmd("cam pins", 2.0)
        cmd("cam rx 400", 3.0, until=b"rx probe")

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
