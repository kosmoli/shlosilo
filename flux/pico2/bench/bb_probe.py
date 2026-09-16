#!/usr/bin/env python3
"""Bit-banged I2C probe sequence for the pico2 touch-bus forensics.

Runs the `bb*` console commands added in commit 8b5bba1 and records
everything to /tmp/pico2-bb-probe.txt.

The sequence:
  1. version           - confirm the flashed build identity
  2. i2c lines         - controller-path idle levels (baseline)
  3. bbscan            - bit-banged scan, documented pin mapping
  4. bbscan swap       - same scan with SDA/SCL roles swapped
  5. bbid 15           - address 0x15: probes + wire trace + reads
  6. bbtrace 15        - three traced probes, raw wire view

Usage: python3 bench/bb_probe.py [device]   (default /dev/ttyACM0)
"""
import os
import select
import sys
import time
import tty

DEV = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyACM0"
OUT = "/tmp/pico2-bb-probe.txt"

CMDS = [
    ("version", 2.5),
    ("i2c lines", 2.5),
    ("bbscan", 30.0),
    ("bbscan swap", 30.0),
    ("bbid 15", 20.0),
    ("bbtrace 15", 20.0),
]


def main():
    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    log = open(OUT, "wb")

    def drain(t=0.3):
        out = b""
        while True:
            r, _, _ = select.select([fd], [], [], t)
            if not r:
                break
            d = os.read(fd, 8192)
            if not d:
                break
            out += d
        return out

    drain(0.5)
    os.write(fd, b"\n")  # first-command quirk guard
    time.sleep(0.3)
    log.write(drain())

    for cmd, wait in CMDS:
        os.write(fd, (cmd + "\n").encode())
        time.sleep(wait)
        data = drain(0.0)
        block = f"\n===== $ {cmd} =====\n".encode() + data
        log.write(block)
        log.flush()
        print(f"--- {cmd}: {len(data)} bytes")

    log.close()
    os.close(fd)
    print(f"captured -> {OUT}")


if __name__ == "__main__":
    main()
