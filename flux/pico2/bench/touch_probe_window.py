#!/usr/bin/env python3
"""Probe the CST816D while the user keeps touching the panel.

Hypothesis (2026-09-16): the controller is alive (INT pulses on touch) but
auto-slept (PowerOn default; nobody disabled it, and every earlier probe hit
a sleeping chip, where the I2C interface does not answer). A finger wakes it
- so probe DURING touch, and on the first ACK write DisAutoSleep=1 (reg
0xFE) plus the rest of the vendor init, which should keep it awake from then
on. Runs ~2 minutes: cycles of `i2c scan` + `i2c id 15` + `i2c wr 15 fe 01`,
switching to 100 kHz at half time for marginal-contact robustness.

Launch in the background, then tell the user to touch NOW.
Log: /tmp/touch-probe-window.txt
"""
import os
import select
import time
import tty

DEV = "/dev/ttyACM0"
OUT = "/tmp/touch-probe-window.txt"
DUR = 120.0  # seconds

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)


def drain():
    out = b""
    while True:
        r, _, _ = select.select([fd], [], [], 0.12)
        if not r:
            break
        d = os.read(fd, 8192)
        if not d:
            break
        out += d
    return out


def send(cmd, wait):
    os.write(fd, (cmd + "\n").encode())
    time.sleep(wait)
    return drain()


log = open(OUT, "wb")


def w(tag, data):
    if data:
        log.write(f"[{tag}] ".encode() + data + b"\n")
        log.flush()


# quirk guard: flush + a bare newline first
drain()
os.write(fd, b"\n")
time.sleep(0.3)
drain()

w("version", send("version", 0.8))
w("lines", send("i2c lines", 0.5))

t0 = time.time()
configured = False
rate_switched = False
cycles = 0

while time.time() - t0 < DUR and not configured:
    el = time.time() - t0
    if el > DUR / 2 and not rate_switched:
        rate_switched = True
        w("freq", send("i2c freq 100", 0.5))

    cycles += 1
    tag = f"{el:5.1f}s c{cycles}"
    out = send("i2c scan", 1.7)
    if b"ACK 0x" in out:
        w(tag + " scan", out)
    out = send("i2c id 15", 1.1)
    if b"probes" in out and b"0 ACK" not in out:
        w(tag + " id15", out)
    out = send("i2c wr 15 fe 01", 0.5)
    if b"ACKed" in out:
        w(tag + " WR-FE-OK", out)
        for c in ["i2c wr 15 ed 01", "i2c wr 15 ee 01", "i2c wr 15 fa 41"]:
            w(tag + " init", send(c, 0.4))
        w(tag + " chipid", send("i2c rd 15 a7", 0.5))
        w(tag + " fingers", send("i2c rd 15 02", 0.5))
        configured = True
    elif b"failed" in out and b"NACK" not in out:
        w(tag + " wr", out)

if configured:
    for i in range(4):
        w(f"post{i}", send("i2c id 15", 0.9))

log.write(f"=== end: cycles={cycles} configured={configured} ===\n".encode())
log.close()
os.close(fd)
print(f"window done: cycles={cycles} configured={configured} -> {OUT}")
