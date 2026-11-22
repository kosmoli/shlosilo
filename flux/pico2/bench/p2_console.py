#!/usr/bin/env python3
"""Minimal pico2 console driver for hardware checks.

Opens the CDC-ACM console raw, drains the boot chatter, sends the given commands
one at a time (waiting a little between them), and prints everything received.

Usage: p2_console.py [--dev /dev/ttyACM0] [--drain SECONDS] [--after SECONDS] cmd1 cmd2 ...
"""
import argparse
import os
import select
import sys
import termios
import time
import tty

ap = argparse.ArgumentParser()
ap.add_argument("--dev", default="/dev/ttyACM0")
ap.add_argument("--drain", type=float, default=3.0, help="seconds of boot chatter to print first")
ap.add_argument("--after", type=float, default=2.0, help="seconds to read after each command")
ap.add_argument("cmds", nargs="*")
args = ap.parse_args()

if not os.path.exists(args.dev):
    sys.exit(f"missing {args.dev}")

fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)


def drain(seconds: float, label: str) -> str:
    end = time.time() + seconds
    out = b""
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try:
                chunk = os.read(fd, 4096)
            except BlockingIOError:
                continue
            if not chunk:
                continue
            out += chunk
    text = out.decode("utf-8", "replace")
    print(f"----- {label} ({len(text)} chars) -----")
    print(text, end="" if text.endswith("\n") else "\n")
    return text


argv = [sys.argv[0]] + sys.argv[1:]
drain(args.drain, "boot chatter")
for cmd in args.cmds:
    print(f"----- send: {cmd!r} -----")
    os.write(fd, (cmd + "\r").encode())
    drain(args.after, f"after {cmd!r}")
os.close(fd)
