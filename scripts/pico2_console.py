#!/usr/bin/env python3
"""Minimal pico2 console probe/runner over /dev/ttyACM0 without pyserial.

Usage: pico2_console.py "<command>" [seconds]

The pico2 USB console is a plain CDC-ACM device: write a line, read what comes
back. pyserial is not installed on this host, so this uses termios directly.
Probe mode (no command) sends a bare newline to re-print the prompt/status.
"""
import os
import select
import sys
import termios
import time
import tty

DEV = "/dev/ttyACM0"


def run(cmd: str, seconds: float) -> str:
    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY)
    try:
        tty.setraw(fd)
        attrs = termios.tcgetattr(fd)
        attrs[4] = attrs[5] = termios.B115200  # ispeed/ospeed
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
        time.sleep(0.4)
        # drain whatever the device already emitted
        while select.select([fd], [], [], 0)[0]:
            os.read(fd, 4096)
        os.write(fd, cmd.encode() + b"\r\n")
        deadline = time.time() + seconds
        out = bytearray()
        while time.time() < deadline:
            if select.select([fd], [], [], 0.2)[0]:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                out += chunk
        return out.decode("utf-8", "replace")
    finally:
        os.close(fd)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    print(run(cmd, secs))
