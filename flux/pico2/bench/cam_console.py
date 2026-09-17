#!/usr/bin/env python3
"""Robust pico2 console helper: handles the USB CDC endpoint's transient
BlockingIOError (the write side can return EAGAIN when the device's USB
buffer is full - e.g. right after a busy command or a re-enumeration).

Small library used by the camera scripts; also runnable for one-off command
sequences:  cam_console.py "command1" "command2" ...
"""
import glob
import os
import select
import sys
import time
import tty


def find_dev():
    for pat in ("/dev/ttyACM*", "/dev/ttyUSB*"):
        devs = sorted(glob.glob(pat))
        if devs:
            return devs[0]
    raise SystemExit("no serial console found")


class Console:
    def __init__(self):
        self.dev = find_dev()
        self.fd = os.open(self.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        tty.setraw(self.fd)

    def write(self, data: bytes, tries: int = 40):
        """Write with retry: EAGAIN on a full device-side buffer is normal."""
        for _ in range(tries):
            try:
                os.write(self.fd, data)
                return True
            except BlockingIOError:
                time.sleep(0.05)
        return False

    def drain(self, t: float = 0.3) -> bytes:
        out = b""
        try:
            while True:
                r, _, _ = select.select([self.fd], [], [], t)
                if not r:
                    break
                d = os.read(self.fd, 8192)
                if not d:
                    break
                out += d
        except (BlockingIOError, OSError):
            pass
        return out

    def sync(self):
        """Flush both directions and send a bare newline."""
        self.drain(0.4)
        self.write(b"\n")
        time.sleep(0.25)
        self.drain(0.25)

    def cmd(self, line: str, wait: float = 1.0, until: bytes | None = None) -> bytes:
        self.write(line.encode() + b"\n")
        deadline = time.time() + wait
        buf = b""
        while time.time() < deadline:
            r, _, _ = select.select([self.fd], [], [], 0.25)
            if r:
                try:
                    d = os.read(self.fd, 8192)
                except (BlockingIOError, OSError):
                    continue
                if d:
                    buf += d
                    if until and until in d:
                        break
                    deadline = time.time() + wait
        return buf

    def close(self):
        os.close(self.fd)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    c = Console()
    print("console:", c.dev)
    c.sync()
    for line in sys.argv[1:]:
        out = c.cmd(line, 2.0)
        for ln in out.decode("utf-8", "replace").splitlines():
            if "[cam]" in ln or "[err]" in ln or "[hb]" in ln:
                print(" ", ln)
    c.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
