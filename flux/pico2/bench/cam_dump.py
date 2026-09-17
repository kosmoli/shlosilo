#!/usr/bin/env python3
"""Camera bring-up: trigger a `cam dump` on the pico2 and reassemble the
streamed hex rows into a PGM, then print quick statistics.

Usage: cam_dump.py [stride] [byte] [out.pgm]

  stride  1|2|4  pixel decimation (default 2 -> 120x160, fast over console)
  byte    0|1    which byte of each DVP word (default 0 = first sample)
  out     output path (default /tmp/cam.pgm)

The firmware prints:
  [cam] PGM <w> <h> stride <s> byte <b>
  [cam] <y> <hex row>          (one line per row, paced)
  [cam] end
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
STRIDE = sys.argv[1] if len(sys.argv) > 1 else "2"
BYTE = sys.argv[2] if len(sys.argv) > 2 else "0"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/cam.pgm"


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

    drain(0.4)
    os.write(fd, b"\n")
    time.sleep(0.25)
    drain(0.2)

    # Stats first (cheap liveness + which byte carries luma), then the dump.
    os.write(fd, b"cam grab 1\n")
    deadline = time.time() + 20
    buf = b""
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            buf += os.read(fd, 8192)
        if b"[cam] 1 frame(s) captured" in buf or b"[err]" in buf:
            break
    for line in buf.decode("utf-8", "replace").splitlines():
        if "[cam]" in line:
            print(line)

    os.write(fd, f"cam dump {STRIDE} {BYTE}\n".encode())
    deadline = time.time() + 120
    buf = b""
    done = False
    while time.time() < deadline and not done:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            d = os.read(fd, 8192)
            if d:
                buf += d
                if b"[cam] end" in d:
                    done = True
    os.close(fd)

    text = buf.decode("utf-8", "replace")
    w = h = None
    rows = {}
    for line in text.splitlines():
        if "[cam] PGM" in line:
            parts = line.split()
            w, h = int(parts[2]), int(parts[3])
        elif line.startswith("[cam] end"):
            break
        elif line.startswith("[cam] "):
            parts = line.split()
            if len(parts) == 3 and parts[1].isdigit():
                try:
                    rows[int(parts[1])] = bytes.fromhex(parts[2])
                except ValueError:
                    pass

    if not done or w is None or not rows:
        print(f"FAILED: done={done} w={w} rows={len(rows)}", file=sys.stderr)
        return 1

    with open(OUT, "wb") as f:
        f.write(b"P5\n%d %d\n255\n" % (w, h))
        for y in sorted(rows):
            f.write(rows[y])

    data = b"".join(rows[y] for y in sorted(rows))
    n = len(data)
    mean = sum(data) / n
    print(
        f"wrote {OUT}: {w}x{h} ({n} bytes), min {min(data)} max {max(data)} "
        f"mean {mean:.1f}, rows {len(rows)}/{h}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
