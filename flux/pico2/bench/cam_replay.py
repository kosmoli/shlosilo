#!/usr/bin/env python3
"""Live experiment (no reflash): drive PWDN low, then replay the entire
OV5640 SCCB init sequence over the console (`cam reg` writes), then check
whether the sensor starts producing DVP frames (cam pins / cam rx / cam grab).

Hypothesis: on this board the sensor needs PWDN driven low; and it must be
(re)configured while in that state. If frames start flowing, the firmware
fix is simply "PWDN low at boot before the SCCB init".
"""
import json
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
CMDS = json.load(open("/tmp/cam_replay.json"))


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

    def say(line, wait=1.5, until=None):
        os.write(fd, (line + "\n").encode())
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
                    deadline = time.time() + wait
        for ln in buf.decode("utf-8", "replace").splitlines():
            if "[cam]" in ln or "[err]" in ln:
                print("   " + ln)
        return buf

    drain(0.5)
    os.write(fd, b"\n")
    time.sleep(0.3)
    drain(0.3)

    print("== baseline (current state, PWDN high-Z from last run) ==")
    say("cam rx 300", 4, until=b"rx probe")

    print("== PWDN low ==")
    say("cam pwdn 0", 1)

    print("== replay full SCCB init table (174 writes, chunked) ==")
    batch = []
    t0 = time.time()
    sent = 0
    for kind, val in CMDS:
        if kind == "sleep":
            if batch:
                os.write(fd, ("\n".join(batch) + "\n").encode())
                sent += len(batch)
                batch = []
                time.sleep(0.2)
            time.sleep(val / 1000.0)
        else:
            batch.append(val)
            if len(batch) >= 10:
                os.write(fd, ("\n".join(batch) + "\n").encode())
                sent += len(batch)
                batch = []
                time.sleep(0.15)
    if batch:
        os.write(fd, ("\n".join(batch) + "\n").encode())
        sent += len(batch)
    time.sleep(0.5)
    drain(1.0)
    print(f"   sent {sent} writes in {time.time()-t0:.1f} s")

    print("== post-checks ==")
    say("cam reg 0x3008", 1)
    say("cam pins", 2)
    say("cam rx 500", 5, until=b"rx probe")
    say("cam grab 1", 8, until=b"frame")
    say("cam reg 0x3400", 1)
    say("cam reg 0x3401", 1)

    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
