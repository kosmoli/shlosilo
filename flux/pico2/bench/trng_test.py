#!/usr/bin/env python3
"""TRNG quality check for the pico2 bench channel.

Drives the console's `trng` command and analyses the returned 192-bit blocks
(24 B each) on the host:

  - duplicate-block check (no two 24-byte blocks equal),
  - all-zero block check (a failed entropy check presents no result),
  - monobit z-score over all bits,
  - byte-distribution chi-square (df=255),
  - serial correlation (lag 1, over bytes),
  - runs test over bits,
  - crude per-byte min-entropy (most-common-value estimator).

These are single-run sanity checks, not a certification: they catch gross
failures (stuck/degenerate source, severe bias) within one run. The real
gate for the entropy path is the hardware's own NIST SP 800-90B-aligned
checks, which stay enabled in the firmware (see src/trng.rs).

Blocks are requested in CHUNKS (default 64 per command): a large job emits
its hex lines faster than the 1 KiB log pipe drains, and the pipe drops
silently - a 256-block single command lost ~40% of its lines on the bench.

The device-side counters from each `[trng] done` line are printed for the
record. `--stress` lowers the sample count to a failure-prone setting;
`--sample=`/`--chain=` sweep the characterisation knobs (the firmware's
measured operating point is chain 4 / sample 200 - see flux/pico2/README).

Usage:
    python3 trng_test.py [--count 1024] [--chunk 64] [--stress]
                         [--sample N] [--chain 0-4] [--timeout MS]
                         [--dev /dev/ttyACM0]
Exit code 0 = all checks passed.
"""
import argparse
import math
import os
import re
import select
import sys
import termios
import threading
import time
import tty
from collections import Counter

BLOCK_HEX_RE = re.compile(r"\[trng\] ([0-9a-f]{48})\b")
DONE_RE = re.compile(r"\[trng\] (done|FAILED)")

# 24 bytes per block -> hex chars per block
BLOCK_HEX_LEN = 48


def monobit_z(bits):
    n = len(bits)
    ones = sum(bits)
    return (ones - n / 2) / math.sqrt(n / 4)


def chi2_bytes(data):
    counts = Counter(data)
    e = len(data) / 256.0
    return sum((counts.get(i, 0) - e) ** 2 / e for i in range(256))


def serial_corr(data):
    n = len(data)
    m = sum(data) / n
    num = sum((data[i] - m) * (data[i + 1] - m) for i in range(n - 1))
    den = sum((x - m) ** 2 for x in data)
    return num / den if den else 0.0


def runs_z(bits):
    runs = 1
    for i in range(1, len(bits)):
        if bits[i] != bits[i - 1]:
            runs += 1
    n = len(bits)
    return (runs - (n + 1) / 2) / math.sqrt((n - 1) / 4)


def min_entropy_byte(data):
    counts = Counter(data)
    p = max(counts.values()) / len(data)
    return -math.log2(p)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="/dev/ttyACM0")
    ap.add_argument("--count", type=int, default=1024)
    ap.add_argument("--chunk", type=int, default=64)
    ap.add_argument("--stress", action="store_true")
    ap.add_argument("--sample", type=int, default=None)
    ap.add_argument("--chain", type=int, default=None)
    ap.add_argument("--timeout", type=int, default=None, help="per-block patience (ms)")
    ap.add_argument("--log", default="/tmp/pico2-trng-run.log")
    args = ap.parse_args()

    t0 = time.time()
    while not os.path.exists(args.dev):
        if time.time() - t0 > 300:
            sys.exit("TIMEOUT: console never appeared")
        time.sleep(0.5)

    fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    # Drop anything queued on the host side, then flush any partial line the
    # device may be holding: until a host program sets the port to raw, the
    # tty echo can send the device's own boot banner back to it (echo is on
    # by default after enumeration), and the banner has no terminator - the
    # first command would merge with it and be rejected as unknown.
    try:
        termios.tcflush(fd, termios.TCIFLUSH)
    except termios.error:
        pass
    os.write(fd, b"\n")
    time.sleep(0.3)

    buf = bytearray()
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    c = os.read(fd, 8192)
                except OSError:
                    break
                if c:
                    buf.extend(c)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    time.sleep(2.0)

    def text():
        return buf.decode(errors="replace")

    def send(cmd):
        os.write(fd, (cmd + "\n").encode())

    opts = ""
    if args.stress:
        opts += " stress"
    if args.sample is not None:
        opts += f" sample={args.sample}"
    if args.chain is not None:
        opts += f" chain={args.chain}"
    if args.timeout is not None:
        opts += f" timeout={args.timeout}"

    chunk = max(1, min(64, args.chunk))
    remaining = args.count
    all_blocks = []
    done_lines = []
    failed = False

    while remaining > 0 and not failed:
        n = min(chunk, remaining)
        before_blocks = len(all_blocks)
        before_done = len(DONE_RE.findall(text()))
        cmd = f"trng{opts} {n}"
        print(f"sending: {cmd}  ({len(all_blocks)}/{args.count} blocks so far)")
        send(cmd)
        deadline = time.time() + max(60, n * 5)
        while time.time() < deadline:
            cur = text()
            if len(DONE_RE.findall(cur)) > before_done:
                break
            time.sleep(0.3)
        time.sleep(0.3)
        chunk_text = text()
        blocks = [b for b in BLOCK_HEX_RE.findall(chunk_text)]
        # blocks accumulate; slice the new ones
        new_blocks = blocks[before_blocks:]
        all_blocks.extend(new_blocks)
        end = [l.strip() for l in chunk_text.split("\r\n") if DONE_RE.search(l)]
        if end:
            done_lines.append(end[-1])
            if "FAILED" in end[-1]:
                failed = True
        if len(all_blocks) == before_blocks:
            print("  !! chunk produced no blocks (see log)")
            failed = True
        remaining -= n

    stop.set()
    th.join(timeout=2)
    os.close(fd)

    full = text()
    with open(args.log, "w") as f:
        f.write(full)

    for l in done_lines[-4:]:
        print("device:", l)

    data = bytes.fromhex("".join(all_blocks))
    nbytes = len(data)
    print(f"blocks received: {len(all_blocks)}/{args.count} ({nbytes} bytes)")

    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print(("PASS " if ok else "FAIL ") + name + (("  :: " + detail) if detail else ""))

    if nbytes < 1024 or failed:
        check(f"received all {args.count} requested blocks", len(all_blocks) == args.count,
              f"got {len(all_blocks)}")
    else:
        check(f"received all {args.count} requested blocks", len(all_blocks) == args.count,
              f"got {len(all_blocks)}")
        dup = len(all_blocks) - len(set(all_blocks))
        check("no duplicate 24-byte blocks", dup == 0, f"{dup} duplicates")
        zeros = sum(1 for b in all_blocks if b == "0" * BLOCK_HEX_LEN)
        check("no all-zero blocks", zeros == 0, f"{zeros} zeros")

        bits = [(b >> i) & 1 for b in data for i in range(8)]
        z = monobit_z(bits)
        check("monobit |z| <= 4", abs(z) <= 4, f"z = {z:.2f}")

        chi2 = chi2_bytes(data)
        df = 255
        lo, hi = df - 4 * math.sqrt(2 * df), df + 4 * math.sqrt(2 * df)
        check(f"byte chi2 within [{lo:.0f}, {hi:.0f}]", lo <= chi2 <= hi,
              f"chi2 = {chi2:.1f} (df={df})")

        r = serial_corr(data)
        thr = 4 / math.sqrt(nbytes)
        check("serial correlation |r| <= 4/sqrt(n)", abs(r) <= thr,
              f"r = {r:.5f} (threshold {thr:.5f})")

        rz = runs_z(bits)
        check("runs test |z| <= 4", abs(rz) <= 4, f"z = {rz:.2f}")

        me = min_entropy_byte(data)
        check("crude per-byte min-entropy >= 7.0 bits", me >= 7.0, f"{me:.3f} bits")

    print("ALL PASS" if all(results) else "SOME FAILED")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
