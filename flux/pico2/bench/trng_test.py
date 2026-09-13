#!/usr/bin/env python3
"""TRNG quality check for the pico2 bench channel.

Drives the console's `trng [stress] <n>` command and analyses the returned
192-bit blocks (24 B each) on the host:

  - duplicate-block check (no two 24-byte blocks equal),
  - monobit z-score over all bits,
  - byte-distribution chi-square (df=255),
  - serial correlation (lag 1, over bytes),
  - runs test over bits,
  - crude per-byte min-entropy (most-common-value estimator).

These are single-run sanity checks, not a certification: they catch gross
failures (stuck/degenerate source, severe bias) within one run. The real
gate for the entropy path is the hardware's own NIST SP 800-90B-aligned
checks, which stay enabled in the firmware (see trng.rs).

The device-side retry counters from the `[trng] done` line are printed for
the record. In `--stress` mode the firmware lowers the sample count to a
failure-prone setting: CRNGT / Von-Neumann retry counters are then
EXPECTED to be non-zero - that is what exercises the retry paths on real
silicon.

Usage:
    python3 trng_test.py [--count 1024] [--stress] [--dev /dev/ttyACM0]
Exit code 0 = all checks passed.
"""
import argparse
import math
import os
import re
import select
import sys
import threading
import time
import tty
from collections import Counter

BLOCK_HEX_RE = re.compile(r"\[trng\] ([0-9a-f]{48})\b")
DONE_RE = re.compile(
    r"\[trng\] done: (\d+) blocks in (\d+) ms \(~(\d+) us/block\);"
    r" crngt=(\d+) vn=(\d+) autocorr=(\d+) odd=(\d+) timeout=(\d+)"
)
FAILED_RE = re.compile(r"\[trng\] FAILED")


def monobit_z(bits):
    n = len(bits)
    ones = sum(bits)
    return (ones - n / 2) / math.sqrt(n / 4)


def chi2_bytes(data):
    counts = Counter(data)
    e = len(data) / 256.0
    return sum((counts.get(i, 0) - e) ** 2 / e for i in range(256)), 255


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
    ap.add_argument("--stress", action="store_true")
    ap.add_argument("--log", default="/tmp/pico2-trng-run.log")
    args = ap.parse_args()

    t0 = time.time()
    while not os.path.exists(args.dev):
        if time.time() - t0 > 180:
            sys.exit("TIMEOUT: console never appeared")
        time.sleep(0.5)

    fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)

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

    time.sleep(2.0)  # drain boot output / replays

    cmd = f"trng {'stress ' if args.stress else ''}{args.count}"
    print(f"sending: {cmd}")
    os.write(fd, (cmd + "\n").encode())

    # Generous deadline: worst case is dominated by a slow/odd TRNG, and the
    # firmware bounds each block attempt itself.
    deadline = time.time() + max(180, args.count * 0.2)
    while time.time() < deadline:
        text = buf.decode(errors="replace")
        if DONE_RE.search(text) or FAILED_RE.search(text):
            break
        time.sleep(0.5)

    stop.set()
    th.join(timeout=2)
    os.close(fd)

    text = buf.decode(errors="replace")
    with open(args.log, "w") as f:
        f.write(text)

    m = DONE_RE.search(text)
    if m:
        blocks_rep, ms, us, crngt, vn, autocorr, odd, timeout = m.groups()
        print(
            f"device: {blocks_rep} blocks in {ms} ms (~{us} us/block); "
            f"crngt={crngt} vn={vn} autocorr={autocorr} odd={odd} timeout={timeout}"
        )
        if args.stress and (int(crngt) + int(vn) + int(autocorr) == 0):
            print("NOTE: stress mode produced no retries (checks did not fail); "
                  "try more blocks or check the sample-count override")
    elif FAILED_RE.search(text):
        print("device reported FAILED:")
        for line in text.split("\r\n"):
            if "[trng]" in line:
                print("  " + line.strip())
    else:
        print("no [trng] done line seen (log: " + args.log + ")")

    blocks = BLOCK_HEX_RE.findall(text)
    data = bytes.fromhex("".join(blocks))
    n = len(data)
    print(f"blocks received: {len(blocks)} ({n} bytes)")

    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print(("PASS " if ok else "FAIL ") + name + (("  :: " + detail) if detail else ""))

    if n < 256:
        check("enough data for analysis (>=256 bytes)", False, f"got {n}")
    else:
        check(f"received all {args.count} requested blocks", len(blocks) == args.count,
              f"got {len(blocks)}")
        dup = len(blocks) - len(set(blocks))
        check("no duplicate 24-byte blocks", dup == 0, f"{dup} duplicates")

        bits = [(b >> i) & 1 for b in data for i in range(8)]
        z = monobit_z(bits)
        check("monobit |z| <= 4", abs(z) <= 4, f"z = {z:.2f}")

        chi2, df = chi2_bytes(data)
        lo, hi = df - 4 * math.sqrt(2 * df), df + 4 * math.sqrt(2 * df)
        check(f"byte chi2 within [lo={lo:.0f}, hi={hi:.0f}]", lo <= chi2 <= hi,
              f"chi2 = {chi2:.1f} (df={df})")

        r = serial_corr(data)
        thr = 4 / math.sqrt(n)
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
