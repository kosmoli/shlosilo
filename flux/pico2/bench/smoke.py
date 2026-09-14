#!/usr/bin/env python3
"""Post-refactor smoke test for pico2 firmware +650db1c (single-owner TRNG).

Covers every path the lock refactor touched:
  version / heap          - console basics
  trngdump                - diagnostics under the instance guard
  trng 8                  - raw reads under the guard
  trng cond 8             - conditioned32 under the guard (two-block pairing)
  ETH fixture UR          - signing path regression (must match host oracle)

Exit 0 = all smoke checks passed.

Requires the bench build (`make pico2-bench-uf2`): trngdump / trng are
bench-only commands (audit #17); this script aborts on a production build
instead of failing them confusingly.
"""
import os
import re
import select
import sys
import termios
import threading
import time
import tty

DEV = "/dev/ttyACM0"
ETH_URI_FILE = "/home/komo/works/shlosilo-poc4/flux/host-sim/fixture_eth_sign_request.txt"
EXPECTED = "/tmp/shlosilo_bench_expected.txt"
LOG = "/tmp/pico2-smoke-run.log"

BLOCK_RE = re.compile(r"\[trng\] ([0-9a-f]{48})\b")
COND_RE = re.compile(r"\[trng\] ([0-9a-f]{64})\b")


def main():
    exp = {}
    with open(EXPECTED) as f:
        for line in f:
            line = line.strip()
            if line:
                k, v = line.split(" ", 1)
                exp[k] = v
    with open(ETH_URI_FILE) as f:
        eth_uri = f.read().strip()

    t0 = time.time()
    while not os.path.exists(DEV):
        if time.time() - t0 > 600:
            sys.exit("TIMEOUT: console never appeared")
        time.sleep(0.5)

    fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
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
    time.sleep(2.5)  # drain boot output

    def text():
        return buf.decode(errors="replace")

    def send(cmd):
        os.write(fd, (cmd + "\n").encode())

    def wait_marker(marker, timeout, start=0):
        """Wait for `marker` to appear in text STARTING AT OFFSET `start`.

        The window matters: a global search is satisfied by earlier
        commands' output (the first `trng` done line made a later job's
        wait return instantly, before its output had arrived).
        """
        t = time.time()
        while time.time() - t < timeout:
            if marker in text()[start:]:
                return True
            time.sleep(0.2)
        return False

    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print(("PASS " if ok else "FAIL ") + name + (("  :: " + detail) if detail else ""))

    # 1. version
    before = len(buf)
    send("version")
    ok = wait_marker("[ver]", 10, before)
    m = re.search(r"\[ver\] (v[\w.+-]+) \(cabi (v[\w.+-]+)\)", text()[before:])
    check("console: version", ok and bool(m), (m.group(1) if m else "no [ver] line"))

    # 1b. build flavor: trngdump / trng below only exist in bench builds
    # (audit #17); abort clearly instead of failing them one by one.
    fm = re.search(r"\[ver\].*?build=(\w+)", text()[before:])
    build = fm.group(1) if fm else "unknown"
    if build != "bench":
        print(f"ABORT: board build={build}; this smoke needs the bench build "
              "(make pico2-bench-uf2)")
        stop.set()
        th.join(timeout=2)
        os.close(fd)
        sys.exit(2)

    # 2. heap
    send("heap")
    ok = wait_marker("[heap]", 10, before)
    check("console: heap", ok)

    # 3. trngdump (under the instance guard)
    before = len(buf)
    send("trngdump")
    ok = wait_marker("[tdump]", 10, before)
    check("diag: trngdump under guard", ok)

    # 4. raw 8 blocks
    before = len(buf)
    send("trng 8")
    ok = wait_marker("[trng] done", 30, before) or wait_marker("FAILED", 5, before)
    chunk = text()[before:]
    raw_blocks = BLOCK_RE.findall(chunk)
    check("trng raw 8: got 8 blocks", len(raw_blocks) == 8, f"got {len(raw_blocks)}")

    # 5. conditioned 8 (two-block pairing under one guard)
    before = len(buf)
    send("trng cond 8")
    ok = wait_marker("[trng] done", 60, before) or wait_marker("FAILED", 5, before)
    chunk = text()[before:]
    cond_out = COND_RE.findall(chunk)
    check("trng cond 8: got 8 conditioned outputs", len(cond_out) == 8, f"got {len(cond_out)}")

    # 6. ETH signing regression
    before = len(buf)
    send(eth_uri)
    ok = wait_marker("[sign] eth-sign-request hex", 30, before)
    chunk = text()[before:]
    m = re.search(r"\[sign\] eth-sign-request hex: ([0-9a-f]+)", chunk)
    check("sign: ETH fixture full hex matches host oracle",
          bool(m) and m.group(1) == exp["eth_hex"],
          (m.group(1)[:32] + "..." if m else "no hex line"))
    m2 = re.search(r"\[sign\] eth-sign-request ok: \d+ bytes sha256=([0-9a-f]{64})", chunk)
    check("sign: ETH sha256 matches host oracle",
          bool(m2) and m2.group(1) == exp["eth_sha256"],
          (m2.group(1)[:16] + "..." if m2 else "no sha line"))

    # 7. liveness after all of it (heartbeats still ticking)
    hb_before = len(re.findall(r"\[hb\]", text()))
    time.sleep(7)
    hb_after = len(re.findall(r"\[hb\]", text()))
    check("liveness: heartbeats still running after the exercises",
          hb_after > hb_before, f"{hb_before} -> {hb_after}")

    stop.set()
    th.join(timeout=2)
    os.close(fd)

    with open(LOG, "w") as f:
        f.write(text())

    print("SMOKE ALL PASS" if all(results) else "SMOKE FAILED")
    print(f"log: {LOG}")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
