#!/usr/bin/env python3
"""Run the pico2 bench-channel test against a flashed board.

Prerequisites:
  1. the bench fixtures exist (generated on the host):
       cargo test --release --test pico2_smoke_parity -- --ignored --nocapture
     which writes /tmp/shlosilo_sparrow_fragments.txt and
     /tmp/shlosilo_bench_expected.txt;
  2. the board runs firmware with the console bench channel and is plugged in
     (/dev/ttyACM0 on Linux; see ../99-shlosilo-pico2.rules).

The script drives the channel and checks the board's output against the
host-pinned values:
  - ETH fixture UR  -> 89-byte ur:eth-signature container (full hex + sha256)
  - Sparrow 12.4 KiB PSBT as 32 multipart fragments -> signed PSBT
    (length + sha256)

Requires the bench build (`make pico2-bench-uf2`): the Sparrow session
uses the bench-only `entropy` command (audit #17).

`--btc-only` is the chain-subset face: the image declares `chain-btc` alone, so the ETH
request must be REFUSED. The flag feeds the same ETH fixture and asserts that no
`eth-sign-request ok:` line appears - a chain switch that silently accepts a request it
cannot sign is worse than one that refuses it, so the refusal is checked, not skipped.

Usage:  python3 run_bench.py [--dev /dev/ttyACM0] [--log /tmp/pico2-bench-run.log] [--btc-only]
Exit code 0 = all checks passed.
"""
import argparse
import os
import re
import select
import sys
import termios
import threading
import time
import tty

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
ETH_URI_FILE = os.path.join(REPO_ROOT, "flux", "host-sim", "fixture_eth_sign_request.txt")
EXP_DEFAULT = "/tmp/shlosilo_bench_expected.txt"
FRAGS_DEFAULT = "/tmp/shlosilo_sparrow_fragments.txt"
SPARROW_ENTROPY = "f284fb6ca9f4d5835455be65e4b22916"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="/dev/ttyACM0")
    ap.add_argument("--expected", default=EXP_DEFAULT)
    ap.add_argument("--fragments", default=FRAGS_DEFAULT)
    ap.add_argument("--log", default="/tmp/pico2-bench-run.log")
    ap.add_argument(
        "--btc-only",
        action="store_true",
        help="image declares chain-btc alone: require the ETH request to be refused",
    )
    args = ap.parse_args()

    for p in (args.expected, args.fragments, ETH_URI_FILE):
        if not os.path.exists(p):
            sys.exit(f"missing input: {p} (run the generator test first)")

    exp = {}
    with open(args.expected) as f:
        for line in f:
            line = line.strip()
            if line:
                k, v = line.split(" ", 1)
                exp[k] = v
    with open(ETH_URI_FILE) as f:
        eth_uri = f.read().strip()
    with open(args.fragments) as f:
        frags = [l.strip() for l in f if l.strip()]

    eth_note = exp["eth_sha256"][:16] + "..." if exp.get("eth_sha256") else "<absent>"
    print(f"expected: eth_sha256={eth_note} sparrow_sha256={exp['sparrow_sha256'][:16]}...")
    print(f"fixtures: 1 eth UR ({len(eth_uri)} chars), {len(frags)} sparrow fragments")

    t0 = time.time()
    while not os.path.exists(args.dev):
        if time.time() - t0 > 180:
            sys.exit("TIMEOUT: console never appeared")
        time.sleep(0.5)

    fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    # Host-side queue + device-side partial-line flush (see trng_test.py:
    # tty echo during the enumeration window can inject the device's own
    # boot banner into its RX, which the first command would merge with).
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
                    c = os.read(fd, 4096)
                except OSError:
                    break
                if c:
                    buf.extend(c)

    th = threading.Thread(target=reader, daemon=True)
    th.start()

    def send(s):
        os.write(fd, (s + "\n").encode())

    def wait_for(marker, timeout):
        t = time.time()
        while time.time() - t < timeout:
            if marker in buf.decode(errors="replace"):
                return True
            time.sleep(0.2)
        return False

    time.sleep(3)  # drain boot output
    send("version")
    time.sleep(0.4)
    # Build-flavor gate: the Sparrow session below uses the bench-only
    # `entropy` command (audit #17); require the bench build.
    probe_deadline = time.time() + 10
    while "[ver]" not in buf.decode(errors="replace") and time.time() < probe_deadline:
        time.sleep(0.2)
    fm = re.search(r"\[ver\].*?build=(\w+)", buf.decode(errors="replace"))
    if not fm or fm.group(1) != "bench":
        stop.set()
        th.join(timeout=2)
        os.close(fd)
        sys.exit(f"ABORT: board build={fm.group(1) if fm else 'unknown'}; "
                 "this bench runner needs the bench build: make pico2-bench-uf2")
    send("heap reset")
    time.sleep(0.4)

    # ── ETH fixture, default dice session ──
    # On a chain-subset image this must be refused; feeding it anyway is what turns
    # "the ETH arm is compiled out" from a claim about the build into an observed fact.
    print("feeding eth fixture UR ...")
    send(eth_uri)
    ok = wait_for("[sign] eth-sign-request", 30)
    print("  eth sign appeared:", ok)
    time.sleep(0.5)
    send("heap")
    time.sleep(0.5)
    if args.btc_only:
        send("urclear")
        time.sleep(0.4)

    # ── Sparrow session ──
    print("setting sparrow session entropy ...")
    send(f"entropy {SPARROW_ENTROPY}")
    time.sleep(0.6)
    send("heap reset")
    time.sleep(0.4)
    print(f"feeding {len(frags)} sparrow fragments ...")
    for f in frags:
        send(f)
        time.sleep(0.03)
    ok = wait_for("[sign] crypto-psbt", 90)
    print("  sparrow sign appeared:", ok)
    time.sleep(0.5)
    send("heap")
    time.sleep(0.5)

    stop.set()
    th.join(timeout=2)
    os.close(fd)

    text = buf.decode(errors="replace")
    with open(args.log, "w") as f:
        f.write(text)

    results = []

    def check(name, cond, detail=""):
        results.append(cond)
        print(("PASS " if cond else "FAIL ") + name + (("  :: " + detail) if detail else ""))

    m = re.search(r"\[sign\] eth-sign-request ok: (\d+) bytes sha256=([0-9a-f]{64})", text)
    m2 = re.search(r"\[sign\] eth-sign-request hex: ([0-9a-f]+)", text)
    if args.btc_only:
        # The refusal is the assertion here: an image that declares one chain must not
        # produce a signature for another. Scope the search to what the device printed
        # AFTER the fed URI, so the boot smoke's own ETH attempt (which cannot be read as
        # an answer to our command) cannot satisfy the check by accident.
        mark = text.rfind(eth_uri[:40])
        window = text[mark:] if mark >= 0 else text
        wm = re.search(r"\[sign\] eth-sign-request ok: (\d+) bytes", window)
        check("eth refused (no signature for the fed request)", not wm,
              wm.group(0) if wm else "")
        eth_errs = [ln for ln in window.split("\r\n") if "[err]" in ln and "eth" in ln.lower()]
        check("eth refusal is reported on the console", bool(eth_errs),
              eth_errs[0].strip() if eth_errs else "silently dropped")
        check("boot smoke also cannot sign ETH on this face",
              "[sign] eth-sign-request ok:" not in text,
              "a boot-smoke ETH signature exists, so chain-eth is still linked")
    else:
        check("eth ok line present", bool(m))
        if m:
            check("eth sha256 matches host", m.group(2) == exp["eth_sha256"], m.group(2))
        check("eth full hex matches host", bool(m2) and m2.group(1) == exp["eth_hex"])

    m3 = re.search(r"\[sign\] crypto-psbt ok: (\d+) bytes sha256=([0-9a-f]{64})", text)
    check("sparrow ok line present", bool(m3))
    if m3:
        check("sparrow length matches host", m3.group(1) == exp["sparrow_len"], m3.group(1))
        check("sparrow sha256 matches host", m3.group(2) == exp["sparrow_sha256"], m3.group(2))

    frag_lines = re.findall(r"\[ur\] frag \d+/\d+ \((new|dup)\) \d+%", text)
    check(
        f"all {exp['fragment_count']} fragments accepted",
        len(frag_lines) == int(exp["fragment_count"]),
        f"got {len(frag_lines)}",
    )
    check("ur session completed", "[ur] complete: type=crypto-psbt" in text)

    for line in text.split("\r\n"):
        if "[heap]" in line or "[smoke] heap" in line:
            print("  " + line.strip())

    print("ALL PASS" if all(results) else "SOME FAILED")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
