#!/usr/bin/env python3
"""Drive the XMR signing flow on the pico2 bench channel.

Sequence:
  1. set the session mnemonic to the smoke fixture wallet (`entropy 11...`);
  2. `xmrseed <hex>`: fixed entropy for a byte-exact host A/B (default), or
     `--trng` to exercise the production entropy path;
  3. feed the xmr-txunsigned UR (from xmr_device_peak_fixture);
  4. wait for `[xmr] signed ok` - the signing stretch stalls the executor
     (CN scratchpad + BP+ prove, scratchpad in PSRAM), so mid-sign silence
     including missing heartbeats is EXPECTED; the wait budget is minutes;
  5. fetch the blob via `xmrout` in 512-char segments and assemble
     /tmp/xmr_device_signed.bin.
Then run the host A/B:
  cargo test --release --test xmr_device_blob_verify -- --ignored --nocapture

Usage: python3 xmr_sign.py [--trng] [--dev /dev/ttyACM0] [--timeout 900]
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

SMOKE_ENTROPY = "11" * 16  # -> the idx12 smoke wallet
FIXED_ENTROPY = "77" * 32  # must match FIXED_ENTROPY in the verify test
UR_FILE = "/tmp/xmr_smoke_ur.txt"
OUT_BIN = "/tmp/xmr_device_signed.bin"
LOG = "/tmp/pico2-xmr-run.log"

SIGNED_RE = re.compile(
    r"\[xmr\] signed ok: (\d+) bytes in (\d+) ms sha256=([0-9a-f]{64})"
)
XMR_OUT_RE = re.compile(r"\[xmrout\] (\d+)\+(\d+)/(\d+) ([0-9a-f]+)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="/dev/ttyACM0")
    ap.add_argument("--trng", action="store_true",
                    help="use the TRNG entropy path instead of fixed A/B entropy")
    ap.add_argument("--timeout", type=int, default=900,
                    help="seconds to wait for the signing result")
    ap.add_argument("--log", default=LOG)
    args = ap.parse_args()

    if not os.path.exists(UR_FILE):
        sys.exit(f"missing {UR_FILE} (run xmr_device_peak_fixture first)")
    with open(UR_FILE) as f:
        ur = f.read().strip()

    t0 = time.time()
    while not os.path.exists(args.dev):
        if time.time() - t0 > 300:
            sys.exit("TIMEOUT: console never appeared")
        time.sleep(0.5)

    fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
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
    time.sleep(2.5)

    def text():
        return buf.decode(errors="replace")

    def send(cmd):
        os.write(fd, (cmd + "\n").encode())

    def wait_marker(marker, timeout, start=0):
        t = time.time()
        while time.time() - t < timeout:
            if marker in text()[start:]:
                return True
            time.sleep(0.3)
        return False

    # 1. session wallet + entropy mode
    before = len(buf)
    send(f"entropy {SMOKE_ENTROPY}")
    wait_marker("[entropy] session key set", 10, before)

    if not args.trng:
        before = len(buf)
        send(f"xmrseed {FIXED_ENTROPY}")
        wait_marker("[xmr] fixed entropy set", 10, before)
        print("entropy: FIXED (A/B mode)")
    else:
        print("entropy: TRNG (production path)")

    # 2. feed the UR
    before = len(buf)
    print(f"feeding xmr UR ({len(ur)} chars) ...")
    send(ur)
    ok = wait_marker("[xmr] request:", 30, before)
    print("  request accepted:", ok)

    # 3. wait for the signing result (long stall expected)
    print(f"waiting for signing result (budget {args.timeout}s; silence is expected) ...")
    ok = wait_marker("[xmr] signed ok", args.timeout, before)
    if not ok:
        chunk = text()[before:]
        fails = [l for l in chunk.split("\r\n") if "[err]" in l or "FAILED" in l]
        print("NO RESULT. error lines:")
        for l in fails[-5:]:
            print("  " + l.strip())
        sys.exit(1)
    m = SIGNED_RE.search(text()[before:])
    if not m:
        sys.exit("signed-ok line unparseable")
    total_blob = int(m.group(1))
    total_hex = total_blob * 2
    print(f"  signed: {total_blob} bytes in {int(m.group(2))/1000:.1f}s sha256={m.group(3)}")

    # 4. fetch the blob in segments
    print(f"fetching {total_hex} hex chars via xmrout ...")
    assembled = []
    off = 0
    while off < total_hex:
        before = len(buf)
        send(f"xmrout {off} 512")
        if not wait_marker("[xmrout]", 30, before):
            sys.exit(f"xmrout at {off} produced no response")
        chunk = text()[before:]
        ms = XMR_OUT_RE.findall(chunk)
        if not ms:
            sys.exit(f"xmrout at {off}: no segment line")
        last = ms[-1]
        seg_off, seg_len = int(last[0]), int(last[1])
        hex_seg = last[3]
        if seg_off != off or len(hex_seg) != seg_len:
            sys.exit(f"xmrout mismatch at {off}: got off={seg_off} len={len(hex_seg)}")
        assembled.append(hex_seg)
        off += seg_len
        time.sleep(0.15)  # keep the pipe drained

    blob = bytes.fromhex("".join(assembled))
    if len(blob) != total_blob:
        sys.exit(f"assembled {len(blob)} bytes, expected {total_blob}")
    with open(OUT_BIN, "wb") as f:
        f.write(blob)
    print(f"blob assembled: {len(blob)} bytes -> {OUT_BIN}")

    # 5. liveness after the stretch
    time.sleep(6)
    hb = len(re.findall(r"\[hb\]", text()))
    print(f"heartbeats seen in this session: {hb}")

    stop.set()
    th.join(timeout=2)
    os.close(fd)
    with open(args.log, "w") as f:
        f.write(text())
    print(f"log: {args.log}")
    print("now run: cargo test --release --test xmr_device_blob_verify -- --ignored --nocapture")


if __name__ == "__main__":
    main()
