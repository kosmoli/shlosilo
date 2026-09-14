#!/usr/bin/env python3
"""XMR bring-up driver for the pico2 bench channel (v2).

Lesson from v1: the transcript must survive the run even when the device
dies mid-flow - this script appends every received chunk to a transcript
file immediately, so a frozen device still leaves the full evidence.

Flow:
  0. attach; dump 8 s                  ([hb] liveness; [psram]/[crash] lines)
  1. psramtest                         (write/read-back at 5 offsets; maps
                                       the psram heap on success)
  2. entropy <hex>                     (session wallet = smoke idx12)
  3. xmrseed <hex>                     (fixed entropy for host A/B) unless --trng
  4. feed the xmr-txunsigned UR; wait [xmr] request -> signed ok (long;
     executor stalls during signing - silence is expected)
  5. fetch the blob via `xmrout` -> /tmp/xmr_device_signed.bin
Then on the host:
  cargo test --release --test xmr_device_blob_verify -- --ignored --nocapture

Usage: python3 xmr_bringup.py [--trng] [--dev /dev/ttyACM0] [--timeout 1500]
"""
import argparse
import glob
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
TRANSCRIPT = "/tmp/pico2-bringup-transcript.txt"

SIGNED_RE = re.compile(r"\[xmr\] signed ok: (\d+) bytes in (\d+) ms sha256=([0-9a-f]{64})")
XMR_OUT_RE = re.compile(r"\[xmrout\] (\d+)\+(\d+)/(\d+) ([0-9a-f]+)")

# lines worth echoing to stdout live, in order of arrival
LIVE_RE = re.compile(
    r"\[psramtest\]|\[psram\]|\[alloctest\]|\[crash\]|\[entropy\]|\[xmr\]|\[xmrout\]|\[err\]|ALL OK"
)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", default="/dev/ttyACM0")
    ap.add_argument("--trng", action="store_true",
                    help="use the TRNG entropy path instead of fixed A/B entropy")
    ap.add_argument("--timeout", type=int, default=1500,
                    help="seconds to wait for the signing result")
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

    # Mutable holder: the reader swaps the node/fd on device resets.
    state = {"fd": fd, "node": args.dev}

    transcript = open(TRANSCRIPT, "ab")
    buf = bytearray()
    stop = threading.Event()
    seen = 0  # bytes already echoed live

    def reader():
        nonlocal seen
        while not stop.is_set():
            # Node-follow: a device reset removes the tty node; select() on
            # the orphaned fd stays silent (measured on this bench). Poll the
            # path itself and reattach to whatever node comes back.
            if not os.path.exists(state["node"]):
                try:
                    os.close(state["fd"])
                except OSError:
                    pass
                note = (
                    f"\n### NODE LOST ({state['node']}); rescanning for the "
                    "rebooted device...\n"
                )
                print(note, flush=True)
                transcript.write(note.encode())
                transcript.flush()
                t0 = time.time()
                while time.time() - t0 < 60:
                    nodes = sorted(glob.glob("/dev/ttyACM*"), key=os.path.getmtime)
                    if nodes:
                        try:
                            nfd = os.open(
                                nodes[-1], os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK
                            )
                            tty.setraw(nfd)
                            state["node"] = nodes[-1]
                            state["fd"] = nfd
                            fresh = f"### reattached to {nodes[-1]} ###\n"
                            print(fresh, flush=True)
                            transcript.write(fresh.encode())
                            transcript.flush()
                            break
                        except OSError:
                            pass
                    time.sleep(0.5)
                continue
            try:
                r, _, _ = select.select([state["fd"]], [], [], 0.2)
            except (OSError, ValueError):
                state["node"] = "/dev/ttyACM_gone"
                continue
            if r:
                try:
                    c = os.read(state["fd"], 8192)
                except OSError:
                    state["node"] = "/dev/ttyACM_gone"
                    continue
                if c:
                    buf.extend(c)
                    transcript.write(c)
                    transcript.flush()
                    text = buf[seen:].decode(errors="replace")
                    seen = len(buf)
                    for line in text.replace("\r\n", "\n").split("\n"):
                        if not line.strip():
                            continue
                        if LIVE_RE.search(line):
                            print(f"  dev| {line.rstrip()}", flush=True)

    th = threading.Thread(target=reader, daemon=True)
    th.start()
    print(f"opened {args.dev}; transcript -> {TRANSCRIPT}", flush=True)
    time.sleep(8)
    print(f"  (settled; {len(buf)} bytes so far)", flush=True)

    def text():
        return buf.decode(errors="replace")

    def send(cmd):
        n = os.write(state["fd"], (cmd + "\n").encode())
        print(f">>> {n}B: {cmd[:48]}{'...' if len(cmd) > 48 else ''}", flush=True)

    def wait_marker(marker, timeout, start=0):
        t = time.time()
        while time.time() - t < timeout:
            if marker in text()[start:]:
                return True
            time.sleep(0.25)
        return False

    def fail(step, start):
        print(f"\n### FAILED at: {step}", flush=True)
        chunk = text()[start:]
        tail = [l for l in chunk.replace("\r\n", "\n").split("\n") if l.strip()][-12:]
        print("last device output in window:")
        for l in tail:
            print("  " + l, flush=True)
        print(f"full transcript: {TRANSCRIPT}", flush=True)
        stop.set()
        transcript.close()
        sys.exit(1)

    # ---- step 1: psramtest ----
    before = len(buf)
    send("psramtest")
    t = time.time()
    while time.time() - t < 180:
        chunk = text()[before:]
        if "ALL OK" in chunk:
            print("  psramtest: ALL OK (psram heap mapped)", flush=True)
            break
        if "FAILED" in chunk or "no mapped region" in chunk:
            fail("psramtest", before)
        time.sleep(0.5)
    else:
        fail("psramtest (timeout: hung mid-op - see last line above)", before)

    # ---- step 1b: allocator sweep (which sizes can the heaps serve?) ----
    before = len(buf)
    send("alloctest sweep")
    if not wait_marker("[alloctest] sweep done", 120, before):
        fail("alloctest sweep", before)
    print("  alloctest sweep complete", flush=True)

    # ---- step 2: session wallet ----
    before = len(buf)
    send(f"entropy {SMOKE_ENTROPY}")
    if not wait_marker("[entropy] session key set", 15, before):
        fail("entropy (session wallet)", before)
    print("  session wallet set", flush=True)

    # ---- step 3: entropy mode ----
    if not args.trng:
        before = len(buf)
        send(f"xmrseed {FIXED_ENTROPY}")
        if not wait_marker("[xmr] fixed entropy set", 15, before):
            fail("xmrseed", before)
        print("  entropy: FIXED (A/B mode)", flush=True)
    else:
        print("  entropy: TRNG (production path)", flush=True)

    # ---- step 4: feed the UR ----
    before = len(buf)
    send(ur)
    # Crash-aware wait for the request echo: a [crash] means the device
    # panicked in the decode/ingest path (or the request itself).
    t = time.time()
    got_req = False
    while time.time() - t < 60:
        chunk = text()[before:]
        if "[xmr] request:" in chunk:
            got_req = True
            break
        if "[crash]" in chunk:
            time.sleep(8)
            fail("device CRASHED while ingesting the UR (record above)", before)
        time.sleep(0.4)
    if not got_req:
        fail("XMR request accepted", before)
    print("  request accepted; signing (silence expected, budget "
          f"{args.timeout}s) ...", flush=True)
    # Crash-aware wait: a [crash] record means the device panicked and
    # rebooted (node-followed by the reader) - fail fast with the record
    # instead of burning the whole budget.
    t = time.time()
    got_signed = False
    while time.time() - t < args.timeout:
        chunk = text()[before:]
        if "[xmr] signed ok" in chunk:
            got_signed = True
            break
        if "[crash]" in chunk:
            time.sleep(8)  # let the record and boot lines finish
            fail("device CRASHED during signing (record above)", before)
        time.sleep(0.5)
    if not got_signed:
        fail("XMR signing timeout", before)
    m = SIGNED_RE.search(text()[before:])
    if not m:
        fail("signed-ok line parse", before)
    assert m is not None
    total_blob = int(m.group(1))
    total_hex = total_blob * 2
    print(f"  SIGNED: {total_blob} bytes in {int(m.group(2))/1000:.2f}s", flush=True)

    # ---- step 5: fetch the blob ----
    assembled = []
    off = 0
    while off < total_hex:
        before = len(buf)
        send(f"xmrout {off} 512")
        if not wait_marker("[xmrout]", 30, before):
            fail(f"xmrout at {off}", before)
        ms = XMR_OUT_RE.findall(text()[before:])
        if not ms:
            fail(f"xmrout at {off}: no segment", before)
        seg_off, seg_len, _, hex_seg = ms[-1]
        if int(seg_off) != off or len(hex_seg) != int(seg_len):
            fail(f"xmrout mismatch at {off}", before)
        assembled.append(hex_seg)
        off += int(seg_len)
        time.sleep(0.1)
    blob = bytes.fromhex("".join(assembled))
    if len(blob) != total_blob:
        fail(f"assembled {len(blob)} != {total_blob}", before)
    with open(OUT_BIN, "wb") as f:
        f.write(blob)
    print(f"blob assembled: {len(blob)} bytes -> {OUT_BIN}", flush=True)

    # ---- liveness after the stretch ----
    time.sleep(6)
    hb = len(re.findall(r"\[hb\]", text()))
    print(f"heartbeats this session: {hb}", flush=True)
    stop.set()
    transcript.close()
    print("DONE; now run: cargo test --release --test xmr_device_blob_verify "
          "-- --ignored --nocapture", flush=True)


if __name__ == "__main__":
    main()
