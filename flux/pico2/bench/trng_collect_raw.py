#!/usr/bin/env python3
# Raw-ROSC capture via the bench console (`trngraw` + paced `trngrawout` dump).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Collect raw-ROSC capture data from the pico2 (SP 800-90B source data).

Usage: python3 collect_raw.py <label> <nblocks> [chain] [sample] [pace_ms]

Flow:
  1. `trngraw <n> [chain] [sample]`  -> capture into the board's PSRAM buffer
  2. `trngrawout 0 [pace_ms]`        -> stream back as `[traw] <idx> <hex>` lines
  3. verify block completeness (no gaps), assemble the packed binary
  4. write:
       /tmp/raw_<label>.bin         packed (24 B per 192-bit block)
       /tmp/raw_<label>_1bit.bin    one bit per byte (NIST tool format)
       /tmp/raw_<label>_1bit_msb.bin  same, MSB-first within bytes (order check)
       /tmp/raw_<label>.json        metadata (rate line, sha256, gaps)
  5. print sanity stats (ones fraction, lag-1, zero blocks)

Convention: sample k = bit (k mod 8) of packed byte (k div 8), LSB first.
"""
import hashlib
import json
import os
import re
import select
import sys
import termios
import threading
import time
import tty

label = sys.argv[1] if len(sys.argv) > 1 else "test"
nblocks = int(sys.argv[2]) if len(sys.argv) > 2 else 4096
chain = sys.argv[3] if len(sys.argv) > 3 else "4"  # int or "rand"
sample = int(sys.argv[4]) if len(sys.argv) > 4 else 0
pace_ms = int(sys.argv[5]) if len(sys.argv) > 5 else 1

DEV = "/dev/ttyACM0"
LOG = f"/tmp/collect_raw_{label}.log"

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
transcript = open(f"/tmp/collect_raw_{label}_transcript.txt", "wb")


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
                transcript.write(c)
                transcript.flush()


th = threading.Thread(target=reader, daemon=True)
th.start()
time.sleep(2.5)
text = lambda: buf.decode(errors="replace")  # noqa: E731


def send(s):
    os.write(fd, (s + "\n").encode())


def wait_for(marker, timeout, start=0):
    t = time.time()
    while time.time() - t < timeout:
        if marker in text()[start:]:
            return True
        if "[crash]" in text()[start:]:
            return False
        time.sleep(0.25)
    return False


# firmware gate
before = len(buf)
send("version")
time.sleep(0.8)
m = re.search(r"v0\.5\.0-poc4\+([a-z0-9-]+)", text()[before:])
fw = m.group(1) if m else "?"
print(f"firmware: {fw}", flush=True)

send("faultclr")
time.sleep(0.3)

# ── 1. capture ──
before = len(buf)
send(f"trngraw {nblocks} {chain} {sample}")
print(f">>> trngraw {nblocks} {chain} {sample}", flush=True)
if not wait_for("[traw] captured", 300, before):
    sys.exit("FAIL: capture timeout / error (see transcript)")
cm = re.search(
    r"\[traw\] captured (\d+) blocks = (\d+) raw bits in (\d+) ms \(([\d]+) kbit/s; ones~(\d+)e-3; zero-blocks=(\d+)[^)]*\)",
    text()[before:],
)
if not cm:
    sys.exit(f"FAIL: cannot parse capture line: {text()[before:][-300:]}")
got_blocks = int(cm.group(1))
rate_line = cm.group(0)
print(f"    {rate_line}", flush=True)
# print the raw-mode + wait-statistic lines (handshake audit)
wm = re.search(r"\[traw\] raw mode: [^\n]*", text()[before:])
if wm:
    print(f"    {wm.group(0)}", flush=True)
ws = re.search(r"\[traw\] waits=[^\n]*", text()[before:])
if ws:
    print(f"    {ws.group(0)}", flush=True)

# ── 2. dump ──
before = len(buf)
send(f"trngrawout 0 {pace_ms}")
print(f">>> trngrawout 0 {pace_ms}", flush=True)
if not wait_for("[traw] dump", 30, before):
    sys.exit("FAIL: no dump start line")
dm = re.search(r"\[traw\] dump 0\.\.(\d+) \(", text()[before:])
total = int(dm.group(1)) if dm else got_blocks
print(f"    dumping {total} blocks (pace {pace_ms} ms/line)...", flush=True)

assembled = bytearray(total * 24)
seen = bytearray(total)  # 1 = block present
LINE_RE = re.compile(r"\[traw\] (\d+) ([0-9a-f]+)\r?\n")
deadline = time.time() + max(120, total // 4 * pace_ms / 1000 * 6 + 60)
last_progress = 0
while time.time() < deadline:
    chunk = text()[before + len("[traw] dump".encode()):] if False else text()[before:]
    found_any = False
    for mm in LINE_RE.finditer(chunk):
        idx = int(mm.group(1))
        hexs = mm.group(2)
        if idx >= total:
            continue
        nbytes = len(hexs) // 2
        if nbytes > 24 * 4:
            continue
        if seen[idx]:
            continue
        # mark blocks covered by this line
        nblk = nbytes // 24
        for j in range(nblk):
            b = idx + j
            if b < total and not seen[b]:
                seen[b] = 1
                a = b * 24
                assembled[a:a + 24] = bytes.fromhex(hexs[j * 48:(j + 1) * 48])
        found_any = True
    if "[traw] done" in text()[before:]:
        # final sweep then break
        for mm in LINE_RE.finditer(text()[before:]):
            idx = int(mm.group(1))
            if idx < total and not seen[idx]:
                hexs = mm.group(2)
                nbytes = len(hexs) // 2
                nblk = nbytes // 24
                for j in range(nblk):
                    b = idx + j
                    if b < total and not seen[b]:
                        seen[b] = 1
                        a = b * 24
                        assembled[a:a + 24] = bytes.fromhex(hexs[j * 48:(j + 1) * 48])
        break
    # progress
    have = sum(seen)
    if have != last_progress and have % 4096 < 8:
        print(f"    ... {have}/{total} blocks", flush=True)
        last_progress = have
    if "[crash]" in text()[before:]:
        sys.exit("FAIL: device crashed during dump")
    time.sleep(0.5)

have = sum(seen)
gaps = [i for i, v in enumerate(seen) if not v]
print(f"    received {have}/{total} blocks; gaps: {len(gaps)}", flush=True)

stop.set()
th.join(timeout=2)
os.close(fd)
transcript.close()
with open(LOG, "w") as f:
    f.write(text())

if have == 0:
    sys.exit("FAIL: no data received")

# ── 3. write outputs ──
packed = bytes(assembled)
with open(f"/tmp/raw_{label}.bin", "wb") as f:
    f.write(packed)

# one bit per byte (LSB-first within each byte) for the NIST tool
onebit = bytearray(len(packed) * 8)
for i, byte in enumerate(packed):
    for b in range(8):
        onebit[i * 8 + b] = (byte >> b) & 1
with open(f"/tmp/raw_{label}_1bit.bin", "wb") as f:
    f.write(onebit)

# MSB-first variant (bit-order sensitivity check)
onebit_msb = bytearray(len(packed) * 8)
for i, byte in enumerate(packed):
    for b in range(8):
        onebit_msb[i * 8 + b] = (byte >> (7 - b)) & 1
with open(f"/tmp/raw_{label}_1bit_msb.bin", "wb") as f:
    f.write(onebit_msb)

sha = hashlib.sha256(packed).hexdigest()
meta = {
    "label": label,
    "firmware": fw,
    "nblocks_requested": nblocks,
    "blocks_total": total,
    "blocks_received": have,
    "gaps": len(gaps),
    "gap_first": gaps[:8],
    "chain": chain,
    "sample": sample,
    "pace_ms": pace_ms,
    "capture_line": rate_line,
    "sha256_packed": sha,
    "raw_bits": have * 192,
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
}
with open(f"/tmp/raw_{label}.json", "w") as f:
    json.dump(meta, f, indent=2)

# ── 4. sanity stats ──
ones = sum(bin(x).count("1") for x in packed)
total_bits = have * 192
print()
print(f"=== {label}: {have} blocks ({total_bits} raw bits) ===")
print(f"  ones fraction: {ones/total_bits:.4f}")
# lag-1 over the whole stream (bit i vs bit i+1)
eq = 0
prev = None
count = 0
for byte in packed:
    for b in range(8):
        bit = (byte >> b) & 1
        if prev is not None:
            count += 1
            if bit == prev:
                eq += 1
        prev = bit
print(f"  lag-1 equal fraction: {eq/count:.4f} (0.5 = uncorrelated)")
zero_blocks = sum(1 for i in range(have) if assembled[i * 24:(i + 1) * 24] == b"\x00" * 24)
print(f"  zero blocks: {zero_blocks}")
print(f"  packed -> /tmp/raw_{label}.bin (sha256 {sha[:16]}...)")
print(f"  1bit   -> /tmp/raw_{label}_1bit.bin ({len(onebit)} bytes = samples)")
print(f"  meta   -> /tmp/raw_{label}.json")
print(f"  transcript -> /tmp/collect_raw_{label}_transcript.txt")
