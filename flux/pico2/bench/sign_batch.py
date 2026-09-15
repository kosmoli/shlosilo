#!/usr/bin/env python3
# Sign-batch measurement protocol: warmup + N fixed-entropy signs, per-sign ms + phases.
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Net-account replication: N consecutive warm fixed-entropy signs.

Usage: python3 sign_batch.py <label> [n=4]
Prints per-sign totals + key bp phases; appends a summary line to
/tmp/sign_batch_results.txt for cross-firmware comparison.
"""
import os
import re
import select
import sys
import termios
import threading
import time
import tty

LABEL = sys.argv[1] if len(sys.argv) > 1 else "unlabeled"
N = int(sys.argv[2]) if len(sys.argv) > 2 else 4

DEV = "/dev/ttyACM0"
SMOKE_ENTROPY = "11" * 16
FIXED_ENTROPY = "77" * 32
UR_FILE = "/tmp/xmr_smoke_ur.txt"
RESULTS = "/tmp/sign_batch_results.txt"
LOG = f"/tmp/pico2-signbatch-{LABEL}.log"

with open(UR_FILE) as f:
    ur = f.read().strip()

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


# flavor gate + record firmware
before = len(buf)
send("version")
time.sleep(0.8)
hm = re.search(r"v0\.5\.0-poc4\+([a-z0-9-]+) \(build=(\w+(?:\+\w+)?)\)", text()[before:])
fw = hm.group(1) if hm else "?"
print(f"firmware: {fw}", flush=True)

send("faultclr")
time.sleep(0.4)
send("xmrchunk 12")
time.sleep(0.4)
# pre-warm the multiexp hot code (cold I-cache costs ~15%)
before = len(buf)
send("perfbench ctm 130 12 1")
wait_for("[pf] ctm", 120, before)
time.sleep(0.3)
before = len(buf)
send("perfbench xchain 130 1 1 1")
wait_for("[pf] xchain", 180, before)
time.sleep(0.3)
print("pre-warm done", flush=True)

send(f"entropy {SMOKE_ENTROPY}")
time.sleep(0.4)

signs = []
for i in range(N):
    send(f"xmrseed {FIXED_ENTROPY}")
    time.sleep(0.4)
    before = len(buf)
    send(ur)
    if not wait_for("[xmr] request:", 60, before):
        sys.exit("FAIL: no request echo")
    print(f"sign {i+1}/{N} (silence ~17s)...", flush=True)
    if not wait_for("[xmr] signed ok", 400, before):
        sys.exit("FAIL: signing timeout/crash")
    time.sleep(1.0)
    chunk = text()[before:]
    sm = re.search(r"\[xmr\] signed ok: (\d+) bytes in (\d+) ms sha256=([0-9a-f]{64})", chunk)
    tx = re.findall(r"\[xt\] tx:((?: \d+=\d+)+)", chunk)
    bp = re.findall(r"\[xt\] bp:((?: \d+=\d+)+)", chunk)
    cn = re.findall(r"\[xt\] cn:((?: \d+=\d+)+)", chunk)
    txm = {int(k): int(v) for k, v in re.findall(r"(\d+)=(\d+)", tx[-1])} if tx else {}
    bpm = {int(k): int(v) for k, v in re.findall(r"(\d+)=(\d+)", bp[-1])} if bp else {}
    cnm = {int(k): int(v) for k, v in re.findall(r"(\d+)=(\d+)", cn[-1])} if cn else {}
    s = {"ms": int(sm.group(2)), "sha": sm.group(3), "bp1": bpm.get(1), "bp5": bpm.get(5),
         "bp6": bpm.get(6), "clsag": txm.get(4), "cn5": cnm.get(5)}
    signs.append(s)
    print(f"  {s['ms']} ms  bp1={s['bp1']} bp5={s['bp5']} bp6={s['bp6']} clsag={s['clsag']} cn5={s['cn5']}",
          flush=True)
    time.sleep(1.2)

stop.set()
th.join(timeout=2)
os.close(fd)
with open(LOG, "w") as f:
    f.write(text())

avg = sum(s["ms"] for s in signs) / len(signs)
print()
print(f"=== {LABEL} ({fw}): {len(signs)} signs ===")
for k in ("ms", "bp1", "bp5", "bp6", "clsag", "cn5"):
    vals = [s[k] for s in signs if s[k] is not None]
    if vals:
        print(f"  {k:>6}: min={min(vals)} max={max(vals)} avg={sum(vals)/len(vals):.1f}")
sha_set = {s["sha"] for s in signs}
print(f"  sha256: {'ALL IDENTICAL ' + list(sha_set)[0][:16] if len(sha_set) == 1 else 'DIFFERS!'}")

with open(RESULTS, "a") as f:
    f.write(f"{LABEL}\t{fw}\t{len(signs)}")
    for k in ("ms", "bp1", "bp5", "bp6", "clsag", "cn5"):
        vals = [s[k] for s in signs if s[k] is not None]
        f.write(f"\t{k}={sum(vals)/len(vals):.0f}" if vals else f"\t{k}=?")
    f.write("\n")
print(f"appended to {RESULTS}")
