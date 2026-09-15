#!/usr/bin/env python3
# In-situ xchain perf probe (per-round L/R timing vs clean baselines).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""bp5 attribution round 2: cache-aligned alternating measurement.

Lesson from round 1: the bench commands warm the 32KB flash I-cache for the
multiexp hot code, so any "bench first, then sign" sequence measures the
sign in a WARM cache while earlier runs measured it COLD. Round 1 showed a
15% shift in ALL bp phases between the two firmwares' first signs.

Protocol (all on one firmware, no reflash):
  1. pre-warm: ctm + xchain once (both hot)
  2. alternate x3: ctm / xchain tail=0 / xchain tail=1  (same cache state)
  3. two consecutive fixed-entropy signs (warm) -> in-situ reference,
     plus the run-to-run delta of the sign itself
  4. cleanup: heap

Separates: wrapper-only tax (xchain t0 vs ctm), tail cost (t1 vs t0),
in-situ vs xchain residual, and the sign's warm-state repeatability.
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
SMOKE_ENTROPY = "11" * 16
FIXED_ENTROPY = "77" * 32
UR_FILE = "/tmp/xmr_smoke_ur.txt"
LOG = "/tmp/pico2-xchain2.log"

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


def wait_re(pat, timeout, start=0):
    t = time.time()
    while time.time() - t < timeout:
        mm = re.findall(pat, text()[start:])
        if mm:
            return mm
        if "[crash]" in text()[start:]:
            return None
        time.sleep(0.25)
    return None


# flavor gate
before = len(buf)
send("version")
time.sleep(0.8)
m = re.search(r"\[ver\].*?build=(\w+(?:\+\w+)?)", text()[before:])
if not m or "perf" not in m.group(1):
    sys.exit(f"ABORT: build={m.group(1) if m else '?'}; needs the xchain firmware")
print(f"board build={m.group(1)}", flush=True)

send("faultclr")
time.sleep(0.4)
send("xmrchunk 12")
time.sleep(0.4)

# ── 1. pre-warm both paths ──
before = len(buf)
send("perfbench ctm 130 12 1")
wait_re(r"\[pf\] ctm", 120, before)
time.sleep(0.3)
before = len(buf)
send("perfbench xchain 130 1 1 1")
wait_re(r"\[pf\] xchain", 120, before)
time.sleep(0.3)
print("pre-warm done", flush=True)

# ── 2. alternating measurements ──
runs = {"ctm": [], "xt0": [], "xt1": []}
for rep in range(3):
    for key, cmd, pat in (
        ("ctm", "perfbench ctm 130 12 1", r"\[pf\] ctm n=130 chunk=12 iters=1: \d+us total, (\d+)us/chunk"),
        ("xt0", "perfbench xchain 130 1 0 0", r"\[pf\] xchain n=130 iters=1 tail=0 gen=0: \d+us total, (\d+)us/call"),
        ("xt1", "perfbench xchain 130 1 1 1", r"\[pf\] xchain n=130 iters=1 tail=1 gen=1: \d+us total, (\d+)us/call"),
    ):
        before = len(buf)
        send(cmd)
        mm = wait_re(pat, 120, before)
        if mm:
            runs[key].append(int(mm[-1]))
        time.sleep(0.3)
    print(f"rep{rep}: ctm={runs['ctm'][-1]} xt0={runs['xt0'][-1]} xt1={runs['xt1'][-1]}", flush=True)

# ── 3. two consecutive warm signs ──
send(f"entropy {SMOKE_ENTROPY}")
time.sleep(0.4)
signs = []
for i in range(2):
    send(f"xmrseed {FIXED_ENTROPY}")
    time.sleep(0.4)
    before = len(buf)
    send(ur)
    if not wait_re(r"\[xmr\] request:", 60, before):
        sys.exit("FAIL: no request echo")
    print(f"sign #{i+1} (silence ~17s)...", flush=True)
    if not wait_re(r"\[xmr\] signed ok", 400, before):
        sys.exit("FAIL: signing timeout/crash")
    time.sleep(1.0)
    chunk = text()[before:]
    sm = re.search(r"\[xmr\] signed ok: (\d+) bytes in (\d+) ms", chunk)
    bp = re.findall(r"\[xt\] bp:((?: \d+=\d+)+)", chunk)
    insitu = {int(k): int(v) for k, v in re.findall(r"(\d+)=(\d+)", bp[-1])} if bp else {}
    signs.append({
        "ms": int(sm.group(2)),
        "L1": insitu.get(11, 0),
        "R1": insitu.get(21, 0),
        "bp1": insitu.get(1, 0),
        "bp5": insitu.get(5, 0),
        "bp6": insitu.get(6, 0),
    })
    print(f"  sign#{i+1}: {signs[-1]['ms']}ms bp1={signs[-1]['bp1']} bp5={signs[-1]['bp5']} "
          f"bp6={signs[-1]['bp6']} L1={signs[-1]['L1']} R1={signs[-1]['R1']}", flush=True)
    time.sleep(1.5)

stop.set()
th.join(timeout=2)
os.close(fd)
with open(LOG, "w") as f:
    f.write(text())

print()
print("=== round-2 summary (all warm, same firmware) ===")
for key, label in (("ctm", "ctm direct (no wrapper, no tail)"),
                   ("xt0", "xchain wrapper, no tail"),
                   ("xt1", "xchain wrapper + tail")):
    vals = runs[key]
    if vals:
        avg = sum(vals) / len(vals)
        print(f"{label:<34}: {vals} avg {avg:.0f} us")
if runs["ctm"] and runs["xt0"] and runs["xt1"]:
    c = sum(runs["ctm"]) / len(runs["ctm"])
    x0 = sum(runs["xt0"]) / len(runs["xt0"])
    x1 = sum(runs["xt1"]) / len(runs["xt1"])
    print()
    print(f"wrapper tax  (xt0 - ctm) : {x0 - c:>8.0f} us")
    print(f"tail cost    (xt1 - xt0) : {x1 - x0:>8.0f} us")
    print(f"wrapper+tail (xt1 - ctm) : {x1 - c:>8.0f} us")
    if signs:
        s = signs[-1]
        print(f"in-situ L1 (warm)        : {s['L1'] * 1000:>8.0f} us  (vs xt1 {x1:.0f})")
        print(f"in-situ residual (L1-xt1): {s['L1'] * 1000 - x1:>8.0f} us")
print()
if len(signs) == 2:
    d = signs[1]["ms"] - signs[0]["ms"]
    print(f"sign repeatability: {signs[0]['ms']}ms -> {signs[1]['ms']}ms (delta {d:+d}ms)")
