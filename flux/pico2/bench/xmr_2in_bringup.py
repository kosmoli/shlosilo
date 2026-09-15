#!/usr/bin/env python3
"""P64 device run: 2-input XMR fixture → device sign → blob fetch (task 4).

Prereq: bench firmware on /dev/ttyACM0 (has `entropy`/`xmrseed`), board plugged in.
Feeds /tmp/xmr_2in_frames.txt (fountain multipart, 18 fragments x 2 rounds).

Flow: version gate → faultclr → entropy <dev wallet> → xmrseed <fixed> →
      feed frames → wait signed ok → fetch blob → /tmp/xmr_2in_device.bin.
Then: python3 /tmp/p64_compare.py compares against /tmp/p64_host_ab.bin.
"""
import os, re, select, sys, termios, threading, time, tty

DEV = "/dev/ttyACM0"
FRAMES = "/tmp/xmr_2in_frames.txt"
OUT_BIN = "/tmp/xmr_2in_device.bin"
TRANSCRIPT = "/tmp/p64_device_transcript.txt"

DEV_ENTROPY = "4a9291a702c0ba28aa285882efde4f2c9237556ceb685570d595fd6586074530"
FIXED_ENTROPY = "77" * 32
SIGN_BUDGET_S = 600

SIGNED_RE = re.compile(r"\[xmr\] signed ok: (\d+) bytes in (\d+) ms sha256=([0-9a-f]{64})")
XMR_OUT_RE = re.compile(r"\[xmrout\] (\d+)\+(\d+)/(\d+) ([0-9a-f]+)")

if not os.path.exists(DEV):
    sys.exit(f"missing {DEV} (plug the board in)")
if not os.path.exists(FRAMES):
    sys.exit(f"missing {FRAMES}")

frames = [l.strip() for l in open(FRAMES) if l.strip()]
print(f"{len(frames)} frames loaded", flush=True)

fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
try:
    termios.tcflush(fd, termios.TCIFLUSH)
except termios.error:
    pass
buf = bytearray()
stop = threading.Event()
transcript = open(TRANSCRIPT, "wb")


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
time.sleep(1.0)
text = lambda: buf.decode(errors="replace")  # noqa: E731


def send(s):
    os.write(fd, (s + "\n").encode())


def wait(marker, timeout, start):
    t0 = time.time()
    while time.time() - t0 < timeout:
        chunk = text()[start:]
        if marker in chunk:
            return True
        if "[crash]" in chunk:
            print("!! device crashed", flush=True)
            return False
        time.sleep(0.3)
    return False


# 0) version gate
before = len(buf)
send("version")
time.sleep(1.0)
m = re.search(r"v0\.5\.0-poc4\+([a-z0-9-]+) \(build=([a-z+]+)\)", text()[before:])
if not m:
    sys.exit("no version line")
fw, flavor = m.group(1), m.group(2)
print(f"firmware {fw} ({flavor})", flush=True)
if "bench" not in flavor:
    sys.exit("need a bench build (entropy/xmrseed are bench-only)")

send("faultclr")
time.sleep(0.3)

# 1) session wallet (our deterministic dev wallet)
before = len(buf)
send(f"entropy {DEV_ENTROPY}")
if not wait("session key set", 15, before):
    sys.exit("entropy command failed")
print("session wallet set", flush=True)

# 2) fixed signer entropy (A/B mode)
before = len(buf)
send(f"xmrseed {FIXED_ENTROPY}")
if not wait("fixed entropy set", 15, before):
    sys.exit("xmrseed failed")
print("fixed entropy set", flush=True)

# 3) feed the fountain frames
before = len(buf)
print("feeding frames...", flush=True)
for i, fr in enumerate(frames):
    send(fr)
    time.sleep(0.15)
    if (i + 1) % 9 == 0:
        print(f"  {i+1}/{len(frames)}", flush=True)

# wait for request acceptance
if not wait("[xmr] request:", 60, before):
    sys.exit("XMR request not accepted")
print("request accepted; signing (executor stalls, be patient)...", flush=True)

# 4) wait for the signed result
t0 = time.time()
signed = None
while time.time() - t0 < SIGN_BUDGET_S:
    m = SIGNED_RE.search(text()[before:])
    if m:
        signed = m
        break
    if "[crash]" in text()[before:]:
        time.sleep(8)
        sys.exit("device crashed during signing")
    time.sleep(0.5)
if not signed:
    sys.exit(f"signing timeout after {SIGN_BUDGET_S}s")
total_blob, ms, sha = int(signed.group(1)), int(signed.group(2)), signed.group(3)
print(f"SIGNED: {total_blob} bytes in {ms/1000:.2f}s sha256={sha}", flush=True)

# 5) fetch the blob
assembled = []
off = 0
while off < total_blob * 2:
    before = len(buf)
    send(f"xmrout {off} 512")
    if not wait("[xmrout]", 30, before):
        sys.exit(f"xmrout failed at {off}")
    ms2 = XMR_OUT_RE.findall(text()[before:])
    if not ms2:
        sys.exit(f"no xmrout segment at {off}")
    seg_off, seg_len, _, hex_seg = ms2[-1]
    if int(seg_off) != off or len(hex_seg) != int(seg_len):
        sys.exit(f"xmrout mismatch at {off}")
    assembled.append(hex_seg)
    off += int(seg_len)
    time.sleep(0.1)

blob = bytes.fromhex("".join(assembled))
if len(blob) != total_blob:
    sys.exit(f"assembled {len(blob)} != {total_blob}")
with open(OUT_BIN, "wb") as f:
    f.write(blob)
import hashlib
print(f"blob: {len(blob)} bytes -> {OUT_BIN}", flush=True)
print(f"blob sha256: {hashlib.sha256(blob).hexdigest()}", flush=True)
print(f"expect (host A/B): {sha}", flush=True)

stop.set()
th.join(timeout=2)
os.close(fd)
transcript.close()
print("DONE", flush=True)
