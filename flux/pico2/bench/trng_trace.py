#!/usr/bin/env python3
# DWT BUSY/VALID trace runner (`trngtrace`).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Run trngtrace and print the waveform."""
import os, re, select, sys, termios, threading, time, tty

blocks = sys.argv[1] if len(sys.argv) > 1 else "3"
chain = sys.argv[2] if len(sys.argv) > 2 else "4"
sample = sys.argv[3] if len(sys.argv) > 3 else "0"
window = sys.argv[4] if len(sys.argv) > 4 else "8192"

fd = os.open("/dev/ttyACM0", os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
try:
    termios.tcflush(fd, termios.TCIFLUSH)
except termios.error:
    pass
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
time.sleep(1.0)
os.write(fd, b"\nfaultclr\n")
time.sleep(0.3)
os.write(fd, f"\ntrngtrace {blocks} {chain} {sample} {window}\n".encode())
print(f">>> trngtrace {blocks} {chain} {sample} {window}", flush=True)
t0 = time.time()
text = lambda: buf.decode(errors="replace")  # noqa: E731
while time.time() - t0 < 60:
    if "[ttr] done" in text() or "trace failed" in text():
        break
    time.sleep(0.5)
time.sleep(1.0)
stop.set(); th.join(timeout=2); os.close(fd)
t = text()
# print all ttr lines
for line in t.splitlines():
    if "[ttr]" in line:
        print(line.strip())
