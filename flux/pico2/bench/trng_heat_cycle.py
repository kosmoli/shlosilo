#!/usr/bin/env python3
# Die-heat cycle: perfbench bursts + `temp` logging (self-heating was ineffective; see docs).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Heat the die with perfbench bursts, logging temperature each cycle."""
import os, re, select, sys, termios, threading, time, tty

rounds = int(sys.argv[1]) if len(sys.argv) > 1 else 6
iters = int(sys.argv[2]) if len(sys.argv) > 2 else 30000000

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
text = lambda: buf.decode(errors="replace")  # noqa: E731

def read_temp():
    before = len(buf)
    os.write(fd, b"\ntemp\n")
    t0 = time.time()
    while time.time() - t0 < 10:
        m = re.search(r"\[temp\] ([0-9.]+) C", text()[before:])
        if m:
            return float(m.group(1))
        time.sleep(0.2)
    return None

print(f"baseline temp: {read_temp()} C", flush=True)
for i in range(rounds):
    before = len(buf)
    os.write(fd, f"\nperfbench fmul {iters}\n".encode())
    t0 = time.time()
    while time.time() - t0 < 300:
        if "[pf] fmul" in text()[before:]:
            break
        time.sleep(0.5)
    t = read_temp()
    print(f"round {i+1}/{rounds}: perfbench fmul {iters} done, temp = {t} C", flush=True)
    time.sleep(1)

stop.set(); th.join(timeout=2); os.close(fd)
print("heat cycle done")
