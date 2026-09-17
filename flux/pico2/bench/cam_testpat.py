#!/usr/bin/env python3
"""Enable the OV5640 internal color-bar test pattern and dump the AEC/AGC
state. The test pattern is scene-independent ground truth: it lets us tell
"capture path broken" apart from "optics/scene" without needing the user.

Register map (OV5640):
  0x503D  PRE_ISP_TEST_SET1  bit7=enable, low bits=pattern (0=color bar)
  0x3503  AEC/AGC manual control (bit0=AEC, bit1=AGC)
  0x3500/01/02  exposure (24-bit)
  0x350A/0B     gain (16-bit)
"""
import glob
import os
import select
import sys
import time
import tty

DEVS = sorted(glob.glob('/dev/ttyACM*')) or sorted(glob.glob('/dev/ttyUSB*'))
if not DEVS:
    sys.exit('no serial console found')
DEV = DEVS[0]
print('console:', DEV)
fd = os.open(DEV, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)


def drain(t=0.3):
    out = b''
    try:
        while True:
            r, _, _ = select.select([fd], [], [], t)
            if not r:
                break
            d = os.read(fd, 4096)
            if not d:
                break
            out += d
    except Exception:
        pass
    return out


def cmd(c, wait=0.8):
    os.write(fd, (c + '\n').encode())
    deadline = time.time() + wait
    buf = b''
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            d = os.read(fd, 4096)
            if d:
                buf += d
    for line in buf.decode('utf-8', 'replace').splitlines():
        if '[cam]' in line or '[err]' in line:
            print('  ' + line)
    return buf


drain(0.5)
os.write(fd, b'\n')
time.sleep(0.3)
drain(0.3)

print('== sensor state before ==')
for reg in ('0x503d', '0x3503', '0x3500', '0x3501', '0x3502', '0x350a', '0x350b'):
    cmd(f'cam reg {reg}')

print('== enable color-bar test pattern (0x503d <- 0x80) ==')
cmd('cam reg 0x503d 0x80')
cmd('cam reg 0x503d')  # readback

os.close(fd)
