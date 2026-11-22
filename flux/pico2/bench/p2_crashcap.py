#!/usr/bin/env python3
"""Capture a pico2 boot-to-crash transcript with nothing filtered and nothing cleared.

`xmr_hw_slow.py` clears the crash record early and prints a filtered view, which is how an earlier
run concluded "no crash record" while the record may simply have been printed on a boot nobody was
reading. This probe opens the console, timestamps every byte it sees (including the boot banner and
whatever follows a reset), optionally feeds a UR frame file, and writes the whole thing to one file:

    python3 p2_crashcap.py --frames /tmp/xmr_2in_frames.txt --out /tmp/p2_cap.log

Structure it relies on: the sign stalls the executor, so the host's writes start failing with EIO
at acceptance; after the reset the device re-prints its banner. Both are kept verbatim.
"""
import argparse
import os
import sys
import time
import tty

ap = argparse.ArgumentParser()
ap.add_argument("--dev", default="/dev/ttyACM0")
ap.add_argument("--frames", default="")
ap.add_argument("--out", default="/tmp/p2_cap.log")
ap.add_argument("--gap", type=float, default=1.2)
ap.add_argument("--settle", type=float, default=4.0)
ap.add_argument("--hold", type=float, default=45.0, help="seconds to keep reading after the last frame")
ap.add_argument("--sign-timeout", type=float, default=240.0)
# The fixture is encrypted to one device entropy; without this the device signs with TRNG
# entropy, cannot decrypt the request, and fails with EncodingInvalidFormat - which is what an
# earlier capture run mistook for a crash.
ap.add_argument("--fixed-entropy", default="77" * 32)
ap.add_argument("--dev-entropy", default="4a9291a702c0ba28aa285882efde4f2c9237556ceb685570d595fd6586074530")
args = ap.parse_args()

out = open(args.out, "w", buffering=1)
t0 = time.time()


def emit(kind: str, text: str) -> None:
    line = f"{time.time() - t0:8.2f} {kind:5s} {text}"
    print(line, end="" if line.endswith("\n") else "\n")
    out.write(line if line.endswith("\n") else line + "\n")


def drain(fd, seconds: float) -> str:
    """Read whatever the console has for `seconds`, timestamped per chunk."""
    end = time.time() + seconds
    got = []
    while time.time() < end:
        try:
            chunk = os.read(fd, 8192)
        except BlockingIOError:
            time.sleep(0.02)
            continue
        except OSError as e:
            emit("EIO", f"{e.strerror}")
            break
        if chunk:
            text = chunk.decode("utf-8", "replace")
            got.append(text)
            for line in text.splitlines():
                if line.strip():
                    emit("dev", line.strip())
    return "".join(got)


fd = os.open(args.dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
tty.setraw(fd)
emit("info", f"capture -> {args.out}")
drain(fd, args.settle)
# Device entropy: the fixture is encrypted to this wallet, so the view key has to match or the
# request decrypts to garbage (`EncodingInvalidFormat`).
os.write(fd, (f"entropy {args.dev_entropy}" + "\r").encode())
drain(fd, 1.5)
os.write(fd, (f"xmrseed {args.fixed_entropy}" + "\r").encode())
drain(fd, 1.5)

frames = []
if args.frames:
    frames = [l.strip() for l in open(args.frames) if l.strip()]
    emit("info", f"{len(frames)} frames loaded")

stalled = False
for i, fr in enumerate(frames, 1):
    try:
        os.write(fd, (fr + "\r").encode())
    except OSError as e:
        emit("host", f"frame {i}: write failed ({e.strerror}) = stalled into the sign")
        stalled = True
        break
    text = drain(fd, args.gap)
    if "[xmr] request" in text:
        stalled = True
        break

if not stalled:
    emit("info", "no sign started; holding to capture whatever happens")

# Keep reading through the stall, the sign, a possible reset and the boot after it.
deadline = time.time() + args.sign_timeout
saw_signed = False
saw_banner = False
while time.time() < deadline:
    try:
        chunk = os.read(fd, 8192)
    except BlockingIOError:
        time.sleep(0.05)
        if saw_signed and time.time() > deadline - (args.sign_timeout - args.hold):
            break
        continue
    except OSError as e:
        emit("EIO", f"{e.strerror} (device dropped)")
        time.sleep(0.2)
        continue
    if not chunk:
        continue
    text = chunk.decode("utf-8", "replace")
    for line in text.splitlines():
        if line.strip():
            emit("dev", line.strip())
            if "signed ok" in line:
                saw_signed = True
                emit("info", "SIGN COMPLETED")
            if "[cam] sensor id" in line:
                # Once per boot. The 5 s heartbeat also reprints [psram] ready and the banner, so
                # keying reboot detection off those lines reports a reboot every heartbeat.
                if saw_signed:
                    emit("info", "REBOOT AFTER A SUCCESSFUL SIGN")
                elif saw_banner:
                    emit("info", "REBOOT (boot banner seen again)")
                saw_banner = True
    if saw_signed and time.time() > deadline - 5:
        break

emit("info", f"done stalled={stalled} signed={saw_signed} banner={saw_banner}")
os.close(fd)
sys.exit(0 if saw_signed else 20)
