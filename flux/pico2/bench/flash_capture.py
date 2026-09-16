#!/usr/bin/env python3
# Flash a UF2 over BOOTSEL and capture the console (parameterise UF2 path as needed).
# (archived 2026-09-15 from the working /tmp scripts; paths inside may need review)
"""Flash the pico2 (BOOTSEL) with the given UF2 image and capture the console.

Audit #17 bench re-run: same flow as /tmp/pico2-flash-capture.py, but the
UF2 is a stable copy (/tmp/shlosilo-pico2-check.uf2, sha
d87fdc718e0c13d4c95463b1083ae748eb05e54a66810936b8671c27142eaa3a) so a
later rebuild of the shared target path cannot change what gets flashed.

Sequence, fully autonomous after the operator's single action:
  phase1  current console goes away          (unplug)
  phase2  BOOTSEL mass storage appears       (hold BOOTSEL, plug in)
  phase3  flash the UF2, wait for reboot     (copy + sync)
  phase4  new console node appears, capture ~45 s of output
"""
import os
import select
import shutil
import subprocess
import sys
import time
import tty

# UF2 to flash: pass as argv[1] (a stable copy - the shared cargo
# target path gets re-pointed by the next flavor build).
UF2 = sys.argv[1] if len(sys.argv) > 1 else "/tmp/shlosilo-pico2-check.uf2"
MSC = "/media/komo/RP2350"
DEV = "/dev/ttyACM0"
LOG = "/tmp/pico2-flash-check.log"
CONSOLE_OUT = "/tmp/pico2-console-check-flash.txt"


def log(msg):
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def wait_until(pred, timeout, what):
    t0 = time.time()
    while not pred():
        if time.time() - t0 > timeout:
            log(f"TIMEOUT waiting for {what}")
            sys.exit(1)
        time.sleep(0.25)


def main():
    open(LOG, "w").close()

    if not os.path.exists(UF2):
        log(f"UF2 missing: {UF2}")
        sys.exit(1)
    sha = subprocess.run(["sha256sum", UF2], capture_output=True, text=True).stdout.split()[0]
    log(f"UF2 sha256: {sha}")

    log("phase1: waiting for the current console to go away (unplug now)")
    wait_until(lambda: not os.path.exists(DEV), 28800, "console disconnect")
    log("phase1 done: console gone")

    log("phase2: waiting for the BOOTSEL drive (hold BOOTSEL + plug in)")
    wait_until(lambda: os.path.exists(MSC), 28800, "BOOTSEL mass storage")
    log("phase2 done: BOOTSEL drive present")

    time.sleep(1.0)

    def copy_once(name):
        for attempt in range(1, 4):
            try:
                shutil.copyfile(UF2, os.path.join(MSC, name))
                os.sync()
                return True
            except Exception as e:  # noqa: BLE001
                log(f"phase3: copy {name} attempt {attempt} failed: {e}")
                time.sleep(1.0)
        return False

    # The bootrom processes a UF2 as it lands on the drive. Measured failure
    # mode (2026-09-16): the copy lands while the device's USB is in a reset
    # storm (dmesg shows -71 errors), the file sits on the FAT image intact
    # (sha256 verified) but the bootrom never starts processing it - the
    # drive stays present indefinitely. Re-copying the same bytes under a
    # FRESH name re-triggers processing reliably. So: copy, wait for the
    # drive to vanish, and on timeout copy again under a new name.
    flashed = False
    for round_no in range(1, 4):
        name = os.path.basename(UF2) if round_no == 1 else f"FW_RETRY{round_no}.UF2"
        if not copy_once(name):
            continue
        log(f"phase3: UF2 copied as {name} (round {round_no}); waiting for reboot")
        try:
            wait_until(lambda: not os.path.exists(MSC), 30, "drive to disappear (reboot)")
            log("phase3 done: drive gone, board rebooting")
            flashed = True
            break
        except SystemExit:
            log(f"phase3: drive still present after round {round_no}; re-copying under a fresh name")
    if not flashed:
        log("FLASH FAILED: the drive never consumed the UF2 after 3 rounds")
        sys.exit(1)

    log("phase4: waiting for the USB console to reappear")
    wait_until(lambda: os.path.exists(DEV), 120, "console re-enumeration")
    log("console node present; capturing ~45 s")
    time.sleep(0.5)

    fd = os.open(DEV, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    tty.setraw(fd)
    buf = b""
    deadline = time.time() + 45
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            chunk = os.read(fd, 4096)
            if chunk:
                buf += chunk
    os.close(fd)

    with open(CONSOLE_OUT, "wb") as f:
        f.write(buf)
    log(f"READ_DONE {len(buf)} bytes -> {CONSOLE_OUT}")

    try:
        d = subprocess.run(["sudo", "dmesg"], capture_output=True, text=True).stdout
        with open("/tmp/pico2-dmesg-bench-flash.txt", "w") as f:
            f.write("\n".join(d.splitlines()[-80:]))
        log("dmesg tail saved -> /tmp/pico2-dmesg-bench-flash.txt")
    except Exception as e:  # noqa: BLE001
        log(f"dmesg capture failed: {e}")


if __name__ == "__main__":
    main()
