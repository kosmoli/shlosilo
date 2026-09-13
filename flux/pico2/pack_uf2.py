#!/usr/bin/env python3
"""Pack the pico2 ELF into an RP2350-correct UF2 for BOOTSEL drag-and-drop.

Why this exists: elf2uf2-rs (the usual converter) is an RP2040 tool - it tags
every block with the RP2040 family ID (0xe48bff56), which the RP2350 bootrom
rejects. Two corrections, both matching picotool / official RP2350 UF2s:

1. family ID -> rp2350-arm-s (0xe48bff59);
2. prepend the RP2350-E10 errata workaround block. Datasheet RP2350-E10
   ("UF2 drag-and-drop doesn't work with partition tables", affects A2):
   "Add a single block at the start of the UF2 with an Absolute family ID,
   targeting the end of Flash, with block number set to 0 and number of
   blocks set to 2." A3+ bootroms recognise the UF2_EXTENSION_RP2_IGNORE_BLOCK
   extension tag (0x9957e304) and ignore the block; A2 uses it to make the
   download work when a partition table is present.

Usage:
    python3 pack_uf2.py [ELF] [OUT.uf2]
Defaults: the cargo release ELF, output next to it as .uf2.
Requires elf2uf2-rs on PATH:  cargo install elf2uf2-rs
"""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path

MAGIC0 = 0x0A324655
MAGIC1 = 0x9E5D5157
MAGIC_END = 0x0AB16F30
RP2040_FAMILY_ID = 0xE48BFF56
RP2350_ARM_S_FAMILY_ID = 0xE48BFF59
ABSOLUTE_FAMILY_ID = 0xE48BFF57
EXT_RP2_IGNORE_BLOCK = 0x9957E304
ABS_BLOCK_LOC = 0x11000000 - 256  # 0x10FFFF00, end of flash


def abs_block() -> bytes:
    hdr = struct.pack(
        "<IIIIIIII",
        MAGIC0,
        MAGIC1,
        0x2000 | 0x8000,  # family ID present | extension tags present
        ABS_BLOCK_LOC,
        256,
        0,  # block_no
        2,  # num_blocks - deliberately "wrong", per the errata wording
        ABSOLUTE_FAMILY_ID,
    )
    payload = b"\xef" * 256 + struct.pack("<I", EXT_RP2_IGNORE_BLOCK)
    payload += b"\x00" * (476 - 256 - 4)
    blk = hdr + payload + struct.pack("<I", MAGIC_END)
    assert len(blk) == 512
    return blk


def main() -> None:
    here = Path(__file__).resolve().parent
    elf = Path(sys.argv[1]) if len(sys.argv) > 1 else (
        here.parents[1]
        / "target/thumbv8m.main-none-eabihf/release/shlosilo-pico2"
    )
    if not elf.exists():
        sys.exit(f"ELF not found: {elf}  (build first: cargo build --release)")
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else elf.with_suffix(".uf2")
    raw = out.with_name("_uf2_raw.uf2")

    subprocess.run(["elf2uf2-rs", str(elf), str(raw)], check=True)
    data = bytearray(raw.read_bytes())
    assert len(data) % 512 == 0, "not a whole number of UF2 blocks"

    n = len(data) // 512
    for i in range(n):
        off = i * 512
        fam = struct.unpack_from("<I", data, off + 28)[0]
        if fam == RP2350_ARM_S_FAMILY_ID:
            continue  # a future elf2uf2-rs that already targets RP2350
        if fam != RP2040_FAMILY_ID:
            sys.exit(f"block {i}: unexpected family {fam:#x}")
        struct.pack_into("<I", data, off + 28, RP2350_ARM_S_FAMILY_ID)

    out.write_bytes(abs_block() + bytes(data))
    raw.unlink()
    blob = out.read_bytes()
    print(f"wrote {out} ({len(blob)} bytes, {len(blob)//512} blocks: 1 abs + {n} main)")
    print("flash: hold BOOTSEL, plug in, copy the .uf2 to the RP2350 drive")
    print("sha256:", hashlib.sha256(blob).hexdigest())


if __name__ == "__main__":
    main()
