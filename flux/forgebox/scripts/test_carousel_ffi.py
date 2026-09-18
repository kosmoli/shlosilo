#!/usr/bin/env python3
"""Host regression for the UR carousel FFI path (F3 output side).

Why this exists: the first carousel build gave the encoder a 576-byte frame
buffer while the FFI requires >= 1024 (FRAME_BUF_MAX_LEN=1024, rejected with
BufferTooSmall *before* any frame is produced). On device the carousel then
bounced straight back to the welcome page after one visible flash - a flash
cycle burnt on a contract no host-side check covered.

This test closes that gap:
  1. cross-checks the two constants (firmware CAROUSEL_FRAME_MAX vs FFI
     FRAME_BUF_MAX_LEN) - the static half;
  2. builds the real host staticlib and a C harness that calls the same FFI
     calls as product_task.c, at the SAME buffer size the firmware uses:
       begin -> cyclic frames -> decoder -> payload byte-equality,
     asserting one full cycle suffices (the carousel's design rule).

Run: python3 flux/forgebox/scripts/test_carousel_ffi.py
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PRODUCT_TASK = REPO / "flux/forgebox/src/tasks/product_task.c"
C_ABI = REPO / "forms/ffi/c_abi.rs"
LIB = REPO / "target/release/libshlosilo.a"

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shlosilo.h"
#include "demo_payload.h"

#ifndef CAROUSEL_FRAME_MAX
#error "CAROUSEL_FRAME_MAX must be defined (pass -DCAROUSEL_FRAME_MAX=<firmware value>)"
#endif

static uint8_t g_frame[CAROUSEL_FRAME_MAX];
static uint8_t g_out[8192];

/* ur:<type>/<seq>-<count>/<body> -> count */
static int frame_count_of(const char *frame)
{
    const char *p = strchr(frame, '/');
    if (p == NULL) {
        return -1;
    }
    p = strchr(p + 1, '-');
    if (p == NULL) {
        return -1;
    }
    return atoi(p + 1);
}

int main(void)
{
    struct UrMultipartEncoder *enc;
    struct UrMultipartDecoder *dec;
    unsigned int flen = 0;
    int rc, i, count = -1, fed = 0, maxlen = 0;

    printf("firmware frame buffer: %d bytes; payload: %d bytes (%s)\n",
           CAROUSEL_FRAME_MAX, DEMO_PAYLOAD_LEN, DEMO_PAYLOAD_TYPE);

    enc = shlosilo_ur_encode_begin(DEMO_PAYLOAD_TYPE, g_demo_payload,
                                   DEMO_PAYLOAD_LEN, 200);
    if (enc == NULL) {
        printf("FAIL: encode_begin returned NULL\n");
        return 1;
    }

    /* Contract probe: a sub-minimum buffer must be rejected before a frame is
     * produced - this is the exact device failure the firmware hit. */
    {
        static uint8_t small[512];
        unsigned int slen = 0;
        rc = shlosilo_ur_encode_next_cyclic(enc, small, sizeof(small), &slen);
        printf("probe: next_cyclic(512B) rc=%d (expect negative; frames must not be consumed)\n", rc);
    }

    dec = shlosilo_ur_decode_new();
    if (dec == NULL) {
        printf("FAIL: decode_new returned NULL\n");
        return 1;
    }

    /* Round trip at the firmware's exact buffer size; guard well above any
     * plausible cycle count so a non-completing stream reports, not spins. */
    for (i = 0; i < 512 && !shlosilo_ur_decode_complete(dec); i++) {
        rc = shlosilo_ur_encode_next_cyclic(enc, g_frame, sizeof(g_frame), &flen);
        if (rc != 0) {
            printf("FAIL: next_cyclic rc=%d at frame %d\n", rc, i);
            return 2;
        }
        if (flen == 0 || flen + 1 > sizeof(g_frame)) {
            printf("FAIL: bad frame length %u\n", flen);
            return 2;
        }
        if (count < 0) {
            count = frame_count_of((const char *)g_frame);
            printf("frames per cycle: %d\n", count);
            if (count <= 0) {
                printf("FAIL: cannot parse frame count\n");
                return 2;
            }
        }
        if (i == 0 || i == count - 1) {
            printf("  frame %2d len=%3u: %.58s...\n", i, flen, g_frame);
        }
        if (flen > (unsigned int)maxlen) {
            maxlen = (int)flen;
        }
        rc = shlosilo_ur_decode_feed(dec, (const char *)g_frame, NULL);
        if (rc != 0) {
            printf("FAIL: decode_feed rc=%d\n", rc);
            return 2;
        }
        fed++;
    }

    if (!shlosilo_ur_decode_complete(dec)) {
        printf("FAIL: decoder not complete after %d frames (cycle=%d)\n", fed, count);
        return 3;
    }
    if (fed > count) {
        printf("FAIL: one cycle (%d frames) did not suffice; needed %d\n", count, fed);
        return 3;
    }

    {
        unsigned int olen = 0;
        rc = shlosilo_ur_decode_payload(dec, g_out, sizeof(g_out), &olen);
        if (rc != 0) {
            printf("FAIL: decode_payload rc=%d\n", rc);
            return 3;
        }
        if (olen != DEMO_PAYLOAD_LEN || memcmp(g_out, g_demo_payload, olen) != 0) {
            printf("FAIL: payload mismatch (%u vs %d bytes)\n", olen, DEMO_PAYLOAD_LEN);
            return 3;
        }
    }

    printf("PASS: %d frames (cycle %d), max frame len %d (< buffer %d), "
           "payload %d bytes byte-equal\n",
           fed, count, maxlen, CAROUSEL_FRAME_MAX, DEMO_PAYLOAD_LEN);

    shlosilo_ur_encode_free(enc);
    shlosilo_ur_decode_free(dec);
    return 0;
}
"""


def parse_c_define(path: Path, name: str) -> int:
    m = re.search(rf"#define\s+{name}\s+(\d+)", path.read_text(encoding="utf-8"))
    if not m:
        sys.exit(f"cannot parse {name} from {path}")
    return int(m.group(1))


def parse_rust_const(path: Path, name: str) -> int:
    m = re.search(rf"const\s+{name}\s*:\s*usize\s*=\s*(\d+)", path.read_text(encoding="utf-8"))
    if not m:
        sys.exit(f"cannot parse {name} from {path}")
    return int(m.group(1))


def main() -> None:
    fw_buf = parse_c_define(PRODUCT_TASK, "CAROUSEL_FRAME_MAX")
    ffi_min = parse_rust_const(C_ABI, "FRAME_BUF_MAX_LEN")
    print(f"static check: firmware buffer {fw_buf} B vs FFI minimum {ffi_min} B")
    if fw_buf < ffi_min:
        sys.exit(f"FAIL: firmware frame buffer ({fw_buf}) < FFI minimum ({ffi_min}) - "
                 "the carousel will bounce with BufferTooSmall")

    print("building host staticlib (shlosilo-host-sim, release)...")
    subprocess.run(["cargo", "build", "-p", "shlosilo-host-sim", "--release"],
                   cwd=REPO, check=True, capture_output=True)

    nm = subprocess.run(["nm", str(LIB)], capture_output=True, text=True, check=True).stdout
    for sym in ("shlosilo_ur_encode_begin", "shlosilo_ur_encode_next_cyclic",
                "shlosilo_ur_decode_new", "shlosilo_ur_decode_payload"):
        if f" T {sym}" not in nm:
            sys.exit(f"FAIL: {sym} missing from libshlosilo.a (host keep table stale?)")

    harness_c = Path("/tmp/carousel_ffi_test.c")
    harness_bin = Path("/tmp/carousel_ffi_test")
    harness_c.write_text(HARNESS, encoding="utf-8")

    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra",
         f"-DCAROUSEL_FRAME_MAX={fw_buf}",
         "-o", str(harness_bin), str(harness_c),
         "-I", str(REPO), "-I", str(REPO / "flux/forgebox/src"),
         "-L", str(REPO / "target/release"), "-lshlosilo",
         "-lpthread", "-ldl", "-lm"],
        check=True)

    out = subprocess.run([str(harness_bin)], capture_output=True, text=True)
    print(out.stdout, end="")
    if out.returncode != 0:
        print(out.stderr, end="", file=sys.stderr)
        sys.exit(out.returncode)
    print(f"carousel FFI regression PASS (at firmware buffer size {fw_buf} B)")


if __name__ == "__main__":
    main()
