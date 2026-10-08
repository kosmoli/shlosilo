#!/usr/bin/env python3
"""Host regression for the T5 Cake pairing leg in the product flow.

Why this exists: the four-beat cold-sign flow lives entirely in
product_task.c (firmware C) -- beat 1 dispatch (xmr-output), beat 2 QR show
(xmr-keyimage), the flow-exit gate exemption that keeps the plate session
alive across the QR page, and the beat-2->3 return to the scan page. None of
that is exercised by the Rust test suite, and a wiring slip (gate kills the
session on the QR page / pairing falls into the fixture sign path / wrong
output type) compiles clean and only misbehaves on device.

This test closes the gap in two halves:
  1. STATIC -- pins the source-level wiring contract of product_task.c:
     dispatch, no-fixture pairing leg, gate exemption + self-clear, carousel
     leave routing (session survives beat 2->3, real exit still tears down),
     output type mapping, and the beat copy strings.
  2. DYNAMIC -- builds the real host staticlib and a C harness that calls
     shlosilo_xmr_pairing_ffi at the SAME call shape product_task.c uses
     (probe first, then the buffer/error contracts the firmware relies on).

Run: python3 flux/forgebox/scripts/test_pairing_flow.py
"""

import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

REPO = Path(__file__).resolve().parents[3]
PRODUCT_TASK = REPO / "flux/forgebox/src/tasks/product_task.c"
C_ABI = REPO / "forms/ffi/c_abi.rs"
LIB = REPO / "target/release/libshlosilo.a"

# The C harness: probe contract + error paths at the firmware's call shape.
# (A full golden pairing run needs a live KeySession + a real xmr-output
# container -- both are Rust-side test surfaces, pinned by
# tests/xmr_pairing_zero_alloc.rs / tests/xmr_keystone_cross_validation.rs.
# The C-side contract is what this harness can reach.)
HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shlosilo.h"

int main(void)
{
    unsigned int ws_need = 0, actual = 0;
    uint8_t *ws_raw, *ws;
    int rc;

    /* (1) PURE PROBE: ws == NULL reports the workspace requirement and
     * touches nothing -- this is exactly how pairing_run gets ws_need. */
    rc = shlosilo_xmr_pairing_ffi(NULL, NULL, 0, NULL, 0,
                                  NULL, 0, &ws_need, NULL, 0);
    printf("probe: rc=%d ws_need=%u\n", rc, ws_need);
    if (rc != 0 || ws_need == 0) {
        printf("FAIL: pure probe must return 0 with a positive requirement\n");
        return 1;
    }

    /* (2) under-capacity ws is refused BEFORE execution and reports the
     * requirement through actual_len (the firmware re-probes on this). */
    {
        static uint8_t small[64];
        actual = 0;
        rc = shlosilo_xmr_pairing_ffi(NULL, NULL, 0, NULL, 0,
                                      NULL, 0, &actual, small, sizeof(small));
        printf("under-cap: rc=%d actual=%u (expect negative, actual==%u)\n",
               rc, actual, ws_need);
        if (rc >= 0 || actual != ws_need) {
            printf("FAIL: under-capacity ws must fail and report the requirement\n");
            return 2;
        }
    }

    /* (3) u128-aligned ws base at the requirement size, NULL session: the
     * null-pointer guard (firmware pairing_run checks g_key_session first;
     * this pins the FFI side refuses too -- a keyless device cannot answer). */
    ws_raw = (uint8_t *)malloc(ws_need + 15u);
    if (ws_raw == NULL) {
        printf("FAIL: cannot allocate %u B workspace\n", ws_need);
        return 3;
    }
    ws = (uint8_t *)(((uintptr_t)ws_raw + 15u) & ~(uintptr_t)15u);
    actual = 0;
    rc = shlosilo_xmr_pairing_ffi(NULL, NULL, 0, NULL, 0,
                                  NULL, 0, &actual, ws, ws_need);
    printf("null session: rc=%d (expect negative)\n", rc);
    if (rc >= 0) {
        printf("FAIL: NULL session must be refused (no key, no answer)\n");
        free(ws_raw);
        return 4;
    }
    free(ws_raw);

    printf("PASS: pairing FFI probe/contract at the firmware call shape\n");
    return 0;
}
"""


def fail(msg: str) -> NoReturn:
    sys.exit(f"FAIL: {msg}")


def static_checks() -> None:
    src = PRODUCT_TASK.read_text(encoding="utf-8")

    def require(needle: str, what: str, flags: int = 0) -> re.Match:
        m = re.search(needle, src, flags)
        if not m:
            fail(f"product_task.c lost the {what} wiring: /{needle}/")
        return m

    print("static: pairing leg wiring in product_task.c")

    # -- beat 1 dispatch: BOTH UR shapes reach pairing_run -----------------
    # G2: 13-char prefix so the slash-less `ur:xmr-output` form is covered
    # too -- it must never reach the fixture sign path.
    require(r'strncmp\(text, "ur:xmr-output", 13\) == 0',
            "single-frame xmr-output dispatch (incl. slash-less form)")
    require(r'strncmp\(g_ur_type, "xmr-output", 10\) == 0[\s\S]{0,400}?pairing_run\(g_ur_payload, plen\)',
            "multipart xmr-output -> pairing_run dispatch")
    require(r'ur_single_decode\(text, &plen\) == 0\)[\s\S]{0,400}?pairing_run\(g_ur_payload, plen\)',
            "single-frame xmr-output -> pairing_run dispatch")

    # -- pairing leg: session-gated, NO fixture fallback -------------------
    pm = re.search(r"static void pairing_run\(const uint8_t \*payload, unsigned plen\)\n\{([\s\S]*?)\n\}", src)
    if not pm:
        fail("pairing_run not found")
    body = pm.group(1)
    guard = body.find("g_key_session == NULL")
    call = body.find("shlosilo_xmr_pairing_ffi(")
    if guard < 0 or call < 0 or guard > call:
        fail("pairing_run must check g_key_session BEFORE the FFI call")
    if "k_sign_idx12" in body:
        fail("pairing_run must never touch the fixture key (no fixture fallback)")
    if "keep scanning" not in body:
        fail("pairing_run failures must prompt + keep scanning")
    if "shlosilo_xmr_pairing_ffi(g_key_session, NULL, 0, NULL, 0" not in body:
        fail("pairing_run must take the ws requirement from the pure probe")
    print("  ok: pairing_run is session-gated with no fixture fallback")

    # -- beat 2 show: xmr-keyimage container on the F3 carousel ------------
    if 'sign_out_type_for("xmr-output")' not in body:
        fail("pairing_run must map its output type via sign_out_type_for")
    if "UiGotoPage(UI_PAGE_QR)" not in body or "g_pairing_qr = 1" not in body:
        fail("pairing_run must show the QR page flow-owned (g_pairing_qr = 1)")
    require(r'strcmp\(in_type, "xmr-output"\) == 0\)[\s\S]{0,200}?"xmr-keyimage"',
            "sign_out_type_for xmr-output -> xmr-keyimage mapping")
    print("  ok: beat 2 shows the xmr-keyimage QR through the F3 carousel")

    # -- non-sign types stay prompt + keep scanning (single + multipart) ----
    # Shared whitelist helper: only sign types reach sign_run. Exchange legs
    # (xmr-keyimage is a device-OUT leg) must never enter it -- the sign FAIL
    # leg unconditionally closes the plate session underneath.
    wl = re.search(r"static int ur_type_is_sign\(const char \*type\)\n\{([\s\S]*?)\n\}", src)
    if not wl:
        fail("ur_type_is_sign whitelist helper not found")
    wbody = wl.group(1)
    for t in ("xmr-txunsigned", "crypto-monero-tx", "crypto-psbt",
              "eth-sign-request"):
        if t not in wbody:
            fail(f"sign whitelist lost {t!r}")
    if '"xmr-keyimage"' in wbody or '"xmr-output"' in wbody:
        fail("exchange legs must NOT be in the sign whitelist")
    if src.count("ur_type_is_sign(g_ur_type)") < 2:
        fail("single-frame AND multipart dispatch must both gate through ur_type_is_sign")
    print("  ok: sign whitelist shared (single + multipart), xmr-keyimage stays out")

    # -- dispatch ORDER: pairing leg BEFORE the fixture path ---------------
    # N2: a bare/odd xmr-output must never fall through to the fixture sign
    # path (no fixture fallback on the pairing leg) -- pin the order, not
    # just the presence, so a re-shuffle cannot re-open the leak.
    sm = re.search(r"static void scan_ur_hit\(const char \*text\)\n\{([\s\S]*?)\n\}", src)
    if not sm:
        fail("scan_ur_hit not found")
    sbody = sm.group(1)
    ppos = sbody.find('strncmp(text, "ur:xmr-output", 13)')
    fpos = sbody.find("sign_run(text, NULL, NULL, 0)")
    if ppos < 0 or fpos < 0:
        fail("scan_ur_hit lost the pairing dispatch or the fixture sign path")
    if ppos > fpos:
        fail("pairing dispatch must run BEFORE the fixture path (no fixture leak)")
    gpos = sbody.find("!ur_type_is_sign(g_ur_type)")
    spos = sbody.find("sign_run(NULL, g_ur_type, g_ur_payload, plen)")
    if gpos < 0 or spos < 0 or gpos > spos:
        fail("single-frame session sign must gate through ur_type_is_sign BEFORE sign_run")
    print("  ok: pairing dispatch precedes the fixture path; single-frame sign gated")

    # -- the page gate: exemption + self-clear + teardown intact -----------
    gate = re.search(
        r"if \(UiGetPage\(\) != UI_PAGE_QR\) \{[\s\S]*?g_pairing_qr = 0;[\s\S]*?\}"
        r"[\s\S]*?if \(g_key_session != NULL && g_key_from_se == 0 && g_key_console == 0 &&"
        r"[\s\S]*?g_pairing_qr != 0 && UiGetPage\(\) == UI_PAGE_QR[\s\S]*?\)\s*\{"
        r"([\s\S]*?)\n            \}", src)
    if not gate:
        fail("flow-exit gate lost the pairing-QR exemption / self-clear")
    teardown = gate.group(1)
    if "key_session_close()" not in teardown or "seed_plate_wipe()" not in teardown:
        fail("flow-exit teardown must still close the session and wipe the plate")
    print("  ok: gate exempts the pairing QR page (self-clearing), teardown intact")

    # -- beat 2->3: carousel leave routes back to scanning -----------------
    cl = re.search(r"static void carousel_leave\(const char \*why\)\n\{([\s\S]*?)\n\}", src)
    if not cl:
        fail("carousel_leave not found")
    cbody = cl.group(1)
    if "g_pairing_qr = 0" not in cbody:
        fail("carousel_leave must clear the flow-owned flag on every exit")
    if not re.search(r"pairing\s*\)[\s\S]*?UiGotoPage\(UI_PAGE_SCAN\)", cbody):
        fail("pairing carousel must return to the SCAN page (session -> beat 3)")
    if "UiGotoPage(UI_PAGE_WELCOME)" not in cbody:
        fail("non-pairing carousel must still exit to welcome (real exit)")
    print("  ok: beat 2 exit -> scan page (session survives); other exits -> welcome")

    # -- beat 4: xmr-txsigned straight to the QR page ----------------------
    sr = re.search(r"static void sign_run\(const char \*uri, const char \*type,[\s\S]*?\n\}", src)
    if not sr:
        fail("sign_run not found")
    if not re.search(r'"xmr-txsigned"\) == 0[\s\S]{0,600}?UiGotoPage\(UI_PAGE_QR\)', sr.group(0)):
        fail("sign_run must show the xmr-txsigned QR (beat 4)")
    print("  ok: beat 4 shows the xmr-txsigned QR")

    # -- beat copy strings in the image ------------------------------------
    for s in ("scan with Cake", "key images ready", "computing key images",
              "pairing: output received", "keep scanning"):
        if s not in src:
            fail(f"beat copy string missing: {s!r}")
    print("  ok: four-beat copy strings present")

    # -- capacity cross-check: firmware out buffer <= FFI cap --------------
    m = re.search(r"#define\s+SIGN_OUT_MAX\s+\((\d+)\s*\*\s*1024\)", src)
    if not m:
        fail("cannot parse SIGN_OUT_MAX from product_task.c")
    fw_out = int(m.group(1)) * 1024
    mm = re.search(r"const SIGN_OUTPUT_BUF_MAX_LEN: usize = ([^;]+);", C_ABI.read_text(encoding="utf-8"))
    if not mm:
        fail("cannot parse SIGN_OUTPUT_BUF_MAX_LEN from c_abi.rs")
    expr = mm.group(1)
    mmax = re.search(r"MULTIPART_PAYLOAD_MAX_LEN:\s*usize\s*=\s*(\d+)",
                     (REPO / "forms/ur/ur_multipart.rs").read_text(encoding="utf-8"))
    if not mmax:
        mmax = re.search(r"MULTIPART_PAYLOAD_MAX_LEN\s*=\s*(\d+)",
                         C_ABI.read_text(encoding="utf-8"))
    mp = int(mmax.group(1)) if mmax else 16384
    ffi_cap = eval(expr.replace("crate::ur::ur_multipart::MULTIPART_PAYLOAD_MAX_LEN", str(mp)))  # noqa: S307
    print(f"static: firmware SIGN_OUT_MAX {fw_out} B vs FFI cap {ffi_cap} B")
    if fw_out > ffi_cap:
        fail(f"firmware out buffer ({fw_out}) exceeds FFI cap ({ffi_cap})")


def dynamic_checks() -> None:
    print("building host staticlib (shlosilo-host-sim, release)...")
    subprocess.run(["cargo", "build", "-p", "shlosilo-host-sim", "--release"],
                   cwd=REPO, check=True, capture_output=True)

    nm = subprocess.run(["nm", str(LIB)], capture_output=True, text=True, check=True).stdout
    if " T shlosilo_xmr_pairing_ffi" not in nm:
        fail("shlosilo_xmr_pairing_ffi missing from libshlosilo.a (keep table stale?)")

    harness_c = Path("/tmp/pairing_flow_test.c")
    harness_bin = Path("/tmp/pairing_flow_test")
    harness_c.write_text(HARNESS, encoding="utf-8")
    subprocess.run(
        ["gcc", "-O2", "-Wall", "-Wextra",
         "-o", str(harness_bin), str(harness_c),
         "-I", str(REPO / "flux/forgebox/shlosilo"),
         "-L", str(REPO / "target/release"), "-lshlosilo",
         "-lpthread", "-ldl", "-lm"],
        check=True)

    out = subprocess.run([str(harness_bin)], capture_output=True, text=True)
    print(out.stdout, end="")
    if out.returncode != 0:
        print(out.stderr, end="", file=sys.stderr)
        sys.exit(out.returncode)
    print("pairing flow regression PASS")


def main() -> None:
    static_checks()
    dynamic_checks()


if __name__ == "__main__":
    main()
