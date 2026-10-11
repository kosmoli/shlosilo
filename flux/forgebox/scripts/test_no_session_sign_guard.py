#!/usr/bin/env python3
"""Host regression for the Bug A no-session sign guard in the product flow.

Why this exists: the scan dispatch lives entirely in product_task.c (firmware
C). Before the fix, a sign UR scanned with NO session silently fell into the
legacy fixture-key path (k_sign_idx12) and signed with the smoke-anchor key --
the wallet rejected it (Cake rc=-21, wrong key) with no prompt of any kind.
A routing slip of this shape compiles clean and only misbehaves on device, so
the wiring contract is pinned at the source level (same approach as
test_pairing_flow.py's STATIC half).

Pinned contract (2026-10-09):
  1. single-frame leg, no session: prompt "import a wallet first /
     scan the plate first" + keep scanning -- sign_run is ONLY reachable behind the
     explicit one-shot 'sign fixture' arm;
  2. multipart completion leg, no session: same prompt + ur_intake_reset() +
     keep scanning, again arm-gated before sign_run;
  3. the legacy fixture path survives as an EXPLICIT entry: 'sign fixture'
     dev console (se_smoke.c) -> ProductSignFixtureArm -> one-shot arm
     (cleared at every consume).

DYNAMIC half: not reachable from the host -- the guard is pure firmware C
routing (scan frame -> sign_run), with no FFI surface to drive it. The
on-device check is the acceptance run: scan xmr-txunsigned with no wallet ->
"import a wallet first / scan the plate first" on screen + "keep scanning" on UART0.

Run: python3 flux/forgebox/scripts/test_no_session_sign_guard.py
"""


import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
PRODUCT_TASK = REPO / "flux/forgebox/src/tasks/product_task.c"
SE_SMOKE = REPO / "flux/forgebox/src/tasks/se_smoke.c"

fails = []


def pin(name: str, cond: bool, detail: str = "") -> None:
    tag = "ok  " if cond else "FAIL"
    print(f"  [{tag}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    if not cond:
        fails.append(name)


def block(src: str, opener: str) -> str:
    """Extract the brace-balanced block that starts at `opener`."""
    i = src.index(opener)
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
    raise AssertionError(f"unbalanced block after {opener!r}")


def main() -> int:
    src = PRODUCT_TASK.read_text(encoding="utf-8")
    se = SE_SMOKE.read_text(encoding="utf-8")

    print("== no-session sign guard (Bug A, product_task.c)")

    # 0. prompt persistence (2026-10-09 device report: the scan-info copy is
    #    overwritten by the next collect tick — the footer copy must survive)
    pin(
        "prompt lives in the STATUS slot (l1) with progress cleared",
        'UiScanProgress(0);' in block(src, "static void no_session_prompt(void)")
        and 'UiScanInfo("import a wallet first", "", "", "");' in block(src, "static void no_session_prompt(void)"),
    )
    pin(
        "status-slot lifecycle: QR out of view clears slot + re-arms prompt",
        "g_scan_miss" in src
        and "g_no_session_prompted = 0;"
        in src[src.index("static void scan_step(void)\n{") :],
    )
    pin(
        "status slot empty by default + metrics never write the slot",
        'UiScanInfo("", "point camera at QR", "", "");' in src
        and "UiScanMetrics(l1, l2, l3);" in src
        and 'UiScanInfo("scanning..."' not in src,
    )
    pin(
        "no-session prompt throttled once per state-entry",
        "g_no_session_prompted = 1;" in src
        and "if (g_no_session_prompted) {" in src
        and "g_no_session_prompted = 0;" in src,
    )
    pin(
        "UI strings stay ASCII (font is ASCII-only; CJK renders as '?')",
        not any(ord(c) > 127 for c in src[src.index("static void no_session_prompt"):src.index("static void scan_ur_hit")]),
    )
    hit = block(src, "static void scan_ur_hit(const char *text)")
    pin(
        "first-frame classification precedes the collector (Kosmo's state machine)",
        "First-frame classification" in hit
        and hit.index("First-frame classification") < hit.index("shlosilo_ur_decode_feed"),
    )
    pin(
        "frame-1 refusal for key-needing types without a session",
        "no_session_prompt();" in hit.split("shlosilo_ur_decode_feed")[0],
    )

    # 1. single-frame no-session leg
    single = block(src, "if (slash2 == NULL && g_key_session == NULL)")
    pin(
        "single-frame: sign_run only behind the one-shot arm",
        "g_fixture_sign_ok" in single
        and single.index("g_fixture_sign_ok")
        < single.index("sign_run(text, NULL, NULL, 0)"),
    )
    pin(
        "single-frame: unarmed path prompts + keeps scanning (no sign_run)",
        "no_session_prompt();" in single
        and single.rstrip().endswith("}"),
    )
    pin("single-frame: arm consumed one-shot", "g_fixture_sign_ok = 0;" in single)
    # follow-up (2026-10-09): the single-frame no-session leg runs the SAME
    # type filter as the multipart completion leg BEFORE the import prompt --
    # a non-sign frame with no session is "not a sign request", not "import a
    # wallet first" (the pre-filter shape prompted import for every type).
    pin(
        "single-frame: type filter before the no-session prompt",
        "ur_type_is_sign(g_ur_type)" in single
        and single.index("!ur_type_is_sign(g_ur_type)")
        < single.index("no_session_prompt();")
        and "not a sign request" in single,
    )
    pin(
        "fixture arm is volatile (cross-task flag)",
        "static volatile int g_fixture_sign_ok;" in src,
    )

    # 2. shared prompt copy
    prompt = block(src, "static void no_session_prompt(void)")
    pin(
        "prompt copy: single line 'import a wallet first'",
        "import a wallet first" in prompt and "scan the plate first" not in prompt,
    )

    # 3. multipart completion leg
    hit = block(src, "static void scan_ur_hit(const char *text)")
    complete_leg = hit[hit.index("ur: complete type"):]
    guard = block(complete_leg, "if (g_key_session == NULL)")
    pin(
        "multipart: session check + prompt + intake reset before sign",
        "no_session_prompt();" in guard and "ur_intake_reset();" in guard,
    )
    pin("multipart: arm consumed one-shot", "g_fixture_sign_ok = 0;" in guard)
    pin(
        "multipart: sign_run(NULL, ...) only after the session check",
        hit.index("if (g_key_session == NULL)")
        < hit.rindex("sign_run(NULL, g_ur_type, g_ur_payload, plen);"),
    )
    pin(
        "multipart: the no-session guard returns before the sign",
        guard.rstrip().endswith("return;\n        }"),
    )
    # every sign_run site in the scan dispatch must sit directly behind a
    # guard header (nearest enclosing `if (`): the one-shot arm, the
    # session-only single-frame branch, the sign-type classification, or the
    # session-checked multipart completion (order pinned above). A bare
    # `sign_run(` with no guard in front of it is the pre-fix fallback shape.
    sites = [m.start() for m in re.finditer(r"sign_run\(", hit)]
    guard_headers = (
        "if (g_fixture_sign_ok)",
        "if (slash2 == NULL)",
        "if (g_key_session == NULL)",
        "if (!ur_type_is_sign(g_ur_type))",
        "if (ur_single_decode(text, &plen) == 0)",
    )
    bare = []
    for s in sites:
        k = hit.rfind("if (", 0, s)
        if k < 0 or not hit[k:].startswith(guard_headers):
            bare.append(s)
    pin(
        f"scan dispatch: all {len(sites)} sign_run sites sit behind a guard",
        len(sites) == 4 and not bare,
        f"unguarded offsets {bare}",
    )

    # 4. explicit legacy entry (smoke/acceptance anchor)
    pin(
        "legacy entry: one-shot arm function present",
        "int ProductSignFixtureArm(void)" in src
        and "g_fixture_sign_ok = 1;" in src,
    )
    pin(
        "legacy entry: 'sign fixture' console command wired",
        '"sign") == 0' in se and "RunSignFixture();" in se
        and "ProductSignFixtureArm" in se,
    )

    print()
    if fails:
        print(f"FAIL: {len(fails)} pin(s) broken: {', '.join(fails)}")
        return 1
    print("PASS: no-session sign guard wiring contract holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())

    # 4. injection red line (2026-10-09, Kosmo): QR-derived strings never
    #    reach the screen verbatim; failures are fixed templates.
    print("== injection red line (QR-derived text / failure templates)")
    pin(
        "UR type display goes through the fixed-name mapper",
        src.count("ur_type_display(") >= 4 and "%.16s" not in src,
    )
    pin(
        "sign failure screen is a fixed template (no rc / no type / no head)",
        "sign failed\\nrequest could not be signed" in src
        and "sign FAIL: rc=%d\\ntype:" not in src,
    )
    pin(
        "scan failures are fixed templates",
        'UiScanInfo("scan failed"' in src
        and 'UiScanInfo("scan failed", "code not recognized", "rescan..."' in src,
    )

    print(f"\nPASS: no-session sign guard wiring contract holds ({PASS} pins)")

    # 5. failure latch (2026-10-09): no doomed-message re-collection loop
    pin(
        "failure latch: set on pairing fail, frames dropped, cleared on QR-away",
        "g_ur_latch = 1;" in src
        and "if (g_ur_latch) {" in src
        and "pairing_fail_reason" in src,
    )
