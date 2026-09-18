#!/usr/bin/env python3
"""Cross-check the C word wrap against the Python mirror before flashing.

The firmware (src/ui/ui_wrap.c) and the host preview (preview_ui.py) implement
the same wrap algorithm in two languages; a silent drift shows up as dropped
characters on the device. This script builds a tiny gcc harness around the
real C file, runs both implementations over a set of tricky cases, and
requires byte-identical output. It also asserts the no-loss property
(join(lines) == input minus newline characters) in Python.

Run before flashing any change to the wrap logic:
    python3 flux/forgebox/scripts/test_wrap.py
"""

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
UI_DIR = REPO / "flux/forgebox/src/ui"
sys.path.insert(0, str(REPO / "flux/forgebox/scripts"))

from preview_ui import parse_layout, wrap_payload  # noqa: E402

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include "ui_wrap.h"

int main(int argc, char **argv)
{
    unsigned long chars = strtoul(argv[1], NULL, 10);
    int max_lines = (int)strtol(argv[2], NULL, 10);
    static char buf[65536];

    for (int a = 3; a < argc; a++) {
        FILE *f = fopen(argv[a], "rb");
        if (!f) { return 2; }
        size_t n = fread(buf, 1, sizeof(buf), f);
        fclose(f);

        UiWrapLine lines[64];
        bool trunc = false;
        int count = ui_wrap_text(buf, (uint32_t)n, (uint32_t)chars, max_lines,
                                 lines, &trunc);
        printf("case %s count=%d trunc=%d\n", argv[a], count, trunc ? 1 : 0);
        for (int i = 0; i < count; i++) {
            printf("line %d: %u:%.*s\n", i, lines[i].len,
                   (int)lines[i].len, buf + lines[i].start);
        }
    }
    return 0;
}
"""


def main() -> None:
    L = parse_layout(UI_DIR / "ui_layout.h")
    chars = L["UI_P_CHARS_PER_LINE"]
    max_lines = L["UI_P_MAX_LINES"]

    sample = ("SHLOSILO-FORGEBOX-OK-2026 " * 6) + "\n" + (
        "ur:eth-sign-request/otaohddmaowpadlalrfrnysgaelrktecmwaelfgmay"
        "mwcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcpcplfaxvdlartlalalaaxad"
        "aaadrpceaadt")

    cases = {
        "sample.txt": sample,
        "long_token.txt": "X" * 200,
        "short.txt": "short",
        "blank_lines.txt": "a b c d e\n\nf g h",
        "trailing_spaces.txt": "abc   \ndef",
        "exact_line.txt": ("E" * chars) + " tail",
        "empty.txt": "",
        "token_130.txt": "A" * 130,
        "crlf.txt": "line1\r\nline2\r\n",
        "words.txt": "word ending in space then break test " * 3,
        "mixed.txt": "prefix " + "Z" * 70 + " suffix\nnext line here",
    }

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        harness_c = td / "harness.c"
        harness_bin = td / "wrap_test"
        harness_c.write_text(HARNESS, encoding="utf-8")

        subprocess.run(
            ["gcc", "-O2", "-Wall", "-Wextra", "-o", str(harness_bin),
             str(harness_c), str(UI_DIR / "ui_wrap.c"), "-I", str(UI_DIR)],
            check=True)

        case_files = {}
        for name, text in cases.items():
            p = td / name
            p.write_bytes(text.encode("utf-8"))
            case_files[name] = p

        c_out = subprocess.run(
            [str(harness_bin), str(chars), str(max_lines)]
            + [str(p) for p in case_files.values()],
            check=True, capture_output=True, text=True).stdout

    # Python mirror in the same format.
    py_lines = []
    content_fails = []
    for name, text in cases.items():
        p = case_files[name]  # same path string the C harness printed
        lines, trunc = wrap_payload(text, chars, max_lines)
        py_lines.append(f"case {p} count={len(lines)} trunc={1 if trunc else 0}")
        for i, ln in enumerate(lines):
            py_lines.append(f"line {i}: {len(ln)}:{ln}")

        if not trunc:
            joined = "".join(lines)
            expected = text.replace("\n", "").replace("\r", "")
            if joined != expected:
                content_fails.append(name)
    py_out = "\n".join(py_lines) + "\n"

    if c_out != py_out:
        print("MISMATCH between C and Python wrap:")
        c_lines = c_out.splitlines()
        py_split = py_out.splitlines()
        for i in range(max(len(c_lines), len(py_split))):
            c_l = c_lines[i] if i < len(c_lines) else "<missing>"
            p_l = py_split[i] if i < len(py_split) else "<missing>"
            if c_l != p_l:
                print(f"  C  : {c_l}")
                print(f"  Py : {p_l}")
        sys.exit(1)

    if content_fails:
        print(f"CONTENT LOSS in Python wrap for cases: {content_fails}")
        sys.exit(1)

    print(f"wrap cross-check PASS: {len(cases)} cases, C == Python, no lost characters")
    print(f"  chars_per_line={chars} max_lines={max_lines}")


if __name__ == "__main__":
    main()
