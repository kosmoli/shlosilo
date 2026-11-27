#!/usr/bin/env python3
"""Read cargo's JSON message stream (`--message-format=json-render-diagnostics`).

Why this exists: two things a build wrapper needs are only knowable from cargo itself.

**The artifact paths a delivery receipt must hash.** Reported per unit
(`compiler-artifact`), and not guessable for a workspace with several shims.

The build identity is deliberately NOT read from here: it used to come from the
`build-script-executed` message's `out_dir`, but cargo replays a fresh build script's output
without re-emitting that message, so the lookup worked on a warm tree and vanished on a clean
checkout (measured in CI). `build.rs` now also writes the identity to a stable path
(`build/build-identity/<target>/<profile>/`) that any tool can compute.

Usage:
  cargo_msg.py out-dir   <json-log>   # OUT_DIR of the `shlosilo` (forms) build script
  cargo_msg.py artifacts <json-log>   # artifact files, one absolute path per line

Exit 1 with a message on stderr when the answer is empty or ambiguous: an empty
answer must never look like a successful one to the caller (that is how a receipt
ends up attesting nothing).
"""
import json
import os
import sys

# The forms core package. Its build script owns the limits/identity projection.
CORE_PACKAGE = "#shlosilo@"

# Products worth hashing in a receipt. `.rmeta`/`.d`/`.json` are intermediates.
PRODUCT_EXTS = (".rlib", ".a", ".elf", ".bin", ".uf2", ".so", ".dylib", ".exe")


def messages(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue


def artifacts(path):
    """Artifact files of THIS WORKSPACE's packages (never the dependency tree).

    A receipt hashes what this repository produced. Including every dependency rlib
    (hundreds of lines from vendor/ and the registry cache) would bury the two files a
    reader cares about and imply the receipt vouches for third-party builds it never saw.
    Membership is read from the package id: path packages whose directory is inside the
    working tree but not inside `vendor/` (vendored crates are third-party code that
    happens to live here). Build-script `out/` intermediates are dropped too — they are
    by-products of a package, not its product.
    """
    repo = os.getcwd()
    found = []
    for msg in messages(path):
        if msg.get("reason") != "compiler-artifact":
            continue
        pid = msg.get("package_id") or ""
        if not pid.startswith("path+file://"):
            continue
        pkg_dir = pid[len("path+file://") :].split("#")[0]
        if not (pkg_dir == repo or pkg_dir.startswith(repo + os.sep)):
            continue
        if pkg_dir.startswith(os.path.join(repo, "vendor") + os.sep):
            continue
        names = list(msg.get("filenames") or [])
        exe = msg.get("executable")
        if exe:
            names.append(exe)
        for name in names:
            if not name or name in found:
                continue
            # A bin target's product is `executable`, and on bare-metal targets it has NO
            # extension (`shlosilo-pico2`, not `shlosilo-pico2.elf`). Filtering by extension
            # alone silently dropped exactly the file a firmware receipt must hash — measured
            # on a pico2 delivery build whose receipt said "produced no artifact".
            is_product = name.endswith(PRODUCT_EXTS) or name == exe
            if not is_product or not os.path.isfile(name):
                continue
            # `<target>/<profile>/build/<pkg>/<hash>/out/...` = a build script's output.
            if os.sep + "build" + os.sep in name and os.sep + "out" + os.sep in name:
                continue
            found.append(name)
    return found


def main(argv):
    if len(argv) != 3 or argv[1] not in ("out-dir", "artifacts"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, log = argv[1], argv[2]
    if not os.path.isfile(log):
        print(f"ERROR: no such cargo json log: {log}", file=sys.stderr)
        return 2

    if mode == "artifacts":
        found = artifacts(log)
        if not found:
            # Silence here is what let receipts claim to hash "every artifact" while
            # listing none: the caller renders an explanation, but only if we refuse.
            print(
                "ERROR: no artifact of this workspace appears in the cargo json log "
                "(type-check surfaces produce none; a build that produced a binary "
                "but is missing here means the artifact filter is wrong)",
                file=sys.stderr,
            )
            return 1
        for path in found:
            print(path)
        return 0

    # out-dir: DEPRECATED. `build.rs` writes the identity to a stable path
    # (build/build-identity/<target>/<profile>/build_identity.txt) because cargo never
    # re-emits `build-script-executed` for a fresh build script (measured on a clean CI
    # checkout). Kept only so an old caller fails with an explanation, not silence.
    for msg in messages(log):
        if msg.get("reason") != "build-script-executed":
            continue
        if not (msg.get("package_id") or "").startswith(CORE_PACKAGE):
            continue
        out_dir = msg.get("out_dir")
        if out_dir:
            print(out_dir)
            return 0
    print(
        "ERROR: no `build-script-executed` message for the core package in this log. "
        "This lookup is cache-dependent by design; read "
        "build/build-identity/<target>/<profile>/build_identity.txt instead.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
