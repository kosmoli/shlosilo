#!/usr/bin/env python3
"""Read cargo's JSON message stream (`--message-format=json-render-diagnostics`).

Why this exists: two things a build wrapper needs are only knowable from cargo itself.

1. **The root package's build-script `OUT_DIR`.** `build.rs` writes the build identity
   (`build_identity.txt`) and the C identity header there. The directory name carries a
   hash, so guessing (`target/<triple>/<profile>/build/shlosilo-<hash>/out`) is not a
   plan; cargo reports it as a `build-script-executed` message.
2. **The artifact paths a delivery receipt must hash.** Also reported per unit
   (`compiler-artifact`), and also not guessable for a workspace with several shims.

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


def out_dirs(path):
    found = []
    for msg in messages(path):
        if msg.get("reason") != "build-script-executed":
            continue
        if CORE_PACKAGE not in (msg.get("package_id") or ""):
            continue
        out = msg.get("out_dir")
        if out and out not in found:
            found.append(out)
    return found


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
            if not name.endswith(PRODUCT_EXTS) or not os.path.isfile(name):
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
    if mode == "out-dir":
        found = out_dirs(log)
        if not found:
            print(
                "cargo_msg.py: no build-script-executed message for the forms core in "
                f"{log} (was the package actually built?)",
                file=sys.stderr,
            )
            return 1
        if len(found) > 1:
            print(
                "cargo_msg.py: ambiguous OUT_DIR for the forms core "
                f"({len(found)} units): {found}",
                file=sys.stderr,
            )
            return 1
        print(found[0])
        return 0
    for name in artifacts(log):
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
