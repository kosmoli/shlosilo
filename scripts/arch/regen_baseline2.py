#!/usr/bin/env python3
"""Regenerate vendor baseline diffs in the canonical a/ b/ shape."""
import os
import shutil
import subprocess
import tarfile
import tempfile

ROOT = "/home/komo/works/shlosilo-poc4"
ANCH = os.path.expanduser("~/.cache/shlosilo-vendor-anchors")
REG = os.path.expanduser("~/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f")

CHANGED = {
    "curve25519-dalek": ("curve25519-dalek-4.1.3.crate", "curve25519-dalek-vs-crates-io-4.1.3.diff"),
    "monero-bulletproofs": ("monero-bulletproofs-0.1.0.crate", "monero-bulletproofs-vs-crates-io-0.1.0.diff"),
    "monero-clsag": ("monero-clsag-0.1.0.crate", "monero-clsag-vs-crates-io-0.1.0.diff"),
    "monero-ed25519": ("monero-ed25519-0.1.0.crate", "monero-ed25519-vs-crates-io-0.1.0.diff"),
    "monero-io": ("monero-io-0.1.0.crate", "monero-io-vs-crates-io-0.1.0.diff"),
    "std-shims": ("std-shims-0.1.5.crate", "std-shims-vs-crates-io-0.1.5.diff"),
    "monero-bulletproofs-generators": ("monero-bulletproofs-generators-0.1.0.crate", "monero-bulletproofs-generators-vs-crates-io-0.1.0.diff"),
    "base58-monero": ("base58-monero-2.1.0.crate", "base58-monero-vs-crates-io-2.1.0.diff"),
}

for tree, (crate, diffname) in CHANGED.items():
    src = os.path.join(ANCH, crate)
    if not os.path.exists(src):
        reg = os.path.join(REG, crate)
        if os.path.exists(reg):
            shutil.copy(reg, src)
        else:
            print(f"{tree}: *** ANCHOR MISSING ***")
            continue
    with tempfile.TemporaryDirectory() as td:
        a = os.path.join(td, "a")
        b = os.path.join(td, "b")
        os.makedirs(a)
        with tarfile.open(src) as tf:
            tf.extractall(a, filter="tar")
        entries = os.listdir(a)
        if len(entries) == 1:
            inner = os.path.join(a, entries[0])
            for e in os.listdir(inner):
                shutil.move(os.path.join(inner, e), a)
        shutil.copytree(os.path.join(ROOT, "vendor", tree), b, symlinks=True)
        r = subprocess.run(
            ["diff", "-ruN", "--exclude=target", "--exclude=Cargo.lock",
             "--exclude=.cargo-checksum.json", "--exclude=.cargo-ok", "a", "b"],
            capture_output=True, text=True, cwd=td)
        out = os.path.join(ROOT, "patches", "baseline", diffname)
        open(out, "w").write(r.stdout)
        print(f"{tree}: {r.stdout.count(chr(10))} lines")

# cryptonight: git-subtree anchor (Cuprate/cuprate tarball @ cf3137b7579b), the
# crate lives in the tarball's `cryptonight/` subdir — mirrors SUBDIR_cryptonight
# in scripts/vendor_baseline_check.sh. Generated in the canonical a/b shape with
# the documented exclusions (vendor/BASELINE.md: target/, Cargo.lock,
# .cargo-checksum.json, .cargo-ok are build artifacts, not tree content).
CN_ANCH = os.path.join(ANCH, "cf3137b7579bfc930303243a634ca4d66b7266ed")
if not os.path.exists(CN_ANCH):
    print("cryptonight: *** ANCHOR MISSING ***")
else:
    with tempfile.TemporaryDirectory() as td:
        ext = os.path.join(td, "ext")
        with tarfile.open(CN_ANCH) as tf:
            tf.extractall(ext, filter="tar")
        tops = os.listdir(ext)
        assert len(tops) == 1, tops
        a = os.path.join(td, "a")
        b = os.path.join(td, "b")
        shutil.copytree(os.path.join(ext, tops[0], "cryptonight"), a, symlinks=True)
        shutil.copytree(os.path.join(ROOT, "vendor", "cryptonight"), b, symlinks=True)
        r = subprocess.run(
            ["diff", "-ruN", "--exclude=target", "--exclude=Cargo.lock",
             "--exclude=.cargo-checksum.json", "--exclude=.cargo-ok", "a", "b"],
            capture_output=True, text=True, cwd=td)
        out = os.path.join(ROOT, "patches", "baseline",
                           "cryptonight-vs-upstream-cf3137b7579b.diff")
        open(out, "w").write(r.stdout)
        print(f"cryptonight: {r.stdout.count(chr(10))} lines")
print("done")
