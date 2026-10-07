#!/usr/bin/env python3
"""P2 gate: manually-maintained C declarations must match the Rust FFI
signatures they mirror (name, return type, parameter types, in order).

Why: the flux/keysource QR glue lives in a crate `cbindgen --crate shlosilo`
never parses, so its C declarations ride the cbindgen.toml `trailer` string.
cbindgen regen reproduces that trailer VERBATIM, so a changed Rust signature
keeps the byte-equal header gate (check_header.sh) GREEN while the C host
compiles against a stale ABI. This gate closes that hole: it parses the real
Rust `extern "C" fn` signatures out of the glue sources and the declarations
out of the trailer, normalizes both to one canonical type vocabulary, and
fails on any drift — in either direction (decl without fn, fn without decl).

Normalization scope is the FFI type vocabulary actually used (c_int/c_uint/
u8/u16/u32/size_t/char/void + opaque `struct` handles + up to two pointer
levels). A type the script cannot normalize is a hard error, never a silent
pass.

Run:  python3 scripts/check_ffi_decls.py          (exit 1 on drift)
Hooked into scripts/check_header.sh -> CI "C header sync gate" +
flux/forgebox/build.sh.
"""
import re
import sys
from pathlib import Path

try:
    import tomllib
except ImportError:  # pragma: no cover - python < 3.11
    tomllib = None

REPO = Path(__file__).resolve().parent.parent
CBINDGEN_TOML = REPO / "cbindgen.toml"
# The crate cbindgen cannot see: every `pub extern "C" fn` in here must be
# declared in the trailer (and vice versa).
KEYSOURCE_SRC = REPO / "flux/keysource/src"

RUST_FN_RE = re.compile(
    r"pub\s+(?:unsafe\s+)?extern\s+\"C\"\s+fn\s+(shlosilo_\w+)\s*\((.*?)\)\s*"
    r"(?:->\s*([^{]+?))?\s*\{",
    re.S,
)
C_DECL_RE = re.compile(r"([A-Za-z_][\w\s\*]*?)\b(\w+)\s*\(([^;)]*)\)\s*;")

RUST_BASE = {
    "c_int": "int", "i32": "int",
    "c_uint": "uint", "u32": "uint",
    "u8": "u8", "u16": "u16", "u64": "u64",
    "usize": "size_t", "size_t": "size_t",
    "char": "char", "c_char": "char",
    "()": "void",
}
C_BASE = {
    "int": "int", "unsignedint": "uint", "uint": "uint",
    "uint8_t": "u8", "uint16_t": "u16", "uint32_t": "u32", "uint64_t": "u64",
    "size_t": "size_t", "char": "char", "void": "void",
}


class Unnormalizable(Exception):
    pass


def norm_rust_type(t: str):
    """Rust FFI type -> (base, pointer_depth, innermost_pointee_const)."""
    t = re.sub(r"\s+", "", t)
    depth = 0
    inner_const = False
    while t.startswith("*"):
        t = t[1:]
        if t.startswith("const"):
            inner_const = True
            t = t[5:]
        elif t.startswith("mut"):
            inner_const = False
            t = t[3:]
        else:
            raise Unnormalizable(t)
        depth += 1
    base = RUST_BASE.get(t)
    if base is None:
        if not re.fullmatch(r"[A-Z]\w*", t):  # opaque handle type
            raise Unnormalizable(t)
        base = t
    return (base, depth, inner_const)


C_TYPE_WORDS = {
    "const", "volatile", "struct", "unsigned", "signed", "int", "char", "void",
    "uint8_t", "uint16_t", "uint32_t", "uint64_t", "size_t", "long", "short",
}


def norm_c_type(t: str):
    """C declaration type -> the same (base, pointer_depth, pointee_const)."""
    raw = t.strip()
    if not raw:
        raise Unnormalizable("(empty)")
    # Drop the trailing declarator name ("unsigned int ws_len" -> "unsigned int").
    words = raw.replace("*", " ").split()
    if words and words[-1] not in C_TYPE_WORDS:
        raw = raw[: raw.rfind(words[-1])].strip()
    depth = raw.count("*")
    core = raw.replace("*", " ").replace("struct", " ")
    toks = [w for w in re.sub(r"\s+", " ", core).split(" ") if w]
    const = "const" in toks
    toks = [w for w in toks if w not in ("const", "volatile")]
    if not toks:
        raise Unnormalizable(raw)
    key = "".join(toks) if toks[0] == "unsigned" else toks[0]
    if toks[0] == "unsigned" and toks[1:] not in (["int"], []):
        raise Unnormalizable(raw)
    base = C_BASE.get(key)
    if base is None:
        if not re.fullmatch(r"[A-Z]\w*", toks[0]):  # opaque handle type
            raise Unnormalizable(raw)
        base = toks[0]
    return (base, depth, const if depth else False)


def split_params(s: str):
    """Split a parameter list on top-level commas (generic <...> safe)."""
    s = s.strip()
    if not s or s == "void":
        return []
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def rust_sig(fn_src):
    """(ret, [param types]) in normalized form for one Rust fn match."""
    params_raw, ret_raw = fn_src
    ret = norm_rust_type(ret_raw.strip()) if ret_raw else ("void", 0, False)
    types = []
    for p in split_params(params_raw):
        m = re.match(r"\s*[\w_]+\s*:\s*(.+)$", p, re.S)
        if not m:
            raise Unnormalizable(p)
        types.append(norm_rust_type(m.group(1)))
    return (ret, types)


def c_sig(ret_raw: str, params_raw: str):
    ret = norm_c_type(ret_raw)
    types = [norm_c_type(p) for p in split_params(params_raw)]
    return (ret, types)


def collect_rust_fns():
    fns = {}
    for path in sorted(KEYSOURCE_SRC.rglob("*.rs")):
        src = re.sub(r"//[^\n]*", "", path.read_text())
        for m in RUST_FN_RE.finditer(src):
            name = m.group(1)
            if name in fns:
                raise SystemExit(f"FAIL: duplicate extern fn {name}")
            fns[name] = rust_sig((m.group(2), m.group(3)))
    return fns


def collect_trailer_decls():
    if tomllib is None:
        raise SystemExit("FAIL: python >= 3.11 (tomllib) required")
    cfg = tomllib.loads(CBINDGEN_TOML.read_text())
    trailer = cfg.get("trailer", "")
    if not trailer:
        raise SystemExit("FAIL: cbindgen.toml has no trailer to check")
    src = re.sub(r"/\*.*?\*/", "", trailer, flags=re.S)
    src = re.sub(r"//[^\n]*", "", src)
    decls = {}
    for m in C_DECL_RE.finditer(src):
        ret_raw, name, params = m.group(1), m.group(2), m.group(3)
        if name in decls:
            raise SystemExit(f"FAIL: duplicate trailer decl {name}")
        decls[name] = c_sig(ret_raw, params)
    return decls


def fmt(sig):
    ret, types = sig
    show = lambda t: ("%s%s%s" % ("const " if t[2] else "", t[0], "*" * t[1])).strip()
    return "%s (%s)" % (show(ret), ", ".join(show(t) for t in types))


def main():
    try:
        fns = collect_rust_fns()
        decls = collect_trailer_decls()
    except Unnormalizable as e:
        raise SystemExit(f"FAIL: unparsable FFI type (extend the vocabulary): {e}")
    errors = []
    for name, dsig in sorted(decls.items()):
        if name not in fns:
            errors.append(f"trailer declares {name} but no Rust extern fn exists")
            continue
        if dsig != fns[name]:
            errors.append(
                f"{name}: trailer {fmt(dsig)} != rust {fmt(fns[name])}"
            )
    for name in sorted(fns):
        if name not in decls:
            errors.append(f"rust fn {name} is not declared in the trailer")
    if errors:
        print("FAIL: FFI declarations drifted from the Rust signatures:")
        for e in errors:
            print("  " + e)
        print("  (the trailer is cbindgen-regen output; edit it in cbindgen.toml")
        print("   and regenerate shlosilo.h to match the Rust source)")
        sys.exit(1)
    print(f"OK: {len(decls)} trailer declarations match the Rust signatures")


if __name__ == "__main__":
    main()
