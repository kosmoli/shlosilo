#!/usr/bin/env python3
"""Report the C surface a given chain set actually sees in `shlosilo.h`.

The header is chain-parametric (`[defines]` in cbindgen.toml turns every `#[cfg(feature =
"chain-*")]` into `#if defined(SHLOSILO_CHAIN_*)`), so "what does the host compile against"
depends on the macros the host defines. This module answers that question from the header text
alone, with no knowledge of how the header was generated - which is what makes it usable as an
independent second opinion against the keep table.

Usage:
    python3 scripts/header_chain_surface.py --chains btc,eth        # what a btc+eth host sees
    python3 scripts/header_chain_surface.py --chains '' --guarded    # what a host sees with no
                                                                    # chain declared
    python3 scripts/header_chain_surface.py --chains btc --blocks    # per-macro block spans

Exit codes: 0 = reported, 2 = the header is malformed (`#if`/`#endif` unbalanced) or a
`#if defined(...)` names a macro this script does not model (fail closed: an unmodelled guard
means the report would silently ignore a condition, exactly the class of bug the guards exist to
prevent).
"""
import argparse
import re
import sys

CHAIN_MACROS = {
    "SHLOSILO_CHAIN_BTC": "btc",
    "SHLOSILO_CHAIN_ETH": "eth",
    "SHLOSILO_CHAIN_XMR": "xmr",
}

# Declarations we care about: function prototypes and #define constants.
_RE_PROTO = re.compile(r"^[A-Za-z_][\w \t\*]*?\b(shlosilo_\w+)\s*\(")
_RE_DEFINE = re.compile(r"^#define\s+([A-Za-z_]\w*)")


def _guard_macros(directive):
    """Macro names in an `#if defined(X) [-/&&/|| ...]` line, or None if unmodelled."""
    body = directive.strip()[len("#if"):].strip()
    names = re.findall(r"defined\s*\(\s*(\w+)\s*\)", body)
    # Anything left after removing the defined(...) atoms must be only boolean glue.
    residue = re.sub(r"defined\s*\(\s*\w+\s*\)", "", body)
    residue = residue.replace("&&", "").replace("||", "").replace("!", "")
    residue = residue.replace("(", "").replace(")", "").strip()
    if residue:
        # `#if 0`, `#if defined(A) && A > 3`, ... - not something this script models.
        return None
    return names


def scan(text):
    """Yield (line_no, kind, name, chain_set_that_exposes_it_is_empty_or_not, active_macros)."""
    stack = []  # list of (line_no, frozenset(macros) or None)
    out = []
    for no, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if line.startswith("#if"):
            macros = _guard_macros(line)
            if macros is None:
                return None, f"line {no}: unmodelled condition: {line!r}"
            stack.append((no, frozenset(macros)))
            continue
        if line.startswith("#ifdef") or line.startswith("#ifndef"):
            return None, f"line {no}: #ifdef/#ifndef is not modelled: {line!r}"
        if line.startswith("#else") or line.startswith("#elif"):
            return None, f"line {no}: #else/#elif is not modelled: {line!r}"
        if line.startswith("#endif"):
            if not stack:
                return None, f"line {no}: #endif without #if"
            stack.pop()
            continue
        m = _RE_PROTO.match(raw.strip()) or _RE_DEFINE.match(raw.strip())
        if not m:
            continue
        name = m.group(1)
        required = frozenset().union(*[s[1] for s in stack]) if stack else frozenset()
        unmodelled = sorted({mac for mac in required if mac not in CHAIN_MACROS})
        if unmodelled:
            return None, f"line {no}: {name} is guarded by a non-chain macro: {unmodelled}"
        out.append((no, "proto" if _RE_PROTO.match(raw.strip()) else "define", name,
                    required))
    if stack:
        return None, f"unterminated #if opened at line {stack[-1][0]}"
    return out, None


def exposed(items, chains):
    have = {CHAIN_MACROS[m] for m in CHAIN_MACROS}
    have = {m for m, c in CHAIN_MACROS.items() if c in chains}
    return [it for it in items if it[3] <= have]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--header", default="shlosilo.h")
    ap.add_argument("--chains", required=True,
                    help="comma-separated chain set, e.g. btc,eth (empty string = none)")
    ap.add_argument("--kind", choices=["proto", "define"], help="restrict to one declaration kind")
    ap.add_argument("--guarded", action="store_true",
                    help="print the declarations that a guard hides instead of the visible ones")
    ap.add_argument("--blocks", action="store_true",
                    help="print `macro<TAB>name` for every guarded declaration")
    args = ap.parse_args(argv)

    chains = {c.strip() for c in args.chains.split(",") if c.strip()}
    unknown = chains - {c for c in CHAIN_MACROS.values()}
    if unknown:
        print(f"error: unknown chain(s): {sorted(unknown)}", file=sys.stderr)
        return 2

    try:
        text = open(args.header, encoding="utf-8").read()
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    items, err = scan(text)
    if err:
        print(f"FAIL: {args.header}: {err}", file=sys.stderr)
        return 2
    assert items is not None  # scan() returns None only alongside an error

    if args.kind:
        items = [it for it in items if it[1] == args.kind]
    visible = exposed(items, chains)
    if args.blocks:
        for no, kind, name, required in items:
            if required:
                print(f"{sorted(CHAIN_MACROS[m] for m in required)[0]}\t{name}")
        return 0
    if args.guarded:
        for no, kind, name, required in items:
            if required and name not in {v[2] for v in visible}:
                print(f"{name}\t(needs {','.join(sorted(CHAIN_MACROS[m] for m in required))})")
        return 0
    for no, kind, name, required in visible:
        print(name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
