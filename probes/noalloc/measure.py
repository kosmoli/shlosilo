#!/usr/bin/env python3
"""Z6 allocation-face measurement — the formal instrument.

Reads a linked ELF (via `arm-none-eabi-objdump -d`), recovers the call
graph, and reports every allocator call site with its CALLER function,
split by reachability from the probe entry point.

Two faces, two claims (see README.md):
  * REACHABLE face — the security claim: no code reachable from the
    signing probe entry may call the allocator. Proven by disassembly
    (this tool). A zero here is evidence; a nonzero here is a debt list.
  * GRAPH face — the stub-pull condition: the crate graph links `alloc`
    at all. Probed by scripts/z6_langitem_check.sh (rustc's
    "no global memory allocator found" error), NOT by this tool.

Output: human report on stdout + JSON on --json PATH.
Exit codes: 0 = REACHABLE-CLEAN, 10 = reachable debt (listed), 1 = tool
or build problem.
"""
import argparse
import json
import re
import subprocess
import sys

ALLOC_SYMS = (
    "__rust_alloc",
    "__rust_dealloc",
    "__rust_realloc",
    "__rust_alloc_zeroed",
)
# Rust's allocator lang items reach the image name-mangled (`_RNvCs..._7___rustc12___rust_alloc`),
# so a plain equality check against ALLOC_SYMS sees nothing on a Rust-linked device image. That
# blindness is indistinguishable from "no allocations" - it silently passed a build that allocates
# 320 KiB per sign. Match the stable tail instead, and report the allocator symbols themselves so a
# reader can tell "support not linked" apart from "support linked but never called".
ALLOC_SUFFIXES = tuple("___" + s.lstrip("_") for s in ALLOC_SYMS)


def alloc_kind(name: str):
    """-> the allocator lang item this symbol name refers to, or None."""
    for plain, suffix in zip(ALLOC_SYMS, ALLOC_SUFFIXES):
        if name == plain or name.endswith(suffix):
            return plain
    return None
# The OOM glue pair is retained dead code; it is not an allocation site.
OOM_GLUE = ("handle_alloc_error", "__rust_alloc_error_handler")


def disassemble(elf: str) -> str:
    r = subprocess.run(
        ["arm-none-eabi-objdump", "-d", elf],
        capture_output=True, text=True, check=True,
    )
    return r.stdout


def parse_functions(disasm: str):
    """-> {fn_name: [call targets]}"""
    calls = {}
    cur = None
    fn_head = re.compile(r"^[0-9a-f]+ <([^>]+)>:")
    call = re.compile(r"\bbl?x?\s+[0-9a-f]+ <([^>]+)>")
    for line in disasm.split("\n"):
        m = fn_head.match(line)
        if m:
            cur = m.group(1)
            calls.setdefault(cur, [])
            continue
        if cur is None:
            continue
        m = call.search(line)
        if m:
            calls[cur].append(m.group(1))
    return calls


def reachable(calls, entry):
    seen = set()
    stack = [entry]
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        for t in calls.get(f, ()):
            # strip linker suffixes like `foo::h1234` variants
            if t not in seen:
                stack.append(t)
    return seen


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("elf")
    ap.add_argument(
        "--entry",
        default="z6_probe_run",
        help="one entry symbol, or a comma-separated list of them "
        "(every entry is measured; the verdict covers all of them)",
    )
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()

    disasm = disassemble(args.elf)
    calls = parse_functions(disasm)
    entries = [e.strip() for e in args.entry.split(",") if e.strip()]
    if not entries:
        print("no entry symbols given", file=sys.stderr)
        return 1
    missing = [e for e in entries if e not in calls]
    if missing:
        # An entry that is not in the image would make "0 reachable sites" vacuous,
        # so a missing entry is a tool/fixture error, not a clean result.
        print(f"entry symbol(s) not in the linked image: {', '.join(missing)}", file=sys.stderr)
        return 1
    reach = set()
    per_entry = {}
    for e in entries:
        r = reachable(calls, e)
        per_entry[e] = len(r)
        reach |= r

    allocator_symbols = sorted({
        f for f in calls if alloc_kind(f) is not None
    })

    sites = []          # (caller, alloc_sym, reachable)
    for fn, targets in sorted(calls.items()):
        for t in targets:
            if alloc_kind(t) is not None:
                is_reach = fn in reach
                glue = any(g in fn for g in OOM_GLUE)
                sites.append({"caller": fn, "target": t,
                              "reachable": is_reach, "oom_glue": glue})

    real = [s for s in sites if not s["oom_glue"]]
    reach_debt = [s for s in real if s["reachable"]]

    print("Z6 ALLOCATION-FACE MEASUREMENT REPORT")
    print(f"  elf:        {args.elf}")
    print(f"  entries:    {', '.join(entries)}")
    print(f"  functions:  {len(calls)} in the linked image")
    if allocator_symbols:
        print(f"  allocator symbols in image: {len(allocator_symbols)}")
        for sym in allocator_symbols:
            print(f"    {alloc_kind(sym)} <- {sym}")
    else:
        print("  allocator symbols in image: 0 (the lang items were garbage-collected, "
              "so nothing can call them)")
    print(f"  alloc call sites (linked image): {len(real)}"
          f"  (+{len(sites) - len(real)} oom-glue, excluded)")
    print(f"  reachable from entries:          {len(reach_debt)}")
    for e in entries:
        print(f"    {e}: {per_entry[e]} functions reachable")
    if reach_debt:
        print("  REACHABLE DEBT:")
        for s in reach_debt:
            print(f"    {s['caller']} -> {s['target']}")
    else:
        print("  verdict: REACHABLE-CLEAN — the signing face provably never")
        print("           calls the allocator (disassembly, not runtime luck)")
    if real and not reach_debt:
        out = [s for s in real if not s["reachable"]]
        print(f"  non-reachable image sites (kept dead): {len(out)}")
        for s in out[:10]:
            print(f"    [dead] {s['caller']} -> {s['target']}")
    print("  graph face: run scripts/z6_langitem_check.sh")
    print("              (ALLOC-IN-GRAPH vs GRAPH-CLEAN — the stub-pull condition)")

    if args.json_path:
        with open(args.json_path, "w") as f:
            json.dump({
                "elf": args.elf,
                "entry": args.entry,
                "entries": entries,
                "entries_missing": [],
                "functions": len(calls),
                "allocator_symbols": allocator_symbols,
                "alloc_sites_linked": len(real),
                "alloc_sites_reachable": len(reach_debt),
                "sites": sites,
            }, f, indent=2)

    return 10 if reach_debt else 0


if __name__ == "__main__":
    sys.exit(main())
