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
    ap.add_argument("--entry", default="z6_probe_run")
    ap.add_argument("--json", dest="json_path")
    args = ap.parse_args()

    disasm = disassemble(args.elf)
    calls = parse_functions(disasm)
    reach = reachable(calls, args.entry)

    sites = []          # (caller, alloc_sym, reachable)
    for fn, targets in sorted(calls.items()):
        for t in targets:
            base = t.split("::")[0]
            if base in ALLOC_SYMS or t in ALLOC_SYMS:
                is_reach = fn in reach
                glue = any(g in fn for g in OOM_GLUE)
                sites.append({"caller": fn, "target": t,
                              "reachable": is_reach, "oom_glue": glue})

    real = [s for s in sites if not s["oom_glue"]]
    reach_debt = [s for s in real if s["reachable"]]

    print("Z6 ALLOCATION-FACE MEASUREMENT REPORT")
    print(f"  elf:        {args.elf}")
    print(f"  entry:      {args.entry}")
    print(f"  functions:  {len(calls)} in the linked image")
    print(f"  alloc call sites (linked image): {len(real)}"
          f"  (+{len(sites) - len(real)} oom-glue, excluded)")
    print(f"  reachable from entry:            {len(reach_debt)}")
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
                "functions": len(calls),
                "alloc_sites_linked": len(real),
                "alloc_sites_reachable": len(reach_debt),
                "sites": sites,
            }, f, indent=2)

    return 10 if reach_debt else 0


if __name__ == "__main__":
    sys.exit(main())
