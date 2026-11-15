#!/usr/bin/env python3
"""No-panic gate for `forms/` (the portable, hardware-agnostic core).

Rule (Kosmo, 2026-11-15): a panic is only acceptable for something we could not
possibly foresee, and even then only in `flux/` (the per-carrier I/O layer, where a
panic kills one device build). `forms/` is shared by every carrier, so it must
answer every input with a `Result` - including capacity failures, which are
*recoverable* (the wallet can ask the user to spend fewer coins) and therefore must
never abort.

Scope, conservative:
  * only the part of each file before its `#[cfg(test)]` module is production code;
  * `#[test]` / `#[prop]` functions in that part are removed by brace matching;
  * comment lines and compile-time assertions (`const _: () = assert!(..)`) are
    ignored - the latter cannot panic at runtime;
  * `debug_assert*` is reported for information but not enforced (release builds
    compile it out; the enforced surface is what ships).

Budgets:
  * panic-class macros (`panic!`, `assert!`, `assert_eq!`, `assert_ne!`,
    `unreachable!`, `todo!`) must be **zero**;
  * `unwrap()` / `expect(` / `unimplemented!()` are ratcheted - the numbers in
    RATCHET may only shrink, and lowering one in the same commit that removes the
    call site is the intended way to spend them.
"""
import os
import re
import sys

ROOT = "forms"
PANIC_CLASS = re.compile(r"(?<!debug_)\b(panic!|assert!|assert_eq!|assert_ne!|unreachable!|todo!)\s*[(!]")
DEBUG_CLASS = re.compile(r"\bdebug_assert(_eq|_ne)?!\s*[(!]")
RATCHET = {
    # name: (pattern, budget) - budgets only ever go down
    "unimplemented!": (re.compile(r"\bunimplemented!\s*\("), 0),
    "unwrap()": (re.compile(r"\.unwrap\(\)"), 16),
    "expect(": (re.compile(r"\.expect\("), 22),
}
TEST_FN_ATTR = re.compile(r"^\s*#\[(test|prop|rstest|quickcheck|cfg\(test\))\]")
COMMENT_OR_DOC = re.compile(r"^\s*(//|/\*|\*)")
COMPILE_TIME_ASSERT = re.compile(r"^\s*const\s+_\s*:")


def strip_test_scaffolding(text):
    """Return the file text with `#[cfg(test)]` tails and `#[test]` fns removed."""
    idx = text.find("#[cfg(test)]")
    if idx >= 0:
        text = text[:idx]
    out = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        if TEST_FN_ATTR.match(lines[i]):
            # Skip the attributed item: find its first '{' then match braces,
            # or (for attribute-only lines) swallow until a line ending in ';'.
            depth = 0
            started = False
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                if "{" in lines[i]:
                    started = True
                if started and depth <= 0:
                    i += 1
                    break
                if not started and lines[i].rstrip().endswith(";"):
                    i += 1
                    break
                i += 1
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def main():
    counts = {name: 0 for name in RATCHET}
    panic_hits = []
    debug_hits = 0
    scanned = 0
    for dirpath, _, files in os.walk(ROOT):
        for name in sorted(files):
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            scanned += 1
            prod = strip_test_scaffolding(open(path, errors="replace").read())
            for lineno, line in enumerate(prod.splitlines(), 1):
                if COMMENT_OR_DOC.match(line) or COMPILE_TIME_ASSERT.match(line):
                    continue
                debug_hits += len(DEBUG_CLASS.findall(line))
                for match in PANIC_CLASS.finditer(line):
                    # `const _: () = assert!(..)` filtered above; anything left runs.
                    panic_hits.append((f"{path}:{lineno}", match.group(1), line.strip()[:100]))
                for key, (pattern, _budget) in RATCHET.items():
                    counts[key] += len(pattern.findall(line))

    failures = []
    if panic_hits:
        failures.append(f"{len(panic_hits)} panic-class macro(s) in forms/ production code (budget 0):")
        for where, macro, text in panic_hits:
            failures.append(f"    {where}  {macro}  {text}")
    for key, (_pattern, budget) in RATCHET.items():
        if counts[key] > budget:
            failures.append(
                f"{key}: {counts[key]} > ratchet budget {budget} "
                f"(the budget only goes down: fix the new call site, or lower it deliberately)"
            )

    print(f"scanned {scanned} files under {ROOT}/ (production part only)")
    for key, (_p, budget) in RATCHET.items():
        print(f"  ratchet {key:16s} {counts[key]:3d} / {budget}")
    print(f"  info    debug_assert*   {debug_hits:3d} (compiled out of release; not enforced)")
    if failures:
        print()
        for line in failures:
            print(line)
        print("NOPANIC=1")
        return 1
    print("NOPANIC=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
