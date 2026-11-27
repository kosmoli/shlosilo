#!/usr/bin/env python3
"""CAPSCOPE gate: a chain may only reference the primitives it DECLARES.

What this checks (C1 scope — deliberately narrow, see "Scope" below):

  A. attribution  — a reference inside `forms/chain/<x>/` must be to a capability
                    declared by `capabilities/<x>.toml`.
  B. no orphans   — a reference anywhere in `forms/` must be to a capability that
                    SOME chain declares, or to a capability the vocabulary marks
                    `scope = "shared"`.
  C. declaration shape — unknown sections/keys/names are hard errors; a chain may
                    only declare `wired = true` capabilities (declaring a primitive
                    the product does not use is how a capability table turns into
                    marketing).
  D. debt separation — the frozen debt list is a SEPARATE file, and a debt entry may
                    not name a capability that some chain declares as supported.

Scope (stated on every run, and deliberately asserted): primitives are NOT cargo
features yet, so nothing here proves a dependency closure. The closure check
(`CARGO_FEATURE_PRIM_*` == closure(declared)) arrives with C3, when `prim-*` exist.
This gate is an ARCHITECTURE TRIPWIRE, not a dependency proof.

Fail-closed rules: an unknown key, an unknown section, an unparsable file, a
capability with no source mapping, or an empty scan is an ERROR (exit != 0), never a
silent pass. The scan also carries two sensitivity controls so "nothing matched"
cannot be mistaken for "everything is fine".

Usage:
  python3 scripts/check_capabilities.py            # gate mode (assertions)
  python3 scripts/check_capabilities.py --report   # print attribution, no assertions
  python3 scripts/check_capabilities.py --self-test  # negative fixtures must go red
"""
import fnmatch
import re
import sys
import tomllib
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CAPS = REPO / "capabilities"
FORMS = REPO / "forms"

SECTIONS = (
    "curves",
    "signatures",
    "proofs",
    "derivations",
    "address_encodings",
    "containers",
    "ur_codecs",
)
# Fields a capability may carry in the vocabulary table.
VOCAB_FIELDS = {"sources", "crates", "scope", "note"}
# scope=chain   the capability belongs to a chain; that chain declares it
# scope=shared  product-wide machinery (export/derivation plumbing); no chain owns it
# scope=library implemented for a chain this product does not sign for yet; NO chain may
#               declare it (declaring it is how a capability table turns into marketing)
SCOPES = ("chain", "shared", "library")
CHAIN_KEYS = {"schema_version", "chain"} | set(SECTIONS)
CHAIN_META = {"name", "rules_version", "coin_type", "container"}
DEBT_KEYS = {"schema_version", "debt"}

EXIT_SHAPE = 10
EXIT_ATTRIBUTION = 11
EXIT_ORPHAN = 12
EXIT_DEBT = 13
EXIT_BLIND = 14

BANNER = (
    "CAPSCOPE scope: source-level attribution ONLY. Primitives are not cargo features\n"
    "  yet, so this run does NOT prove a dependency closure; the closure check\n"
    "  (CARGO_FEATURE_PRIM_* == closure(declared)) is enforced from C3."
)


class Fail(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def load(path):
    try:
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        raise Fail(EXIT_SHAPE, f"missing file: {path}")
    except tomllib.TOMLDecodeError as exc:
        # Fail closed: an unparsable declaration is not "no declaration".
        raise Fail(EXIT_SHAPE, f"{path}: cannot parse ({exc})")


def load_vocab(caps):
    doc = load(caps / "_primitives.toml")
    unknown = set(doc) - {"schema_version"} - set(SECTIONS)
    if unknown:
        raise Fail(EXIT_SHAPE, f"_primitives.toml: unknown top-level keys {sorted(unknown)}")
    if doc.get("schema_version") != 1:
        raise Fail(EXIT_SHAPE, "_primitives.toml: schema_version must be 1")

    vocab = {}
    for section in SECTIONS:
        table = doc.get(section, {})
        if not isinstance(table, dict):
            raise Fail(EXIT_SHAPE, f"_primitives.toml: [{section}] must be a table")
        for name, entry in table.items():
            if name in vocab:
                raise Fail(EXIT_SHAPE, f"_primitives.toml: '{name}' declared twice")
            if not isinstance(entry, dict):
                raise Fail(EXIT_SHAPE, f"_primitives.toml: {section}.{name} must be a table")
            unknown = set(entry) - VOCAB_FIELDS
            if unknown:
                raise Fail(
                    EXIT_SHAPE,
                    f"_primitives.toml: {section}.{name} has unknown fields {sorted(unknown)} "
                    f"(known: {sorted(VOCAB_FIELDS)})",
                )
            sources = entry.get("sources", [])
            crates = entry.get("crates", [])
            if not sources and not crates:
                raise Fail(
                    EXIT_SHAPE,
                    f"_primitives.toml: {section}.{name} maps to no source — a capability the "
                    f"scanner can never see would make this gate blind, not green",
                )
            for src in sources:
                mod_path = FORMS.joinpath(*src.replace("::", "/").split("/")).with_suffix(".rs")
                mod_dir = FORMS.joinpath(*src.replace("::", "/").split("/"), "mod.rs")
                if not mod_path.is_file() and not mod_dir.is_file():
                    # A typo here would hide the capability from the scanner forever: the gate
                    # would stay green while the declaration meant nothing.
                    raise Fail(
                        EXIT_SHAPE,
                        f"_primitives.toml: {section}.{name} source '{src}' does not exist "
                        f"(looked for {mod_path} and {mod_dir})",
                    )
            scope = entry.get("scope", "chain")
            if scope not in SCOPES:
                raise Fail(EXIT_SHAPE, f"_primitives.toml: {section}.{name}.scope must be one of "
                                       f"{SCOPES}")
            vocab[name] = {
                "section": section,
                "sources": list(sources),
                "crates": list(crates),
                "scope": scope,
            }
    if not vocab:
        raise Fail(EXIT_BLIND, "_primitives.toml: vocabulary is empty")
    return vocab


def load_chains(caps, vocab):
    chains = {}
    for path in sorted(caps.glob("*.toml")):
        if path.name.startswith("_"):
            continue
        doc = load(path)
        unknown = set(doc) - CHAIN_KEYS
        if unknown:
            raise Fail(EXIT_SHAPE, f"{path.name}: unknown top-level keys {sorted(unknown)}")
        if doc.get("schema_version") != 1:
            raise Fail(EXIT_SHAPE, f"{path.name}: schema_version must be 1")
        meta = doc.get("chain")
        if not isinstance(meta, dict):
            raise Fail(EXIT_SHAPE, f"{path.name}: missing [chain] table")
        unknown = set(meta) - CHAIN_META
        if unknown:
            raise Fail(EXIT_SHAPE, f"{path.name}: [chain] has unknown keys {sorted(unknown)}")
        for required in ("name", "rules_version", "coin_type"):
            if required not in meta:
                raise Fail(EXIT_SHAPE, f"{path.name}: [chain].{required} is required")
        if path.stem != meta["name"]:
            raise Fail(EXIT_SHAPE, f"{path.name}: [chain].name '{meta['name']}' != file name")

        declared = {}
        for section in SECTIONS:
            table = doc.get(section, {})
            if not isinstance(table, dict):
                raise Fail(EXIT_SHAPE, f"{path.name}: [{section}] must be a table")
            for name, value in table.items():
                if name not in vocab:
                    raise Fail(
                        EXIT_SHAPE,
                        f"{path.name}: '{name}' in [{section}] is not in the vocabulary "
                        f"(capabilities/_primitives.toml)",
                    )
                if vocab[name]["section"] != section:
                    raise Fail(
                        EXIT_SHAPE,
                        f"{path.name}: '{name}' belongs in [{vocab[name]['section']}], "
                        f"not [{section}]",
                    )
                if value is not True:
                    raise Fail(
                        EXIT_SHAPE,
                        f"{path.name}: {section}.{name} = {value!r}; only `true` may appear — "
                        f"false entries invite 'is it off or unknown?' speculation",
                    )
                if vocab[name]["scope"] != "chain":
                    raise Fail(
                        EXIT_SHAPE,
                        f"{path.name}: declares '{name}', whose vocabulary scope is "
                        f"{vocab[name]['scope']}. Only scope=chain capabilities may be declared: "
                        f"a primitive that merely exists in the library is not a capability of "
                        f"this chain, and shared machinery belongs to no chain.",
                    )
                declared[name] = section
        if not declared:
            raise Fail(EXIT_SHAPE, f"{path.name}: declares no capability at all")
        chains[path.stem] = {"meta": meta, "declared": declared}
    if not chains:
        raise Fail(EXIT_BLIND, "no capability declarations found under capabilities/")
    return chains


def load_debt(caps, vocab):
    path = caps / "_debt.toml"
    doc = load(path)
    unknown = set(doc) - DEBT_KEYS
    if unknown:
        raise Fail(EXIT_SHAPE, f"_debt.toml: unknown top-level keys {sorted(unknown)}")
    if doc.get("schema_version") != 1:
        raise Fail(EXIT_SHAPE, "_debt.toml: schema_version must be 1")
    entries = doc.get("debt", [])
    if not isinstance(entries, list):
        raise Fail(EXIT_SHAPE, "_debt.toml: `debt` must be an array of tables")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            raise Fail(EXIT_SHAPE, "_debt.toml: every entry must be a table")
        required = {"id", "combination", "capability", "via", "clear_in"}
        optional = {"note"}
        missing = required - set(entry)
        if missing:
            raise Fail(EXIT_SHAPE, f"_debt.toml: entry missing fields {sorted(missing)}")
        extra = set(entry) - required - optional
        if extra:
            raise Fail(EXIT_SHAPE, f"_debt.toml: entry has unknown fields {sorted(extra)} "
                                   f"(required {sorted(required)}, optional {sorted(optional)})")
        if entry["id"] in seen:
            raise Fail(EXIT_SHAPE, f"_debt.toml: duplicate id {entry['id']}")
        seen.add(entry["id"])
        if entry["capability"] not in vocab:
            raise Fail(EXIT_SHAPE, f"_debt.toml: {entry['id']} names unknown capability "
                                   f"'{entry['capability']}'")
        via = entry["via"]
        if not (REPO / via).is_file():
            raise Fail(EXIT_SHAPE, f"_debt.toml: {entry['id']} via '{via}' does not exist — "
                                   f"a debt entry must point at the path that causes the excess")
        if not re.fullmatch(r"C[0-9]+", str(entry["clear_in"])):
            raise Fail(EXIT_SHAPE, f"_debt.toml: {entry['id']} clear_in must be C<N> (got "
                                   f"{entry['clear_in']!r})")
    return entries


def build_matchers(vocab):
    """Longest module path wins, so `ur::codec::crypto_psbt` is not read as `ur`."""
    items = []
    for name, meta in vocab.items():
        for src in meta["sources"]:
            items.append((len(src), name, src))
    items.sort(reverse=True)
    matchers = [(name, re.compile(r"\b(?:crate|shlosilo)::" + re.escape(src) + r"\b"))
                for _, name, src in items]
    crate_matchers = []
    for name, meta in vocab.items():
        for crate in meta["crates"]:
            ident = re.escape(crate.replace("-", "_"))
            crate_matchers.append((name, re.compile(r"\b" + ident + r"\b")))
    return matchers, crate_matchers


def scan(vocab):
    matchers, crate_matchers = build_matchers(vocab)
    per_file = {}
    files = 0
    for path in sorted(FORMS.rglob("*.rs")):
        text = path.read_text(encoding="utf-8", errors="replace")
        files += 1
        hits = {name for name, rx in matchers if rx.search(text)}
        hits |= {name for name, rx in crate_matchers if rx.search(text)}
        if hits:
            per_file[path.relative_to(REPO).as_posix()] = sorted(hits)
    return per_file, files


def chain_of(rel_path):
    parts = rel_path.split("/")
    if len(parts) >= 3 and parts[0] == "forms" and parts[1] == "chain":
        return parts[2]
    return None


def run(report_only=False, caps=None):
    # `caps` is a parameter, not a module global: a fixture must be able to point the checks at a
    # temporary directory WITHOUT mutating shared state (the earlier global-based self-test silently
    # re-read the real tree and every negative fixture "passed" by not going red at all).
    caps = caps or CAPS
    vocab = load_vocab(caps)
    chains = load_chains(caps, vocab)
    debt = load_debt(caps, vocab)
    per_file, files_scanned = scan(vocab)

    problems = []
    attributed = defaultdict(lambda: defaultdict(list))
    shared_hits = defaultdict(list)
    for rel, hits in per_file.items():
        chain = chain_of(rel)
        for name in hits:
            if chain:
                attributed[chain][name].append(rel)
            else:
                shared_hits[name].append(rel)

    # ── sensitivity controls: the instrument must be able to see things at all ──
    total_refs = sum(len(v) for v in per_file.values())
    chain_refs = sum(len(files) for names in attributed.values() for files in names.values())
    if files_scanned == 0:
        raise Fail(EXIT_BLIND, "scanned zero .rs files under forms/ — wrong working directory?")
    if total_refs == 0:
        raise Fail(EXIT_BLIND, "found zero primitive references — the matcher is blind, "
                               "this is not a pass")
    if chain_refs == 0:
        raise Fail(EXIT_BLIND, "found zero references inside forms/chain/*/ — either the tree "
                               "moved or the matcher is blind; attribution cannot be vacuously true")

    if report_only:
        print(f"files scanned: {files_scanned}  files with refs: {len(per_file)}  refs: {total_refs}")
        for chain in sorted(attributed):
            print(f"\n[{chain}] declared: {sorted(chains.get(chain, {}).get('declared', {}))}")
            for name in sorted(attributed[chain]):
                print(f"   ref {name:22s} <- {', '.join(attributed[chain][name][:3])}")
        print("\n[shared faces]")
        for name in sorted(shared_hits):
            print(f"   ref {name:22s} <- {len(shared_hits[name])} file(s)")
        return 0

    print(BANNER)
    # ── A: a chain module may only reference what it declares ──
    for chain, names in attributed.items():
        if chain not in chains:
            raise Fail(EXIT_ATTRIBUTION, f"forms/chain/{chain}/ exists but capabilities/{chain}.toml "
                                         f"does not — an undeclared chain with primitive references")
        declared = chains[chain]["declared"]
        for name, files in names.items():
            if name in declared or vocab[name]["scope"] == "shared":
                continue
            if True:
                problems.append(
                    f"A: forms/chain/{chain}/ references '{name}' "
                    f"({', '.join(files[:2])}) but {chain} does not declare it"
                )

    # ── B: no capability may be referenced without SOME owner ──
    owned = set()
    for info in chains.values():
        owned |= set(info["declared"])
    shared_caps = {name for name, meta in vocab.items() if meta["scope"] == "shared"}
    debt_caps = {entry["capability"] for entry in debt}
    library_refs = {n: f for n, f in shared_hits.items() if vocab[n]["scope"] == "library"}
    for name, files in shared_hits.items():
        if name in owned or name in shared_caps or vocab[name]["scope"] == "library":
            continue
        problems.append(
            f"B: '{name}' is referenced by shared code ({', '.join(files[:2])}) but no chain "
            f"declares it and it is not scope=shared"
            + (" — it is listed in _debt.toml, which licenses the excess but must not be the "
               "capability's only home" if name in debt_caps else "")
        )

    # ── D: debt and declaration must not overlap ──
    # A debt entry says "this capability is compiled into COMBINATION although no chain in it
    # declares it". Declaring it in one of those chains would silence the check by inflating
    # that chain's capability set — the exact move this separation exists to prevent.
    for entry in debt:
        cap = entry["capability"]
        combo = [c.strip() for c in str(entry["combination"]).split(",") if c.strip()]
        for chain in combo:
            if chain not in chains:
                raise Fail(EXIT_SHAPE, f"_debt.toml: {entry['id']} names unknown chain '{chain}'")
            if cap in chains[chain]["declared"]:
                problems.append(
                    f"D: {entry['id']} lists '{cap}' as excess for combination "
                    f"'{entry['combination']}', but capabilities/{chain}.toml declares it — "
                    f"debt is not a place to legalise a declaration, and a declaration is not a "
                    f"place to silence debt"
                )

    print(f"chains: {', '.join(sorted(chains))}")
    print(f"capabilities declared: {sum(len(i['declared']) for i in chains.values())} "
          f"across {len(chains)} chains; vocabulary: {len(vocab)}; debt entries: {len(debt)}")
    print(f"scan: {files_scanned} files, {total_refs} files with references, "
          f"{chain_refs} references inside chain modules")
    if library_refs:
        print("library-only capabilities referenced (implemented for chains this product does "
              f"not sign for yet): {', '.join(sorted(library_refs))}")

    if problems:
        for line in problems:
            print("FAIL " + line, file=sys.stderr)
        print(f"CAPSCOPE: {len(problems)} violation(s)", file=sys.stderr)
        return EXIT_ATTRIBUTION if any(p.startswith("A:") for p in problems) else EXIT_ORPHAN
    print("CAPSCOPE: chain modules reference only declared capabilities; "
          "no unreferenced owner-less capability")
    return 0


def self_test():
    """Negative fixtures: each must raise. A gate that cannot go red is decoration."""
    import contextlib
    import io
    import tempfile

    cases = []

    def fixture(label, code, mutate=None, delete=(), debt=None):
        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            for src in CAPS.glob("*.toml"):
                if src.name in delete:
                    continue
                (tmpdir / src.name).write_bytes(src.read_bytes())
            for name in ("btc.toml", "eth.toml", "xmr.toml"):
                tgt = tmpdir / name
                if not tgt.is_file():
                    continue
                text = tgt.read_text(encoding="utf-8")
                tgt.write_text(mutate(text) if mutate else text, encoding="utf-8")
            if debt is not None:
                (tmpdir / "_debt.toml").write_text(debt, encoding="utf-8")
            # Two ways to go red: a Fail (shape problems, raised while loading) and a non-zero
            # RETURN CODE (attribution / orphan / debt problems, collected then reported). A
            # fixture that only watched exceptions reported four live checks as "no red".
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = run(caps=tmpdir)
            except Fail as exc:
                cases.append((label, exc.code == code, f"{exc.code}: {exc}"))
            else:
                cases.append((label, rc == code,
                              f"returned {rc}" if rc != code else "red as expected"))
            finally:
                pass

    fixture("declaring a library-only primitive is refused", EXIT_SHAPE,
            lambda d: d.replace("[signatures]\n", "[signatures]\nfcmp = true\n")
                      if "[signatures]" in d else d)
    fixture("a false entry is refused", EXIT_SHAPE,
            lambda d: d.replace("[signatures]\n", "[signatures]\nclsag = false\n")
                      if "[signatures]" in d else d)
    fixture("an unknown capability name is refused", EXIT_SHAPE,
            lambda d: d.replace("[signatures]\n", "[signatures]\nnot_a_thing = true\n")
                      if "[signatures]" in d else d)
    # These two run against the REAL forms tree, so they prove the scan direction is live:
    fixture("removing a declared capability makes attribution fail", EXIT_ATTRIBUTION,
            lambda d: d.replace("ecdsa = true", "# removed"))
    fixture("a chain directory without a declaration is refused", EXIT_ATTRIBUTION,
            delete=("btc.toml",))
    fixture("debt may not name a capability its combination declares", EXIT_ORPHAN,
            debt=('schema_version = 1\n\n[[debt]]\nid = "DX"\ncombination = "btc"\n'
                  'capability = "ecdsa"\nvia = "forms/business/sign.rs"\nclear_in = "C3"\n'))

    failed = [c for c in cases if not c[1]]
    for label, ok, detail in cases:
        print(("ok   " if ok else "FAIL ") + label + ("" if ok else f" :: {detail}"))
    print("CAPSCOPE self-test: " + ("all negative fixtures went red" if not failed
                                    else f"{len(failed)} fixture(s) did not go red"))
    return 0 if not failed else EXIT_SHAPE


def main(argv):
    try:
        if "--self-test" in argv:
            return self_test()
        return run(report_only="--report" in argv)
    except Fail as exc:
        print(f"CAPSCOPE: {exc}", file=sys.stderr)
        return exc.code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
