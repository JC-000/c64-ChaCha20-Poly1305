#!/usr/bin/env python3
r"""verify_member_isolation.py — c64-lib-contract SPEC §6.1 member isolation.

    "ld65 links whole archive members. A symbol a consumer may displace —
     suppress under LIB_NO_BARE_EXPORTS, or define itself under APP_OWNED
     (§8.0) — MUST live in a translation unit that exports nothing else a
     consumer may import — other displaceable names included, their own
     prefixed counterparts excepted — and defines nothing else the library's
     own code references."
                                       — SPEC v1.2.0 §6.1, carve-out v1.2.1,
                                         both collision directions at v1.2.2

Issue #108. `c64-x25519`'s equivalent target (its Makefile, `lib-verify-
isolation`) hardcodes three specific pairings — bare `LIB_PRECALC_*` versus
§5 aggregates, bare `LIB_PRECALC_*` versus bare version exports, bare version
versus §5 aggregates — and so does not cover the APP_OWNED displaceable set
at all. A copy of it would pass on a tree that still had `ct_mul_8x8` sitting
beside `poly1305_final`, which is contract #179's shape and this repo's
actual defect. This is the general test instead.

NOTHING IS HARDCODED — BOTH SIDES ARE DERIVED FROM BUILT OBJECTS.
The displaceable set is MEASURED, by building the same sources three ways in
a throwaway tree and differencing the export tables:

    displaceable_bare      = exports(default) - exports(-D LIB_NO_BARE_EXPORTS=1)
    displaceable_appowned  = exports(default) - exports(-D SHARED_SQTAB_INIT=1
                                                        -D SHARED_CT_MUL_8X8=1)

A name that survives both suppressions is not displaceable, whatever anyone
believed when they wrote a list down. The prefixed-counterpart relation is
derived the same way: `B` is a bare form of `P` iff both are exported by the
same member, both start with `LIB_`, and `P` ends with `B` minus its `LIB`.
The library's own §1 prefix is never spelled out here.

That matters because of a specific failure class this fleet has now hit three
times: a check that compares an artifact against a hard-coded copy of its own
expected values is evidence about the copy, not the artifact.

THREE LEGS, AND THE THIRD IS ABOUT THE INSTRUMENT.

  1. conformance   no member may export BOTH a displaceable name and a name a
                   consumer may import that is not one of those names' own
                   prefixed counterparts. Offending names are printed.
  2. non-vacuity   the measured displaceable set must be non-empty, and every
                   variant's dump must parse to at least one export. A green
                   run over an empty dump is the failure mode this whole file
                   exists to avoid.
  3. reconciliation for every member,
                       |bare| + |prefixed counterparts| + |other| == |exports|
                   and the number of parsed names must equal the number of
                   `Name:` rows in the raw od65 dump. Unlike a category count
                   whose pass condition is zero, this catches a mis-SPLIT
                   inside a populated dump — see the parser note below, where
                   exactly that bug hid two bare `LIB_PRECALC_sqtab_*` names
                   and made a count of 9 read as 7.

PARSER NOTE — DO NOT "TIDY" THE REGEX. `od65` emits |24 - len(name)| spaces
after `Name:` — the signature of printf("Name:%*s\"%s\"", 24 - Len, "", Name),
where a negative %*s width left-justifies rather than truncating. A name of
exactly 24 characters therefore gets ZERO spaces, and the row comes out as
`Name:"LIB_PRECALC_sqtab_SHARED"` with NO space. `awk '{print $2}'` and
`Name:\s+"` both drop such rows silently. The `\s*` below (and the equivalent
`sed -n 's/.*Name: *"...` spelling in the docs) is load-bearing.

It is NOT a fixed column — the quote position moves with every name (11 to 45
across this library's objects), so a fixed-offset extraction is wrong for
almost every name rather than just at 24. Verified across four repositories,
lengths 4 to 58.

Usage:  python3 tools/verify_member_isolation.py [--tree DIR]
Exit:   0 conformant, 1 violation or broken instrument.

Not named `lib-*` as a source file; the make target is `lib-verify-isolation`
because it consumes the archives `make lib*` produces.
"""

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# See the PARSER NOTE in the module docstring before changing this.
NAME_RE = re.compile(r'Name:\s*"([^"]*)"')
NAME_ROW_RE = re.compile(r"Name:")

# The three shipped variants and the object dir each `make lib*` target fills.
VARIANTS = {
    "lib": "build/lib/objs",
    "lib-aead-only": "build/lib/objs-aead-only",
    "lib-app-owned": "build/lib/objs-app-owned",
}

# The two suppression knobs §6.1 names. Values are ca65 define strings; the
# NAMES of the resulting symbols are never written down anywhere in this file.
SUPPRESSIONS = {
    "LIB_NO_BARE_EXPORTS": "-D LIB_NO_BARE_EXPORTS=1",
    "APP_OWNED": "-D SHARED_SQTAB_INIT=1 -D SHARED_CT_MUL_8X8=1",
}


def dump_exports(obj):
    """(names, raw_row_count) for one object file."""
    p = subprocess.run(["od65", "--dump-exports", str(obj)],
                       capture_output=True, text=True)
    if p.returncode != 0:
        sys.exit(f"FATAL: od65 failed on {obj}: {p.stderr.strip()}")
    if "(no xo65 object file)" in p.stdout:
        # od65 EXITS 0 on an archive, printing only this. Every check below
        # would then be vacuous (contract v0.7.2 / contract #52).
        sys.exit(f"FATAL: {obj} is not an object file — od65 exits 0 on an "
                 "archive and prints nothing, so this audit would pass "
                 "vacuously. Point it at .o files, never at a .a")
    return NAME_RE.findall(p.stdout), len(NAME_ROW_RE.findall(p.stdout))


def members(objdir):
    """{member stem: [export names]} plus the raw row count, for one build."""
    objs = sorted(Path(objdir).glob("*.o"))
    if not objs:
        sys.exit(f"FATAL: no objects under {objdir} — nothing was built, so "
                 "every leg below would pass vacuously")
    out = {}
    rows = 0
    for o in objs:
        names, n = dump_exports(o)
        out[o.stem] = names
        rows += n
    return out, rows


def build_tree(tree, target, defines):
    cmd = ["make", target]
    if defines:
        cmd.append(f"CONTRACT_DEFINES={defines}")
    p = subprocess.run(cmd, cwd=tree, capture_output=True, text=True)
    if p.returncode != 0:
        print(p.stdout[-3000:])
        print(p.stderr[-3000:])
        sys.exit(f"FATAL: `{' '.join(cmd)}` failed in {tree}")


def flat(mem):
    return {n for names in mem.values() for n in names}


def counterparts(bare, exports):
    """Prefixed forms of `bare` present in `exports`. Derived, not spelled."""
    if not bare.startswith("LIB"):
        return set()
    suffix = bare[3:]              # "LIB_PRECALC_x_SIZE" -> "_PRECALC_x_SIZE"
    return {e for e in exports
            if e != bare and e.startswith("LIB") and e.endswith(suffix)}


def measure_displaceable(tree):
    """Build three ways in `tree`; return (displaceable set, per-knob detail)."""
    build_tree(tree, "lib", None)
    base, _ = members(tree / VARIANTS["lib"])
    base_names = flat(base)
    detail = {}
    displaceable = set()
    for label, defines in SUPPRESSIONS.items():
        build_tree(tree, "lib", defines)
        supp, _ = members(tree / VARIANTS["lib"])
        gone = base_names - flat(supp)
        detail[label] = gone
        displaceable |= gone
    # Leave the throwaway tree back on the default config, in case anything
    # downstream reads it.
    build_tree(tree, "lib", None)
    return displaceable, detail


def check_variant(label, objdir, displaceable):
    """Legs 1 and 3 for one built variant. Returns list of failure strings."""
    mem, raw_rows = members(objdir)
    failures = []

    parsed = sum(len(v) for v in mem.values())
    if parsed != raw_rows:
        failures.append(
            f"{label}: parsed {parsed} export names from {raw_rows} `Name:` "
            "rows — the od65 dump is being mis-split, so every category count "
            "below is unreliable (see the PARSER NOTE)")

    print(f"\n  {label}  ({len(mem)} members, {parsed} exports)")
    for name, exports in sorted(mem.items()):
        exp = set(exports)
        disp = exp & displaceable
        if not disp:
            print(f"    {name:<22} {len(exp):>3} exports, none displaceable")
            continue
        cps = set()
        for b in disp:
            cps |= counterparts(b, exp)
        cps -= disp
        other = exp - disp - cps
        print(f"    {name:<22} {len(exp):>3} exports = {len(disp)} displaceable"
              f" + {len(cps)} prefixed counterpart(s) + {len(other)} other")
        # Leg 3: reconciliation.
        if len(disp) + len(cps) + len(other) != len(exp):
            failures.append(f"{label}/{name}: category counts do not reconcile "
                            f"({len(disp)}+{len(cps)}+{len(other)} != {len(exp)})")
        # Leg 1: conformance.
        if other:
            failures.append(
                f"{label}/{name}.o mixes displaceable names with names a "
                f"consumer may import (SPEC §6.1):\n"
                f"        displaceable: {', '.join(sorted(disp))}\n"
                f"        also exported: {', '.join(sorted(other))}")
    return failures


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tree", default=None,
                    help="check this tree instead of the repo (used to prove "
                         "the check goes red on a known-bad tree)")
    args = ap.parse_args()
    src_root = Path(args.tree).resolve() if args.tree else ROOT

    print("=== SPEC §6.1 member isolation (displaceable set is MEASURED) ===")
    if shutil.which("od65") is None:
        return 1

    failures = []
    with tempfile.TemporaryDirectory(prefix="ccp-iso-") as td:
        tree = Path(td) / "tree"
        tree.mkdir()
        shutil.copytree(src_root / "src", tree / "src")
        shutil.copytree(src_root / "cfg", tree / "cfg")
        shutil.copy2(src_root / "Makefile", tree / "Makefile")

        displaceable, detail = measure_displaceable(tree)
        for label, gone in detail.items():
            print(f"  measured displaceable under {label:<20} "
                  f"{len(gone):>3}: {', '.join(sorted(gone)) or '(none)'}")
        # Leg 2: non-vacuity.
        if not displaceable:
            failures.append("no displaceable names measured at all — the "
                            "suppression knobs did not reach the build, so "
                            "leg 1 would pass vacuously")

        for target, objdir in VARIANTS.items():
            build_tree(tree, target, None)
            failures += check_variant(target, tree / objdir, displaceable)

    if failures:
        print()
        for f in failures:
            print(f"  FAIL: {f}")
        print("\n  lib-verify-isolation: FAILED")
        return 1
    print("\n  lib-verify-isolation: OK — no member mixes a displaceable name "
          "with a non-counterpart importable name")
    return 0


if __name__ == "__main__":
    sys.exit(main())
