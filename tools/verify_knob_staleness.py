#!/usr/bin/env python3
"""verify_knob_staleness.py — §6.3 knob-staleness guard (contract SPEC v0.10.5).

`CONTRACT_DEFINES` reaches every ca65 invocation through `CA65FLAGS`, but it
reaches no make *prerequisite*: the object cache is keyed on source mtimes
alone. Before issue #86 a re-invocation with different knobs therefore reused
every stale object and exited 0 with an artifact other than the one requested
— the v0.10.5 §6.3 shape-3 "silent no-op", the least visible rung of the
looks-reachable ladder because nothing downstream is wrong enough to trip an
assert. The Makefile's CONTRACT_STAMP block closes it; this audit pins it.

Four legs, all four required — a guard that rebuilds unconditionally would
pass the first two and is not the fix:

  1. default `make lib` builds Profile B
  2. a knob CHANGE rebuilds, and the artifact actually flips to Profile A
  3. the SAME knob again is incremental (nothing rebuilds)
  4. reverting the knob rebuilds back to Profile B

The observable is the `_PRECALC_` export count on the archive's manifest
member: Profile B enumerates three §8.4 tables and Profile A four, six
exports each, so 18 vs 24. Per §6.3's checkability note this is an od65
structural dump, never an archive-bytes diff — ca65 stamps OPT_DATETIME into
every object, so raw bytes differ on every knob, no-op or not.

Runs against a throwaway copy of `Makefile` + `src/` in a temp dir: the
guard's invalidation leg deletes every object under `build/`, and this audit
must not cost the caller their profile-a/b object cache.

Usage:  python3 tools/verify_knob_staleness.py
Exit:   0 conformant, 1 drift detected.

Not named `lib-*`: contract §6.1 reserves that make-target namespace for
targets producing archives.
"""

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

PROFILE_A_DEFINE = "-D POLY1305_PROFILE_LONG=1"
MANIFEST_OBJ = "build/lib/objs/lib_manifest.o"

# §8.4 rows per profile x six exports each (prefixed triple + bare triple).
# Profile A gates out the sqtab row (issue #51), so it enumerates four tables
# to Profile B's three.
EXPECT_B = 18
EXPECT_A = 24

NOTHING_TO_BE_DONE = re.compile(r"Nothing to be done", re.I)


def run_make(tree, knobs):
    """`make lib` in `tree`. Returns (rebuilt, stdout)."""
    cmd = ["make", "lib"]
    if knobs:
        cmd.append(f"CONTRACT_DEFINES={knobs}")
    p = subprocess.run(cmd, cwd=tree, capture_output=True, text=True)
    if p.returncode != 0:
        print(f"  FAIL: {' '.join(cmd)} exited {p.returncode}")
        print(p.stdout[-2000:])
        print(p.stderr[-2000:])
        sys.exit(1)
    return (not NOTHING_TO_BE_DONE.search(p.stdout)), p.stdout


def precalc_exports(tree):
    obj = tree / MANIFEST_OBJ
    p = subprocess.run(["od65", "--dump-exports", str(obj)],
                       capture_output=True, text=True)
    if p.returncode != 0 or not p.stdout.strip():
        print(f"  FAIL: od65 could not read {obj} — every count below would "
              "be vacuously 0 (SPEC v0.7.2)")
        sys.exit(1)
    return p.stdout.count("_PRECALC_")


def main():
    print("\n=== §6.3 knob-staleness guard (a defines change must rebuild) ===")
    if shutil.which("od65") is None:
        print("  FAIL: od65 not on PATH")
        return 1

    failures = []
    with tempfile.TemporaryDirectory(prefix="ccp-knob-") as td:
        tree = Path(td) / "tree"
        tree.mkdir()
        shutil.copytree(ROOT / "src", tree / "src")
        shutil.copy2(ROOT / "Makefile", tree / "Makefile")

        # 1. default
        run_make(tree, None)
        n = precalc_exports(tree)
        print(f"  1. default            -> {n} _PRECALC_ exports (want {EXPECT_B}, Profile B)")
        if n != EXPECT_B:
            failures.append(f"default build is not Profile B ({n} != {EXPECT_B})")

        # 2. knob change must rebuild AND flip the artifact
        rebuilt, _ = run_make(tree, PROFILE_A_DEFINE)
        n = precalc_exports(tree)
        print(f"  2. knob change        -> rebuilt={rebuilt}, {n} exports (want {EXPECT_A}, Profile A)")
        if not rebuilt:
            failures.append("a knob change did not rebuild — the stamp is not "
                            "invalidating (issue #86 regression)")
        if n != EXPECT_A:
            failures.append(f"knob change did not select Profile A ({n} != {EXPECT_A}) "
                            "— §6.3 shape-3 silent no-op")

        # 3. same knob must stay incremental
        rebuilt, _ = run_make(tree, PROFILE_A_DEFINE)
        print(f"  3. same knob again    -> rebuilt={rebuilt} (want False)")
        if rebuilt:
            failures.append("unchanged knobs rebuilt — the stamp churns, so the "
                            "guard is an unconditional rebuild, not a staleness check")

        # 4. revert must rebuild back
        rebuilt, _ = run_make(tree, None)
        n = precalc_exports(tree)
        print(f"  4. revert to default  -> rebuilt={rebuilt}, {n} exports (want {EXPECT_B})")
        if not rebuilt:
            failures.append("reverting the knob did not rebuild")
        if n != EXPECT_B:
            failures.append(f"revert did not restore Profile B ({n} != {EXPECT_B})")

    if failures:
        for f in failures:
            print(f"  FAIL: {f}")
        print("  verify-knob-staleness: FAILED")
        return 1
    print("  verify-knob-staleness: OK — change rebuilds, revert rebuilds, "
          "no-change is incremental, artifact tracks the knob")
    return 0


if __name__ == "__main__":
    sys.exit(main())
