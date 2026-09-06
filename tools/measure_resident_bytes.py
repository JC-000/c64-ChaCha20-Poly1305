#!/usr/bin/env python3
"""Measure the §5 RESIDENT_BYTES bound for one variant's object directory.

    python3 tools/measure_resident_bytes.py build/lib/objs [--check N]

Prints the od65 segment sum, the page-aligned section count, the bound and
the value to declare. With --check, exits 1 if the declared value is below
the bound — the direction §5 calls dangerous.

THE BASIS, STATED (issue #113). Declared value =
    sum of each object's LIB_CHACHA20_POLY1305_* section sizes
  + sum of (alignment - 1) over every page-aligned fragment
  rounded up to the next 256.

The charge is per ALIGNED FRAGMENT, not per segment, because this library's
LIB_CHACHA20_POLY1305_CODE takes contributions from eight objects and three of
them are aligned — so fill accumulates inside one segment rather than appearing
as a single inter-segment gap. A sibling using a per-segment charge is correct
for a tree where each aligned segment draws from exactly one object; that is a
property no clause requires, and it is not true here.

SCOPE: the bound is over CONFORMING consumer cfgs. It covers fill forced by
the alignments this library DECLARES. A consumer who declares more than §4
requires — say `LIB_CHACHA20_POLY1305_CODE: align = $200` in their own cfg —
forces fill beyond this charge, and is choosing a cost that is not this
library's footprint, any more than the gaps they leave between segments are.
A bound that tracked arbitrary consumer cfg choices would not be bounded.

(alignment - 1) rather than a hardcoded 255: every aligned fragment here is
256-aligned today, but a future `.align 512` would need 511 and a constant
would under-charge silently — the exact defect class this tool exists to close.

WHY A BOUND AND NOT THE SUM. od65 reports each OBJECT's segment
sizes; it cannot report the padding ld65 inserts BETWEEN sections. This
library forces that padding to exist, because LIB_CHACHA20_POLY1305_CODE must
be declared `align = $100` for the constant-time invariant on its
secret-indexed LUTs. A consumer pays sum + fill; fill before an aligned
section is (-offset) mod 256 and the offset depends on which members that
consumer pulls, so any residue 0..255 is reachable per aligned section.

Do not re-derive from a measured consumer link. There is no single real link:
a consumer pulling part of the archive measures below the sum, one pulling all
of it measures above.

PARSER NOTE. `Alignment:` follows `Size:`, which follows `Name:`. A one-pass
state machine that reads them in the wrong order silently reports zero aligned
sections — that produced a bound equal to the sum during this issue's work,
and it was caught only because the answer contradicted a known count of 3.
Hence the explicit ordering below, and the sanity check that fires when a
library object reports no aligned sections at all.
"""
import os
import re
import subprocess
import sys


def measure(objdir):
    total = 0
    aligned = 0
    charge = 0          # sum of (alignment - 1) over aligned fragments
    seen = 0
    for obj in sorted(os.listdir(objdir)):
        if not obj.endswith(".o"):
            continue
        out = subprocess.run(["od65", "--dump-segments", os.path.join(objdir, obj)],
                             capture_output=True, text=True)
        if out.returncode != 0:
            sys.exit(f"FATAL: od65 failed on {obj}")
        name = size = None
        for line in out.stdout.split("\n"):
            m = re.search(r'Name:\s*"([^"]*)"', line)
            if m:
                name, size = m.group(1), None
                continue
            m = re.search(r"Size:\s+(\d+)", line)
            if m:
                size = int(m.group(1))
                continue
            m = re.search(r"Alignment:\s+(\d+)", line)
            if m and name and size is not None:
                if name.startswith("LIB_CHACHA20_POLY1305") and size > 0:
                    total += size
                    seen += 1
                    a = int(m.group(1))
                    if a > 1:
                        aligned += 1
                        charge += a - 1     # worst-case pad before this fragment
                name = size = None
    if seen == 0:
        sys.exit(f"FATAL: no LIB_CHACHA20_POLY1305_* sections in {objdir} — "
                 "wrong path, an .a archive, or od65's format changed. Every "
                 "number below would be vacuous.")
    if aligned == 0:
        sys.exit(f"FATAL: {seen} library sections in {objdir} but NONE page-aligned. "
                 "This library's CT invariant requires aligned sections, so this "
                 "is a broken parser rather than a real measurement (see the "
                 "PARSER NOTE in this file).")
    return total, aligned, charge, seen


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    objdir = sys.argv[1]
    total, aligned, charge, seen = measure(objdir)
    bound = total + charge
    declare = (bound + 255) // 256 * 256
    print(f"  sections            : {seen} ({aligned} page-aligned)")
    print(f"  od65 segment sum    : {total}")
    print(f"  worst-case fill     : {charge} (sum of alignment-1 per aligned fragment)")
    print(f"  bound               : {bound}")
    print(f"  declare (round 256) : {declare}")
    if "--check" in sys.argv:
        declared = int(sys.argv[sys.argv.index("--check") + 1])
        if declared < bound:
            print(f"  FAIL: declared {declared} < bound {bound} — under-reports "
                  "what a consumer can pay (§5 safe-direction)")
            return 1
        print(f"  OK: declared {declared} >= bound {bound}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
