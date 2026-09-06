#!/usr/bin/env python3
"""Measure the §5 RESIDENT_BYTES bound for one variant's object directory.

    python3 tools/measure_resident_bytes.py build/lib/objs [--check N]

Prints the od65 segment sum, the page-aligned section count, the bound and
the value to declare. With --check, exits 1 if the declared value is below
the bound — the direction §5 calls dangerous.

WHY A BOUND AND NOT THE SUM (issue #113). od65 reports each OBJECT's segment
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
                    if int(m.group(1)) > 1:
                        aligned += 1
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
    return total, aligned, seen


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    objdir = sys.argv[1]
    total, aligned, seen = measure(objdir)
    bound = total + 255 * aligned
    declare = (bound + 255) // 256 * 256
    print(f"  sections            : {seen} ({aligned} page-aligned)")
    print(f"  od65 segment sum    : {total}")
    print(f"  bound (+255 each)   : {bound}")
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
