#!/usr/bin/env python3
"""Measure the §5 RESIDENT_BYTES bound for one variant's object directory.

    python3 tools/measure_resident_bytes.py build/lib/objs [--check]

Prints the od65 segment sum, the alignment fill terms, the bound and the
value to declare. With --check it additionally reads
LIB_CHACHA20_POLY1305_RESIDENT_BYTES out of that directory's lib_manifest.o
and exits 1 if the declared value is below the bound — the direction §5
calls dangerous.

--check takes NO argument. It used to take the expected value, which meant
the check supplied its own answer: a maintainer lowering the equate passed.
A trailing number is now rejected rather than ignored, so a stale
`--check 17920` in a script fails loudly instead of silently reading as the
no-argument form.

THE BASIS, STATED (issue #113). Declared value =
    sum of each object's LIB_CHACHA20_POLY1305_* section sizes
  + sum of (alignment - 1) over every page-aligned fragment
  + (segment alignment - 1) for the SEGMENT START itself
  rounded up to the next 256.

THE SEGMENT-START TERM IS NOT OPTIONAL, and omitting it was a real defect in
this tool's first version. The library requires its consumer to declare
LIB_CHACHA20_POLY1305_CODE with `align = $100` (§4, the CT invariant), so
ld65 must pad from wherever the consumer's preceding code ends up to the next
page. That offset is the consumer's own code size, so any residue 0..255 is
reachable — the identical argument the fragment charge rests on, applied one
level up. The library forces n+1 alignment boundaries and the first version
paid for n. Demonstrated with a real link: an adversarial member order put
library-attributable bytes at 17856 against a declared 17664.

The charge is per ALIGNED FRAGMENT, not per segment, because this library's
LIB_CHACHA20_POLY1305_CODE takes contributions from eight objects and three of
them are aligned — so fill accumulates inside one segment rather than appearing
as a single inter-segment gap. A sibling using a per-segment charge is correct
for a tree where each aligned segment draws from exactly one object; that is a
property no clause requires, and it is not true here.

SCOPE: the bound covers fill forced by the alignments this library declares.
A consumer who declares MORE — `LIB_CHACHA20_POLY1305_CODE: align = $200` —
forces fill beyond it and will under-reserve if they budget from the equate.

That is PERMITTED, not a violation, and saying otherwise would be wrong: §4
places its obligation on the library, and `$200` satisfies the CT invariant
outright, since 512-aligned implies 256-aligned. No clause forbids declaring
more. §5 meanwhile says "every consumer", unqualified — so excluding this case
is the library narrowing §5 by fiat, and it should be read as a stated scope
limit rather than as the consumer being out of contract.

The reason it is the right limit is measured, not definitional: `align = $200`
costs +38 B over the declared value, `$400` costs +550, and it grows without
limit. No finite bound over consumer alignment choices exists. What DOES bound
it is that the case only arises when a consumer deviates from the cfg line §4
tells them to copy verbatim — copy it, and this term is exact.

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
    seg_align = {}      # per segment: the alignment its start must satisfy
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
                        seg_align[name] = max(seg_align.get(name, 1), a)
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
    # One more boundary per aligned SEGMENT: its start must be padded to
    # alignment from wherever the consumer's preceding code ends.
    start_charge = sum(a - 1 for a in seg_align.values())
    return total, aligned, charge, start_charge, seen


def declared_from_object(objdir):
    """Read LIB_CHACHA20_POLY1305_RESIDENT_BYTES out of the BUILT manifest.

    Not passed in as an argument, deliberately. A hardcoded expectation is a
    second copy of the number: it lets the equate be lowered while the check
    passes (the exact regression the manifest warns about), and it lets a
    check run against objects from one configuration while comparing to
    another configuration's literal. Reading it from the object in the
    directory being measured binds the check to what it measured.

    Precedent: tools/verify_zp_usage.py does the same for ZP_USAGE_BYTES.
    """
    obj = os.path.join(objdir, "lib_manifest.o")
    if not os.path.exists(obj):
        sys.exit(f"FATAL: {obj} missing — cannot read the declared value, and "
                 "a check that supplies its own expectation is not a check.")
    out = subprocess.run(["od65", "--dump-exports", obj],
                         capture_output=True, text=True).stdout
    name = None
    for line in out.split("\n"):
        m = re.search(r'Name:\s*"([^"]*)"', line)
        if m:
            name = m.group(1)
            continue
        m = re.search(r"Value:\s+(0x[0-9A-Fa-f]+)", line)
        if m and name == "LIB_CHACHA20_POLY1305_RESIDENT_BYTES":
            return int(m.group(1), 16)
    sys.exit(f"FATAL: {obj} exports no LIB_CHACHA20_POLY1305_RESIDENT_BYTES.")


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    objdir = sys.argv[1]
    total, aligned, charge, start_charge, seen = measure(objdir)
    bound = total + charge + start_charge
    declare = (bound + 255) // 256 * 256
    print(f"  sections            : {seen} ({aligned} page-aligned)")
    print(f"  od65 segment sum    : {total}")
    print(f"  fragment fill       : {charge} (sum of alignment-1 per aligned fragment)")
    print(f"  segment-start fill  : {start_charge} (alignment-1 per aligned segment start)")
    print(f"  bound               : {bound}")
    print(f"  declare (round 256) : {declare}")
    if "--check" in sys.argv:
        i = sys.argv.index("--check")
        if i + 1 < len(sys.argv) and sys.argv[i + 1].isdigit():
            sys.exit(f"FATAL: --check takes no argument, got '{sys.argv[i + 1]}'. "
                     "It used to take the expected value; that let the check "
                     "supply its own answer, so lowering the equate passed. The "
                     "declared value is now read from lib_manifest.o. Drop the "
                     "number — a stale one must fail loudly, not be ignored.")
        declared = declared_from_object(objdir)
        print(f"  declared (from .o)  : {declared}")
        if declared < bound:
            print(f"  FAIL: declared {declared} < bound {bound} — under-reports "
                  "what a consumer can pay (§5 safe-direction)")
            return 1
        print(f"  OK: declared {declared} >= bound {bound}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
