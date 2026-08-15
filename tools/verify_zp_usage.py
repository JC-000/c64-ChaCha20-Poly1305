#!/usr/bin/env python3
"""verify_zp_usage.py — R2 audit: exported ZP surface vs the §5 usage equate.

`LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES` is a hand-maintained literal in
src/lib/lib_manifest.s. Nothing tied it to the actual `.exportzp` surface,
so adding or widening a slot would leave the equate silently stale — and a
consumer sizing its own ZP budget against a stale number is the failure
this audit exists to catch.

The check derives the truth from the built objects rather than the source
text: it reads the exported slot addresses out of zp_config.o with od65,
maps each to its declared width, unions the occupied addresses, and
compares the cardinality to the equate exported by lib_manifest.o.

Two properties beyond the total:

  * every shared address must be an *intended* alias. A union alone would
    hide an accidental self-collision (two distinct slots landing on one
    address shrink the union instead of failing), so aliases are checked
    by name: bare <-> canonical §2 pairs, and cc20_keystream <-> cc20_work.

  * the equate must be safe-direction (>= actual), matching §6.6's rule
    for footprint equates. Profile A omits ct_diff_raw/ct_sign_mask, so
    its real usage is 86 against the declared 88 — the declared value is
    deliberately the A+B union, an upper bound for either profile.

Usage:  python3 tools/verify_zp_usage.py
Exit:   0 conformant, 1 drift detected.

Not named `lib-*`: contract §6.1 reserves that make-target namespace for
targets producing archives.
"""

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Slot widths in bytes. The single place this script trusts the source
# layout; everything else is measured. cc20_keystream is an alias of
# cc20_work and carries its width so the union is computed correctly.
WIDTHS = {
    **{n: 1 for n in ("zp_tmp1", "zp_tmp2", "cc20_round", "cc20_qr_idx",
                      "cc20_remain", "cc20_buf_pos", "poly_i", "poly_j",
                      "poly_carry", "poly_tmp", "ct_diff_raw", "ct_sign_mask")},
    **{n: 2 for n in ("w32_src1", "w32_src2", "w32_dst", "cc20_data_ptr",
                      "zp_ptr1", "zp_ptr2")},
    "cc20_work": 64,
    "cc20_keystream": 64,
}

CANON_PREFIX = "chacha20poly1305_zp_"


def dump_exports(obj):
    """Return {name: value} for an object's exports, or die loudly.

    od65 cannot read .a archives — pointed at one it prints
    "(no xo65 object file)" and exits 0, so a grep-based audit silently
    reports nothing and is indistinguishable from a clean pass. Always
    point this at .o files, and sentinel-check the dump.
    """
    out = subprocess.run(["od65", "--dump-exports", str(obj)],
                         capture_output=True, text=True).stdout
    if "no xo65 object file" in out or not out.strip():
        sys.exit(f"FATAL: unreadable od65 dump for {obj} — audit would be vacuous")
    pairs = re.findall(r'Name:\s*"([^"]+)".*?Value:\s*(0x[0-9a-fA-F]+)', out, re.S)
    if not pairs:
        sys.exit(f"FATAL: no exports parsed from {obj} — dump format changed?")
    return {n: int(v, 16) for n, v in pairs}


def normalise(name):
    return name.replace(CANON_PREFIX, "zp_")


def main():
    zp_obj = ROOT / "build" / "lib" / "objs" / "zp_config.o"
    man_obj = ROOT / "build" / "lib" / "objs" / "lib_manifest.o"

    # zp_config.s is excluded from the archives (§6.2 consumer-assembled
    # model), so assemble it here rather than expecting a build artifact.
    build = ROOT / "build" / "zp-audit"
    build.mkdir(parents=True, exist_ok=True)
    zp_obj = build / "zp_config.o"
    subprocess.run(["ca65", "-t", "c64", "-g", "-I", "src/include",
                    "-I", "src/lib", "-I", "src", "src/zp_config.s",
                    "-o", str(zp_obj)], cwd=ROOT, check=True)

    if not man_obj.exists():
        sys.exit(f"FATAL: {man_obj} missing — run `make lib` first")

    slots = dump_exports(zp_obj)
    manifest = dump_exports(man_obj)

    key = "LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES"
    if key not in manifest:
        sys.exit(f"FATAL: {key} not exported by lib_manifest.o")
    declared = manifest[key]

    occupied, unmapped = set(), []
    for name, addr in slots.items():
        w = WIDTHS.get(normalise(name))
        if w is None:
            unmapped.append(name)
            continue
        occupied |= set(range(addr, addr + w))

    # Aliases: every address shared by >1 exported name must be intended.
    by_addr = {}
    for name, addr in slots.items():
        by_addr.setdefault(addr, []).append(name)
    unexpected = []
    for addr, names in sorted(by_addr.items()):
        if len(names) < 2:
            continue
        norm = {normalise(n) for n in names}
        if len(norm) == 1 or norm == {"cc20_work", "cc20_keystream"}:
            continue
        unexpected.append((addr, sorted(names)))

    actual = len(occupied)
    print(f"  exported slot names : {len(slots)}")
    print(f"  occupied ZP bytes   : {actual}")
    print(f"  {key} : {declared}")

    fail = False
    if unmapped:
        print(f"  FAIL: exported slots with no declared width: {sorted(unmapped)}")
        print("        add them to WIDTHS — an unmapped slot is uncounted, "
              "which silently understates usage")
        fail = True
    for addr, names in unexpected:
        print(f"  FAIL: unintended alias at ${addr:02X}: {', '.join(names)}")
        fail = True
    if declared < actual:
        print(f"  FAIL: equate {declared} < actual {actual} — understates usage; "
              "§6.6 requires safe-direction (>= actual)")
        fail = True
    elif declared != actual:
        print(f"  note: equate {declared} > actual {actual} (safe direction; "
              "expected only if a profile omits slots)")

    if fail:
        return 1
    print("  verify-zp-usage: OK — exported surface and §5 equate agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
