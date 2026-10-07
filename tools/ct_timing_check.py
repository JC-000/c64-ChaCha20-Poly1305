#!/usr/bin/env python3
"""ct_timing_check.py — constant-time check by cycle count, on VICE.

    python3 tools/ct_timing_check.py [--profile compact|a|b] [--samples N]

Runs each routine below over several classes of SECRET input that share
every PUBLIC parameter (lengths, block counter, hibit) and requires the
cycle counts to be IDENTICAL across classes. A routine whose time depends on
its secret operands fails, whatever the size of the difference.

  poly1305_multiply   h, r all-zero / all-$FF / mixed / random — the classes
                      the old `beq @skip_h_zero` / `beq @skip_r_zero` early
                      outs and a carry ripple both separate. Includes
                      poly1305_reduce, which it falls through into.
  chacha20_block      key and nonce zero / $FF / random; counter fixed.
  aead_encrypt n=100  key, nonce, AAD bytes and plaintext bytes varied;
                      AAD length 13 and data length 100 fixed (both public).
  aead_decrypt        tags that mismatch at byte 0 vs byte 15 vs all bytes
                      — the compare must not stop at the first difference.

HOW THE CYCLES ARE MADE EXACT. The count comes from the bench's chained
CIA #1 wrapper (tools/benchmark_chacha20_poly1305.py). CIA timers count bus
cycles, and with the display on the VIC-II steals ~40 of them on every
badline, so the count also depends on where the raster happens to be when
the call starts. That is noise, not a property of the routine, and it is
tens to hundreds of cycles — enough to hide a one-cycle leak and to fake
one. The check therefore clears DEN ($D011 bit 4) first: no display, no
badlines, and VICE is cycle-exact, so repeated runs of one input agree to
the cycle. The tool PROVES that on every run (each class is sampled
--samples times and must not vary) rather than assuming it.

CAN THIS FAIL? Run it against the default Profile B build:

    make profile-b && python3 tools/ct_timing_check.py --profile b

poly1305_multiply there adds partial products through poly_ripple, whose
INC/BNE stops where the carry stops, so its time varies with h and r and
this check reports it. The library has always classified that branch as
acceptable (it is on a carry, not an operand byte); the compact variant is
built not to need the argument.

Exit status: 0 all routines constant-time, 1 a routine varied, 2 harness or
build problem.
"""
import argparse
import os
import random
import struct
import sys
import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    create_manager,
    jsr,
    read_bytes,
    write_bytes,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark_chacha20_poly1305 as bench  # noqa: E402

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PRG_NAME = "c64_chacha20_poly1305.prg"
LABELS_NAME = "labels.txt"

VIC_CR1 = 0xD011
AAD_BUF = 0xC200
DATA_BUF = 0x5000
SHIM = 0xC1E0
AAD_LEN = 13
DATA_LEN = 100


def write_ptr(transport, addr, target):
    write_bytes(transport, addr, bytes([target & 0xFF, target >> 8]))


def measure(transport, addr, overhead, setup, samples):
    """Cycles for one input class; every sample must agree."""
    bench.patch_target(transport, addr)
    vals = []
    for _ in range(samples):
        setup()
        bench.patch_target(transport, addr)
        bench.run_wrapper(transport)
        vals.append(bench.read_timer(transport) - overhead)
    return vals


def poly_classes(rng):
    rnd = lambda n: bytes(rng.randrange(256) for _ in range(n))
    return [
        ("h=0, r=0", bytes(17), bytes(16)),
        ("h=0, r=$FF", bytes(17), b"\xff" * 16),
        ("h=$FF, r=0", b"\xff" * 16 + b"\x03", bytes(16)),
        ("h=$FF, r=$FF", b"\xff" * 16 + b"\x03", b"\xff" * 16),
        ("alternating zero limbs", bytes([0, 0xff] * 8 + [3]),
         bytes([0xff, 0] * 8)),
        ("random 1", rnd(16) + b"\x01", rnd(16)),
        ("random 2", rnd(16) + b"\x02", rnd(16)),
        ("random 3", rnd(16) + b"\x00", rnd(16)),
    ]


def run_checks(transport, labels, samples, rng):
    write_bytes(transport, VIC_CR1, bytes([0x0B]))   # $1B with DEN clear
    bench.install_wrapper(transport)
    overhead, spread = bench.calibrate(transport, samples=10)
    if spread != 0:
        print(f"FATAL: wrapper calibration varies by {spread} cy with the "
              "display blanked — cycle counts are not exact, so no verdict "
              "below would mean anything.")
        return 2
    jsr(transport, labels["poly1305_lib_init"], timeout=120.0)

    results = {}

    # --- poly1305_multiply ---------------------------------------------
    rows = []
    for name, h, r in poly_classes(rng):
        def setup(h=h, r=r):
            write_bytes(transport, labels["poly_h"], h)
            write_bytes(transport, labels["poly_r"], r)
        rows.append((name, measure(transport, labels["poly1305_multiply"],
                                   overhead, setup, samples)))
    results["poly1305_multiply"] = rows

    # --- chacha20_block ------------------------------------------------
    rows = []
    for name, key, nonce in [
        ("key=0, nonce=0", bytes(32), bytes(12)),
        ("key=$FF, nonce=$FF", b"\xff" * 32, b"\xff" * 12),
        ("random 1", bytes(rng.randrange(256) for _ in range(32)),
         bytes(rng.randrange(256) for _ in range(12))),
        ("random 2", bytes(rng.randrange(256) for _ in range(32)),
         bytes(rng.randrange(256) for _ in range(12))),
    ]:
        def setup(key=key, nonce=nonce):
            write_bytes(transport, labels["cc20_key"], key)
            write_bytes(transport, labels["cc20_nonce"], nonce)
            write_bytes(transport, labels["cc20_counter"], struct.pack("<I", 7))
            jsr(transport, labels["chacha20_init"], timeout=30.0)
        rows.append((name, measure(transport, labels["chacha20_block"],
                                   overhead, setup, samples)))
    results["chacha20_block"] = rows

    # --- aead_encrypt, fixed lengths -----------------------------------
    def aead_inputs(key, nonce, aad, pt):
        write_bytes(transport, labels["aead_key"], key)
        write_bytes(transport, labels["aead_nonce"], nonce)
        write_bytes(transport, AAD_BUF, aad)
        write_ptr(transport, labels["aead_aad_ptr"], AAD_BUF)
        write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))
        write_bytes(transport, DATA_BUF, pt)
        write_ptr(transport, labels["aead_data_ptr"], DATA_BUF)
        write_bytes(transport, labels["aead_data_len"],
                    struct.pack("<H", len(pt)))

    rnd = lambda n: bytes(rng.randrange(256) for _ in range(n))
    aead_cases = [
        ("all zero", bytes(32), bytes(12), bytes(AAD_LEN), bytes(DATA_LEN)),
        ("all $FF", b"\xff" * 32, b"\xff" * 12, b"\xff" * AAD_LEN,
         b"\xff" * DATA_LEN),
        ("random 1", rnd(32), rnd(12), rnd(AAD_LEN), rnd(DATA_LEN)),
        ("random 2", rnd(32), rnd(12), rnd(AAD_LEN), rnd(DATA_LEN)),
    ]
    rows = []
    for name, *case in aead_cases:
        rows.append((name, measure(transport, labels["aead_encrypt"], overhead,
                                   lambda case=case: aead_inputs(*case),
                                   samples)))
    results[f"aead_encrypt n={DATA_LEN}"] = rows

    # --- aead_decrypt, tag mismatch position ---------------------------
    # Encrypt once for a valid (ct, tag), then corrupt the tag in different
    # places. Every case fails authentication, so every case takes the same
    # path through the API; only WHERE the tags differ changes.
    key, nonce, aad, pt = aead_cases[2][1:]
    aead_inputs(key, nonce, aad, pt)
    jsr(transport, labels["aead_encrypt"], timeout=120.0)
    ct = read_bytes(transport, DATA_BUF, DATA_LEN)
    tag = read_bytes(transport, labels["aead_tag"], 16)
    rows = []
    for name, flip in [("differs at byte 0", [0]),
                       ("differs at byte 15", [15]),
                       ("differs everywhere", list(range(16)))]:
        bad = bytes(t ^ (0x01 if i in flip else 0) for i, t in enumerate(tag))

        def setup(bad=bad):
            aead_inputs(key, nonce, aad, ct)
            write_bytes(transport, labels["aead_tag"], bad)
        rows.append((name, measure(transport, labels["aead_decrypt"], overhead,
                                   setup, samples)))
    results["aead_decrypt (auth fail)"] = rows

    # --- verdict -------------------------------------------------------
    rc = 0
    for routine, rows in results.items():
        noisy = [n for n, v in rows if len(set(v)) != 1]
        mins = {n: min(v) for n, v in rows}
        distinct = sorted(set(mins.values()))
        print(f"\n{routine}")
        for n, v in rows:
            print(f"  {n:24s} {min(v):>9}" +
                  ("" if len(set(v)) == 1 else f"   VARIES {sorted(set(v))}"))
        if noisy:
            print(f"  ERROR: repeated runs of one input disagree ({noisy}) — "
                  "the measurement is not exact, no verdict")
            rc = max(rc, 2)
        elif len(distinct) == 1:
            print(f"  CONSTANT-TIME: {distinct[0]} cy for all "
                  f"{len(rows)} classes")
        else:
            print(f"  LEAK: {len(distinct)} distinct cycle counts, spread "
                  f"{distinct[-1] - distinct[0]} cy")
            rc = max(rc, 1)
    return rc


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--profile", default="compact",
                    help="build/profile-<name> to load (default: compact)")
    ap.add_argument("--samples", type=int, default=3)
    ap.add_argument("--seed", type=int, default=8439)
    args = ap.parse_args()

    pdir = os.path.join(PROJECT_ROOT, "build", f"profile-{args.profile}")
    prg = os.path.join(pdir, PRG_NAME)
    lbl = os.path.join(pdir, LABELS_NAME)
    if not os.path.exists(prg):
        print(f"FATAL: {prg} not found — run `make profile-{args.profile}`")
        return 2
    labels = Labels.from_file(lbl)
    need = ["poly1305_lib_init", "poly1305_multiply", "poly_h", "poly_r",
            "chacha20_init", "chacha20_block", "cc20_key", "cc20_nonce",
            "cc20_counter", "aead_encrypt", "aead_decrypt", "aead_key",
            "aead_nonce", "aead_aad_ptr", "aead_aad_len", "aead_data_ptr",
            "aead_data_len", "aead_tag"]
    missing = [n for n in need if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing in {lbl}: {missing}")
        return 2
    print(f"ct_timing_check: {prg}")

    cfg = ViceConfig(prg_path=prg, warp=True, ntsc=True, sound=False,
                     extra_args=["-autostartprgmode", "1"])
    with create_manager(backend="vice", vice_config=cfg) as mgr:
        inst = mgr.acquire()
        time.sleep(1.0)
        try:
            rc = run_checks(inst.transport, labels, args.samples,
                            random.Random(args.seed))
        finally:
            mgr.release(inst)
    print("\nRESULT:", {0: "PASS", 1: "FAIL (timing leak)",
                        2: "ERROR (no verdict)"}[rc])
    return rc


if __name__ == "__main__":
    sys.exit(main())
