#!/usr/bin/env python3
"""
Brute-force correctness check for ct_mul_8x8 (Profile B).

Tests all 65 536 (a, b) pairs in [0,255]^2 against a Python
reference `a*b` and asserts byte-equality of the 16-bit result
in poly_prod_lo / poly_prod_hi.

Usage: C64_SKIP_BUILD=1 python3 tools/ct_mul_brute_check.py

Expects build/profile-b/c64_chacha20_poly1305.prg to exist (build via
`make profile-b`). Uses a tiny in-RAM batch harness at $C000 that
loops Y = 0..255 calling ct_mul_8x8 once per b and streaming the
16-bit results to $C200 (lo) / $C300 (hi), so the whole sweep is
256 VICE roundtrips (one per 'a') instead of 65 536.

Does NOT assert timing — that's the CT contract covered by code
inspection and the cross-check. This script only asserts functional
correctness of the primitive.
"""
from __future__ import annotations

import os
import sys
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)

from c64_test_harness import (
    Labels,
    ViceConfig,
    create_manager,
    read_bytes,
    write_bytes,
    jsr,
)

PRG_PATH = os.path.join(PROJECT_ROOT, "build", "profile-b", "c64_chacha20_poly1305.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "profile-b", "labels.txt")

SHIM_ADDR = 0xC000
RESULTS_LO = 0xC200
RESULTS_HI = 0xC300


def build_shim(ct_mul_addr: int, prod_lo: int, prod_hi: int) -> bytes:
    """Assemble the 256-b tight loop at $C000.

    Layout (byte offsets from $C000):
      00: A9 00           lda #$00
      02: 8D 25 C0        sta b_val
      05: A8              tay
      06: 20 lo hi        jsr ct_mul_8x8
      09: AC 25 C0        ldy b_val
      0C: AD lo hi        lda poly_prod_lo
      0F: 99 00 C2        sta $C200,y
      12: AD lo hi        lda poly_prod_hi
      15: 99 00 C3        sta $C300,y
      18: EE 25 C0        inc b_val
      1B: AD 25 C0        lda b_val
      1E: D0 E2           bne -$1E  → back to $C002
      20: 60              rts
      21..24: padding
      25: 00              b_val
    """
    def abs_bytes(a):  # little-endian 16-bit
        return bytes([a & 0xFF, (a >> 8) & 0xFF])

    code = bytearray(0x26)
    code[0x00:0x02] = b"\xA9\x00"                             # lda #$00
    code[0x02:0x05] = b"\x8D" + abs_bytes(SHIM_ADDR + 0x25)   # sta b_val
    code[0x05:0x06] = b"\xA8"                                 # tay
    code[0x06:0x09] = b"\x20" + abs_bytes(ct_mul_addr)        # jsr ct_mul_8x8
    code[0x09:0x0C] = b"\xAC" + abs_bytes(SHIM_ADDR + 0x25)   # ldy b_val
    code[0x0C:0x0F] = b"\xAD" + abs_bytes(prod_lo)            # lda poly_prod_lo
    code[0x0F:0x12] = b"\x99" + abs_bytes(RESULTS_LO)         # sta $C200,y
    code[0x12:0x15] = b"\xAD" + abs_bytes(prod_hi)            # lda poly_prod_hi
    code[0x15:0x18] = b"\x99" + abs_bytes(RESULTS_HI)         # sta $C300,y
    code[0x18:0x1B] = b"\xEE" + abs_bytes(SHIM_ADDR + 0x25)   # inc b_val
    code[0x1B:0x1E] = b"\xAD" + abs_bytes(SHIM_ADDR + 0x25)   # lda b_val
    code[0x1E:0x20] = b"\xD0\xE2"                             # bne -$1E
    code[0x20:0x21] = b"\x60"                                 # rts
    code[0x25:0x26] = b"\x00"                                 # b_val = 0
    return bytes(code)


def main() -> int:
    labels = Labels.from_file(LABELS_PATH)
    ct_mul_addr = labels["ct_mul_8x8"]
    smc_sum_imm1 = labels["smc_sum_a_imm"] + 1   # immediate byte
    smc_diff_imm1 = labels["smc_diff_a_imm"] + 1 # immediate byte
    prod_lo = labels["poly_prod_lo"]
    prod_hi = labels["poly_prod_hi"]
    poly1305_lib_init = labels["poly1305_lib_init"]

    print(f"ct_mul_8x8        = ${ct_mul_addr:04x}")
    print(f"smc_sum_a_imm+1   = ${smc_sum_imm1:04x}")
    print(f"smc_diff_a_imm+1  = ${smc_diff_imm1:04x}")
    print(f"poly_prod_lo      = ${prod_lo:04x}")
    print(f"poly_prod_hi      = ${prod_hi:04x}")

    shim = build_shim(ct_mul_addr, prod_lo, prod_hi)

    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    backend = os.environ.get("C64_BACKEND", "u64").lower()

    t_start = time.time()
    with create_manager(backend=backend, vice_config=cfg) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        time.sleep(1.0)  # let BASIC settle before first jsr

        # Build sqtab_lo/hi (one-shot).
        jsr(transport, poly1305_lib_init, timeout=30.0)

        # Plant shim at $C000.
        write_bytes(transport, SHIM_ADDR, shim)

        mismatches = 0
        max_report = 8
        total = 0
        for a in range(256):
            # SMC-bake a into both ct_mul_8x8 immediate slots.
            write_bytes(transport, smc_sum_imm1, bytes([a]))
            write_bytes(transport, smc_diff_imm1, bytes([a]))

            # Run 256-b inner sweep; results land at $C200 / $C300.
            jsr(transport, SHIM_ADDR, timeout=5.0)

            lo = read_bytes(transport, RESULTS_LO, 256)
            hi = read_bytes(transport, RESULTS_HI, 256)

            for b in range(256):
                expected = a * b
                got = lo[b] | (hi[b] << 8)
                total += 1
                if got != expected:
                    mismatches += 1
                    if mismatches <= max_report:
                        print(
                            f"MISMATCH a={a:3d} b={b:3d}: "
                            f"expected ${expected:04x}, got ${got:04x}"
                        )
            if (a + 1) % 32 == 0:
                elapsed = time.time() - t_start
                print(f"  a={a+1:3d}/256 ({elapsed:.1f}s, {mismatches} mismatches)")

        mgr.release(inst)

    elapsed = time.time() - t_start
    print("=" * 60)
    print(f"Total pairs checked: {total}")
    print(f"Mismatches: {mismatches}")
    print(f"Elapsed: {elapsed:.1f}s")
    if mismatches == 0:
        print("RESULT: ct_mul_8x8 PASS (65536/65536)")
        return 0
    print("RESULT: ct_mul_8x8 FAIL")
    return 1


if __name__ == "__main__":
    sys.exit(main())
