#!/usr/bin/env python3
"""
benchmark_chacha20_poly1305.py - Cycle-accurate benchmark for the
ChaCha20-Poly1305 C64 library.

Measures exact cycle counts for the primary hot-path routines in the
ChaCha20, Poly1305, and AEAD layers using a chained CIA #1 Timer A+B
32-bit cycle counter (Timer A alone overflows for most of these routines).
Model and rationale are borrowed from c64-polyval/tools/benchmark_polyval.py.

Benchmarked routines:
  chacha20_block                  - one 64-byte keystream block (cold state)
  poly1305_block                  - one 16-byte Poly1305 block
                                    (add + multiply + reduce)
  aead_encrypt / aead_decrypt     - full AEAD pass over {0, 64, 128, 512, 1024}
                                    bytes of plaintext / ciphertext

Usage:
    python3 tools/benchmark_chacha20_poly1305.py [--samples N] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc.

All timing is via the c64-test-harness ViceInstanceManager / jsr() API.
Use `min` of N samples (VICE binary monitor occasionally injects stalls).
"""

import argparse
import os
import struct
import subprocess
import sys
import time

from c64_test_harness import (
    Labels,
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
    write_bytes,
    jsr,
)

# ---------------------------------------------------------------------------
# Project paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64_chacha20_poly1305.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

DEFAULT_SAMPLES = 5
VERBOSE = False

# Scratch buffer for inputs. $C200-$CFFF is free (wrappers live in $C000-$C1FF).
SCRATCH_BUF = 0xC200

# ---------------------------------------------------------------------------
# Chained CIA Timer A+B 32-bit wrapper (ported verbatim from c64-polyval)
# ---------------------------------------------------------------------------
#
# Layout at $C080 (see c64-polyval/tools/benchmark_polyval.py for commentary).
# Timer A free-runs from $FFFF; Timer B counts Timer A underflows
# (INMODE=%10, CRB bits 6:5).  Total cycles = (0xFFFF - A) + (0xFFFF - B)*0x10000.

LONG_WRAPPER_ADDR = 0xC080
LONG_WRAPPER = bytes([
    0x78,                               # SEI
    0xAD, 0x0E, 0xDC,                   # LDA $DC0E
    0x8D, 0xE6, 0xC0,                   # STA save_cra
    0xAD, 0x0F, 0xDC,                   # LDA $DC0F
    0x8D, 0xE7, 0xC0,                   # STA save_crb
    0xA9, 0xFF,                         # LDA #$FF
    0x8D, 0x04, 0xDC,                   # STA $DC04
    0x8D, 0x05, 0xDC,                   # STA $DC05
    0x8D, 0x06, 0xDC,                   # STA $DC06
    0x8D, 0x07, 0xDC,                   # STA $DC07
    0xA9, 0x50,                         # LDA #$50  B: load, INMODE=A-underflow
    0x8D, 0x0F, 0xDC,                   # STA $DC0F
    0xA9, 0x10,                         # LDA #$10  A: force-load
    0x8D, 0x0E, 0xDC,                   # STA $DC0E
    0xA9, 0x41,                         # LDA #$41  B: start, continuous, INMODE
    0x8D, 0x0F, 0xDC,                   # STA $DC0F
    0xA9, 0x11,                         # LDA #$11  A: start, continuous
    0x8D, 0x0E, 0xDC,                   # STA $DC0E
    0x20, 0x00, 0x00,                   # JSR target  (patched)
    0xA9, 0x08,                         # LDA #$08  A: stop
    0x8D, 0x0E, 0xDC,                   # STA $DC0E
    0xA9, 0x40,                         # LDA #$40  B: stop
    0x8D, 0x0F, 0xDC,                   # STA $DC0F
    0xAD, 0x04, 0xDC,                   # LDA $DC04
    0x8D, 0xE2, 0xC0,                   # STA a_lo
    0xAD, 0x05, 0xDC,                   # LDA $DC05
    0x8D, 0xE3, 0xC0,                   # STA a_hi
    0xAD, 0x06, 0xDC,                   # LDA $DC06
    0x8D, 0xE4, 0xC0,                   # STA b_lo
    0xAD, 0x07, 0xDC,                   # LDA $DC07
    0x8D, 0xE5, 0xC0,                   # STA b_hi
    0xAD, 0xE6, 0xC0,                   # LDA save_cra
    0x8D, 0x0E, 0xDC,                   # STA $DC0E
    0xAD, 0xE7, 0xC0,                   # LDA save_crb
    0x8D, 0x0F, 0xDC,                   # STA $DC0F
    0x58,                               # CLI
    0x60,                               # RTS
])

# Find the JSR-to-zero placeholder in the wrapper bytes.
def _jsr_offset(buf):
    for i in range(len(buf) - 2):
        if buf[i] == 0x20 and buf[i + 1] == 0x00 and buf[i + 2] == 0x00:
            return i + 1
    raise RuntimeError("wrapper has no JSR placeholder")


JSR_OPERAND_OFFSET = _jsr_offset(LONG_WRAPPER)

# Absolute result addresses (hard-coded by the STA absolutes above).
A_LO_ADDR = 0xC0E2
A_HI_ADDR = 0xC0E3
B_LO_ADDR = 0xC0E4
B_HI_ADDR = 0xC0E5

RTS_STUB_ADDR = 0xC0F0


def install_wrapper(transport):
    write_bytes(transport, LONG_WRAPPER_ADDR, LONG_WRAPPER)
    write_bytes(transport, RTS_STUB_ADDR, bytes([0x60]))
    readback = read_bytes(transport, LONG_WRAPPER_ADDR, len(LONG_WRAPPER))
    if readback != LONG_WRAPPER:
        sys.exit("FATAL: wrapper readback mismatch")
    if VERBOSE:
        print(f"  Wrapper installed at ${LONG_WRAPPER_ADDR:04X} "
              f"({len(LONG_WRAPPER)} bytes)")


def patch_target(transport, addr):
    write_bytes(
        transport,
        LONG_WRAPPER_ADDR + JSR_OPERAND_OFFSET,
        bytes([addr & 0xFF, (addr >> 8) & 0xFF]),
    )


def read_timer(transport):
    a_lo = read_bytes(transport, A_LO_ADDR, 1)[0]
    a_hi = read_bytes(transport, A_HI_ADDR, 1)[0]
    b_lo = read_bytes(transport, B_LO_ADDR, 1)[0]
    b_hi = read_bytes(transport, B_HI_ADDR, 1)[0]
    a_val = (a_hi << 8) | a_lo
    b_val = (b_hi << 8) | b_lo
    return (0xFFFF - a_val) + (0xFFFF - b_val) * 0x10000


def run_wrapper(transport):
    jsr(transport, LONG_WRAPPER_ADDR, timeout=600.0)


def measure(transport, target_addr, overhead, samples, resetup=None):
    """Measure target_addr for `samples` iterations.

    If `resetup` is provided it is called BEFORE each sample with (transport,)
    as args — used to reseed mutable inputs (e.g. re-encrypt a buffer so that
    aead_decrypt has valid ciphertext each run).
    """
    patch_target(transport, target_addr)
    results = []
    for _ in range(samples):
        if resetup is not None:
            resetup(transport)
            patch_target(transport, target_addr)  # resetup may repatch
        run_wrapper(transport)
        results.append(read_timer(transport) - overhead)
    # Use min — VICE binary monitor occasionally injects stalls, min is the
    # stable cycle-accurate number.
    return min(results), max(results) - min(results)


def calibrate(transport, samples=10):
    patch_target(transport, RTS_STUB_ADDR)
    vals = []
    for _ in range(samples):
        run_wrapper(transport)
        vals.append(read_timer(transport))
    overhead = min(vals)
    spread = max(vals) - min(vals)
    if VERBOSE or spread != 0:
        print(f"  Calibration: overhead={overhead} cy, spread={spread}")
    return overhead


def verify_wrapper(transport, overhead):
    """Sanity: LDX #100 / DEX / BNE loop / RTS = 501 cycles delta."""
    stub = bytes([0xA2, 0x64, 0xCA, 0xD0, 0xFD, 0x60])
    stub_addr = 0xC0F8
    write_bytes(transport, stub_addr, stub)
    patch_target(transport, stub_addr)
    run_wrapper(transport)
    measured = read_timer(transport) - overhead
    expected = 501
    if measured != expected:
        print(f"  Wrapper verify: measured={measured} expected={expected} "
              f"(MISMATCH)")
        sys.exit(1)
    if VERBOSE:
        print(f"  Wrapper verify: {measured} cy (OK)")


# ---------------------------------------------------------------------------
# Per-routine setup helpers
# ---------------------------------------------------------------------------

def write_ptr(transport, addr, target):
    write_bytes(transport, addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def setup_chacha20_block(transport, labels):
    """Prime state so chacha20_block processes a known 64-byte block.

    Writes the standard RFC 7539 §2.3.2 test vector into cc20_state and
    returns the target address of chacha20_block.  Benchmark runs the block
    routine with a warm state (no re-init needed each call).
    """
    # RFC 7539 test vector state.
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    counter = 1
    # Build the 16-word state directly.
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))
    state = constants + key_words + [counter] + nonce_words
    state_bytes = struct.pack('<16I', *state)
    write_bytes(transport, labels["cc20_state"], state_bytes)


def setup_poly1305_block(transport, labels):
    """Fully initialize Poly1305 (r, s, h=0, sqtab) so poly1305_block can be
    called in isolation against a 16-byte block of message data at SCRATCH_BUF.
    Returns nothing — caller patches wrapper to poly1305_block.
    """
    # Pick a non-trivial key.  Use RFC 7539 §2.5.2 r,s key for determinism.
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"  # r
        "0103808afb0db2fd4abff6af4149f51b"  # s
    )
    write_bytes(transport, labels["poly_r"], key[:16])
    write_bytes(transport, labels["poly_s"], key[16:])
    # poly1305_init: clamp r, zero h, build sqtab.
    jsr(transport, labels["poly1305_init"], timeout=60.0)
    # Block input at SCRATCH_BUF.
    write_bytes(transport, SCRATCH_BUF, b"Cryptographic Fo")  # 16 bytes
    # Point zp_ptr1 at the block.
    write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
    # poly1305_block reads A on entry for the high bit — the wrapper will
    # not control A for us, but SEI path preserves whatever was left in A
    # before wrapper entry.  To make this deterministic we install a tiny
    # shim at $C1E0 that loads A=1 then jumps to poly1305_block.
    shim = bytes([0xA9, 0x01,                       # LDA #$01
                  0x4C,                              # JMP abs
                  labels["poly1305_block"] & 0xFF,
                  (labels["poly1305_block"] >> 8) & 0xFF])
    write_bytes(transport, 0xC1E0, shim)
    return 0xC1E0


def setup_aead_encrypt(transport, labels, msg_len):
    """Prepare inputs for aead_encrypt over msg_len bytes of plaintext.
    Returns the address to patch into the wrapper (aead_encrypt entry).

    Uses a 32-byte key, 12-byte nonce, 0-byte AAD, and msg_len bytes of
    plaintext.  Plaintext lives at $4000..$4000+msg_len (clear of the
    library PRG at $0810..$12bb and of the sqtab at $8000..$83ff).
    """
    key = bytes(range(32))
    nonce = bytes(range(12))
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    aad_buf = SCRATCH_BUF  # unused when aad_len=0, but must be a valid ptr
    write_ptr(transport, labels["aead_aad_ptr"], aad_buf)
    write_bytes(transport, labels["aead_aad_len"], bytes([0]))

    pt_addr = 0x4000
    if msg_len > 0:
        write_bytes(transport, pt_addr, bytes((i & 0xFF) for i in range(msg_len)))
    write_ptr(transport, labels["aead_data_ptr"], pt_addr)
    write_bytes(transport, labels["aead_data_len"],
                struct.pack('<H', msg_len))
    return labels["aead_encrypt"]


def setup_aead_decrypt(transport, labels, msg_len):
    """Prepare inputs for aead_decrypt.  First runs aead_encrypt to get a
    valid tag for a msg_len message, then rewinds the data and tag so that
    the benchmark call is a valid (tag-ok) decrypt pass."""
    setup_aead_encrypt(transport, labels, msg_len)
    jsr(transport, labels["aead_encrypt"], timeout=600.0)
    # Copy produced tag into aead_tag so decrypt validates.
    tag = read_bytes(transport, labels["poly1305_tag"], 16)
    write_bytes(transport, labels["aead_tag"], tag)
    # Data buffer now holds ciphertext in-place — that's what we want.
    return labels["aead_decrypt"]


# ---------------------------------------------------------------------------
# Benchmark driver
# ---------------------------------------------------------------------------

def run(samples=DEFAULT_SAMPLES):
    # Start VICE
    if not os.path.exists(PRG_PATH):
        subprocess.run(["make"], cwd=PROJECT_ROOT, check=True)

    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    labels = Labels.from_file(LABELS_PATH)

    results = []  # list of (name, cycles, spread)

    with ViceInstanceManager(config=cfg) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        # Let BASIC settle.
        time.sleep(1.0)

        install_wrapper(transport)
        overhead = calibrate(transport, samples=10)
        verify_wrapper(transport, overhead)

        # --- chacha20_block (cold state each call is fine; benchmark warm) ---
        setup_chacha20_block(transport, labels)
        cyc, spr = measure(transport, labels["chacha20_block"],
                           overhead, samples)
        results.append(("chacha20_block (64 B keystream)", cyc, spr))

        # --- poly1305_block (one 16-byte block, r/s/sqtab ready) ---
        shim_addr = setup_poly1305_block(transport, labels)
        cyc, spr = measure(transport, shim_addr, overhead, samples)
        results.append(("poly1305_block (16 B, mul+reduce)", cyc, spr))

        # --- aead_encrypt for various sizes ---
        for msg_len in [0, 64, 128, 512, 1024]:
            target = setup_aead_encrypt(transport, labels, msg_len)
            cyc, spr = measure(transport, target, overhead, samples)
            results.append((f"aead_encrypt n={msg_len:4d}", cyc, spr))

        # --- aead_decrypt for various sizes (tag valid) ---
        for msg_len in [0, 64, 128, 512, 1024]:
            # aead_decrypt is in-place XOR: after the first successful call
            # the data buffer is now plaintext and a second call would
            # fail auth.  Resetup before each sample by re-running
            # aead_encrypt to repopulate the ciphertext + tag.
            def _resetup(t, n=msg_len):
                setup_aead_decrypt(t, labels, n)
            target = setup_aead_decrypt(transport, labels, msg_len)
            cyc, spr = measure(transport, target, overhead, samples,
                               resetup=_resetup)
            results.append((f"aead_decrypt n={msg_len:4d}", cyc, spr))

        mgr.release(inst)

    # Print table
    print()
    print("=" * 64)
    print(f"{'routine':<40s} {'cycles':>12s} {'spread':>8s}")
    print("-" * 64)
    for name, cyc, spr in results:
        print(f"{name:<40s} {cyc:>12d} {spr:>8d}")
    print("=" * 64)

    # cycles-per-byte derived column for AEAD rows
    print()
    print("Derived cycles/byte (aead_encrypt, excluding n=0):")
    for name, cyc, _ in results:
        if name.startswith("aead_encrypt") and " n=   0" not in name:
            try:
                n = int(name.split("n=")[1])
            except ValueError:
                continue
            if n > 0:
                print(f"  {name}: {cyc/n:8.1f} cy/byte")

    return results


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose
    run(samples=args.samples)


if __name__ == "__main__":
    main()
