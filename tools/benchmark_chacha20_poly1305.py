#!/usr/bin/env python3
"""
benchmark_chacha20_poly1305.py - Cycle-accurate benchmark for the
ChaCha20-Poly1305 C64 library.

Measures exact cycle counts for the primary hot-path routines in the
ChaCha20, Poly1305, and AEAD layers.

Benchmarked routines:
  chacha20_block                  - one 64-byte keystream block (cold state)
  poly1305_block                  - one 16-byte Poly1305 block
                                    (add + multiply + reduce)
  aead_encrypt / aead_decrypt     - full AEAD pass over {0, 64, 128, 512, 1024}
                                    bytes of plaintext / ciphertext

Usage:
    python3 tools/benchmark_chacha20_poly1305.py [--samples N] [--verbose]

Requires: Python 3.10+, c64_test_harness, VICE x64sc (for vice backend) or
an Ultimate 64 reachable via U64_HOST (for u64 backend).

Backend selection:
    --backend vice  (default; honors $C64_BACKEND, fallback "vice")
    --backend u64   (cycle counts via the same CIA-timer wrapper as VICE,
                     invoked through the trampoline shim from
                     tools/_u64_helpers.py)

Cycle counting:
    Both backends use a chained CIA #1 Timer A+B 32-bit cycle counter
    installed at $C080. The wrapper does SEI; save CIA state; CIA setup;
    JSR target; CIA stop; restore CIA state; CLI; RTS. Calibration
    measures wrapper(rts_stub) overhead and subtracts it per sample.
    min of N samples reported (VICE binary monitor and U64 REST API
    occasionally inject stalls; min is the stable cycle-accurate number).

    The wrapper is pure 6502 and runs identically on real U64 hardware.
    The only backend-dependent piece is how the wrapper is invoked —
    jsr() (VICE binary monitor breakpoint) on VICE, run_subroutine()
    (sentinel-poll trampoline shim) on U64.

    DebugCapture (UDP cycle-stream) was tried on U64 first per the
    canonical c64-test pattern but observed ~60-90% packet drops on the
    available U64E firmware/network combo, so the marker-based parse
    in _u64_helpers.py:measure_cycles cannot detect every JSR/STA pair
    pair reliably. CIA-timer-in-RAM is cycle-exact on both backends.
    See _u64_helpers.py for the full diagnosis.
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
    create_manager,
    keyboard,
    read_bytes,
    wait_for_text,
    write_bytes,
    jsr,
)

from _u64_helpers import run_subroutine

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
    """VICE calibration: returns (overhead, spread).

    VICE is deterministic so spread is normally 0.  Returned spread is
    used by `verify_wrapper` to construct a tolerance window — on VICE
    that window is exact (spread=0), on U64 it absorbs CIA-timer jitter.
    """
    patch_target(transport, RTS_STUB_ADDR)
    vals = []
    for _ in range(samples):
        run_wrapper(transport)
        vals.append(read_timer(transport))
    overhead = min(vals)
    spread = max(vals) - min(vals)
    if VERBOSE or spread != 0:
        print(f"  Calibration: overhead={overhead} cy, spread={spread} "
              f"(samples={samples})")
    return overhead, spread


def _expected_wrapper_cycles(backend: str) -> int:
    """Nominal expected cycle count for the LDX/DEX/BNE/RTS verify stub.

    The deterministic 6502 work is 501 cycles (LDX #100, then 100x
    DEX/BNE plus the final RTS).  This is exact on VICE.  On U64E
    hardware, the chained CIA wrapper carries an additional non-
    deterministic component of up to ~43 cycles per sample driven by
    real-6526 timer-arming interactions and the REU/cartridge bus
    stretch on CIA accesses; that jitter rides on top of the 501.
    Callers compute the tolerance window from the calibration spread
    rather than picking a single backend-specific scalar.
    """
    return 501


U64_JITTER_FLOOR = 50  # known per-sample CIA-timer jitter on U64E (~43 cy)


def _wrapper_tolerance_window(backend, calibration_spread, calibration_samples):
    """Compute (lo, hi) tolerance window for the verify-stub measurement.

    VICE: exact match (spread=0, no margin).
    U64:  501 +/- jitter, where jitter is the larger of the observed
          calibration spread and a known floor (`U64_JITTER_FLOOR`).
          The floor matters because the calibration's no-op samples
          and the verify's stub sample are independent draws from the
          same distribution: even when calibration's 20 samples happen
          to all land at the fast end (spread=0), the verify can still
          land at the slow end (501 + 43), and conversely if calibration
          catches the slow tail and verify is fast (501 - 43).  The
          window must absorb that worst-case differential.
    """
    nominal = _expected_wrapper_cycles(backend)
    if backend != "u64":
        # Deterministic backend — exact match.
        return nominal, nominal, False
    if calibration_samples >= 5:
        # The dominant noise source is the per-sample CIA-jitter,
        # bounded by the larger of observed and known.  Apply
        # symmetrically because the verify and overhead samples are
        # independent draws (slow verify with fast calibration shifts
        # measured up; fast verify with slow calibration shifts it
        # down by the same amount).
        jitter = max(calibration_spread, U64_JITTER_FLOOR)
        return nominal - jitter, nominal + jitter, False
    # Fallback if calibration was too short to characterize jitter.
    print("  Wrapper verify: WARNING — calibration produced <5 samples, "
          "using fixed fallback window 440..580")
    return 440, 580, True


def verify_wrapper(transport, overhead, calibration_spread=0,
                   calibration_samples=10):
    """Sanity-check the wrapper.

    On VICE the LDX #100 / DEX / BNE / RTS stub takes exactly 501
    cycles after overhead subtraction.  Window comes from the
    backend-specific tolerance helper; on VICE it collapses to an
    exact match.
    """
    stub = bytes([0xA2, 0x64, 0xCA, 0xD0, 0xFD, 0x60])
    stub_addr = 0xC0F8
    write_bytes(transport, stub_addr, stub)
    patch_target(transport, stub_addr)
    run_wrapper(transport)
    measured = read_timer(transport) - overhead
    lo, hi, _ = _wrapper_tolerance_window(
        "vice", calibration_spread, calibration_samples
    )
    if not (lo <= measured <= hi):
        print(f"  Wrapper verify: measured={measured} window=[{lo},{hi}] "
              f"(MISMATCH, backend=vice)")
        sys.exit(1)
    if VERBOSE:
        print(f"  Wrapper verify: {measured} cy in [{lo},{hi}] (OK)")


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
    plaintext.  Plaintext lives at $5000..$5000+msg_len (clear of the
    library PRG — which after the Step 4 unroll reaches ~$43a1 — and of
    the sqtab at $8000..$83ff).
    """
    key = bytes(range(32))
    nonce = bytes(range(12))
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    aad_buf = SCRATCH_BUF  # unused when aad_len=0, but must be a valid ptr
    write_ptr(transport, labels["aead_aad_ptr"], aad_buf)
    write_bytes(transport, labels["aead_aad_len"], bytes([0]))

    pt_addr = 0x5000
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

# ---------------------------------------------------------------------------
# U64-specific setup helpers (use run_subroutine instead of jsr for prep)
# ---------------------------------------------------------------------------

def _u64_calibrate(target, samples=20):
    """U64 calibration: JSRs the wrapper via the trampoline shim.

    Runs more samples than VICE (default 20) because U64E carries up
    to ~43 cycles of CIA-timer-arming jitter per wrapper invocation;
    we need enough samples to characterize the spread that
    `_u64_verify_wrapper` will use as its tolerance.

    Returns (overhead, spread).
    """
    transport = target.transport
    patch_target(transport, RTS_STUB_ADDR)
    vals = []
    for _ in range(samples):
        run_subroutine(target, LONG_WRAPPER_ADDR, timeout=600.0)
        vals.append(read_timer(transport))
    overhead = min(vals)
    spread = max(vals) - min(vals)
    if VERBOSE or spread != 0:
        print(f"  Calibration: overhead={overhead} cy, spread={spread} "
              f"(samples={samples})")
    return overhead, spread


def _u64_verify_wrapper(target, overhead, calibration_spread,
                        calibration_samples):
    """U64 verify: tolerance-window check rather than exact match.

    The deterministic 6502 work in the verify stub is 501 cycles.  On
    U64E a per-sample jitter of up to ~43 cycles rides on top of that
    due to real-CIA timer-arming and REU/cartridge bus stretch.  The
    bench's calibration phase characterizes the same jitter against a
    no-op (RTS) target; we re-use that observed spread (plus a safety
    margin) as the tolerance band here so a single CIA-jitter spike on
    the verify sample doesn't trip the gate.
    """
    transport = target.transport
    stub = bytes([0xA2, 0x64, 0xCA, 0xD0, 0xFD, 0x60])
    stub_addr = 0xC0F8
    write_bytes(transport, stub_addr, stub)
    patch_target(transport, stub_addr)
    run_subroutine(target, LONG_WRAPPER_ADDR, timeout=600.0)
    measured = read_timer(transport) - overhead
    lo, hi, fallback = _wrapper_tolerance_window(
        "u64", calibration_spread, calibration_samples
    )
    if not (lo <= measured <= hi):
        print(f"  Wrapper verify: measured={measured} window=[{lo},{hi}] "
              f"(MISMATCH, backend=u64, calib_spread={calibration_spread}, "
              f"calib_samples={calibration_samples}, fallback={fallback})")
        sys.exit(1)
    if VERBOSE or fallback:
        print(f"  Wrapper verify: {measured} cy in [{lo},{hi}] "
              f"(OK, calib_spread={calibration_spread})")


def _u64_setup_poly1305_block(target, labels):
    """U64 variant of setup_poly1305_block.

    Same memory layout as the VICE path; the only difference is the
    poly1305_init prep call uses run_subroutine() (backend-aware) rather
    than the VICE-only jsr() checkpoint.
    """
    transport = target.transport
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"  # r
        "0103808afb0db2fd4abff6af4149f51b"  # s
    )
    write_bytes(transport, labels["poly_r"], key[:16])
    write_bytes(transport, labels["poly_s"], key[16:])
    run_subroutine(target, labels["poly1305_init"], timeout=60.0)
    write_bytes(transport, SCRATCH_BUF, b"Cryptographic Fo")
    write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
    # poly1305_block reads A on entry for the high bit; install a tiny
    # shim at $C1E0 that loads A=1 then JMPs to poly1305_block. The
    # routine's RTS pops the trampoline's return address (bypassing the
    # JMP-only shim), so cycle accounting matches the VICE-shim path.
    shim = bytes([0xA9, 0x01,                       # LDA #$01
                  0x4C,                              # JMP abs
                  labels["poly1305_block"] & 0xFF,
                  (labels["poly1305_block"] >> 8) & 0xFF])
    write_bytes(transport, 0xC1E0, shim)
    return 0xC1E0


def _u64_setup_aead_decrypt(target, labels, msg_len):
    """U64 variant of setup_aead_decrypt.

    Mirrors setup_aead_decrypt but uses run_subroutine() for the
    aead_encrypt prep call so the trampoline shim drives the JSR on
    hardware.
    """
    transport = target.transport
    setup_aead_encrypt(transport, labels, msg_len)
    run_subroutine(target, labels["aead_encrypt"], timeout=600.0)
    tag = read_bytes(transport, labels["poly1305_tag"], 16)
    write_bytes(transport, labels["aead_tag"], tag)
    return labels["aead_decrypt"]


# ---------------------------------------------------------------------------
# U64 backend driver
# ---------------------------------------------------------------------------

def _run_u64(samples):
    """U64 cycle-bench driver.

    The U64 path uses the SAME chained CIA #1 Timer A+B wrapper as the
    VICE path — the wrapper is pure 6502 and runs identically on real
    hardware. The only backend-dependent piece is how the wrapper is
    invoked (jsr() on VICE, run_subroutine() trampoline shim on U64),
    so we drive the same install_wrapper / calibrate / verify_wrapper
    helpers and re-use the existing measure() reduction (min, max-min)
    via a thin u64_measure() shim.

    Why not the shim's measure_cycles() (DebugCapture markers)?
    -----------------------------------------------------------
    The brief asked for DebugCapture, but on U64E firmware 3.14d in our
    setup the FPGA UDP debug stream hits a packet-drop floor of 60-90%
    after a sustained workload (the audit-tools agent's prior cycle).
    Even with 8 MiB SO_RCVBUF and minimal REST traffic during capture,
    sequence gaps run into the thousands and the JSR/STA marker pairs
    cannot be reliably detected. CIA-timer-in-RAM is cycle-exact, has
    no rate cap, and shares 100% of the wrapper code with VICE.
    measure_cycles() remains in the shim for future use when the
    debug-stream path is healthy (it returned ~1.5% deviation on a
    fresh-boot smoke test); see _u64_helpers.py for the diagnosis.

    Returns the same list-of-(name, cycles, spread) shape so the
    existing _print_results() formatter applies unchanged.
    """
    labels = Labels.from_file(LABELS_PATH)
    results = []  # list of (name, cycles, spread)

    mgr = create_manager(backend="u64")
    inner = getattr(mgr, "_manager", None)
    if inner is not None and hasattr(inner, "_lock_timeout"):
        inner._lock_timeout = 1800.0

    with mgr:
        with mgr.instance() as target:
            transport = target.transport
            client = transport._client

            # Sideload + RUN to reach the same BASIC-READY state VICE
            # gets via -autostart. Mirrors tools/audit_cross_check.py.
            client.WRITE_MEM_QUERY_THRESHOLD = 128
            client.reset()
            time.sleep(2.0)
            _ = wait_for_text(transport, "READY", timeout=30.0)
            with open(PRG_PATH, "rb") as f:
                prg = f.read()
            load_addr = prg[0] | (prg[1] << 8)
            write_bytes(transport, load_addr, prg[2:])
            keyboard.send_text(transport, "RUN\r")
            time.sleep(2.0)
            grid = wait_for_text(transport, "READY", timeout=30.0)
            if grid is None and VERBOSE:
                print("  warning: BASIC READY prompt not seen within 30s")

            install_wrapper(transport)
            calib_samples = 20
            overhead, calib_spread = _u64_calibrate(
                target, samples=calib_samples
            )
            _u64_verify_wrapper(target, overhead, calib_spread, calib_samples)

            def _u64_measure_one(target_addr):
                """Run the CIA wrapper around target_addr `samples` times via
                the trampoline shim, return (min, max-min) cycle tuple.
                """
                patch_target(transport, target_addr)
                vals = []
                for _ in range(samples):
                    run_subroutine(target, LONG_WRAPPER_ADDR, timeout=600.0)
                    vals.append(read_timer(transport) - overhead)
                return min(vals), max(vals) - min(vals)

            # --- chacha20_block ---
            setup_chacha20_block(transport, labels)
            cyc, spr = _u64_measure_one(labels["chacha20_block"])
            results.append(("chacha20_block (64 B keystream)", cyc, spr))

            # --- poly1305_block (r/s/sqtab ready, A=1 shim) ---
            shim_addr = _u64_setup_poly1305_block(target, labels)
            cyc, spr = _u64_measure_one(shim_addr)
            results.append(("poly1305_block (16 B, mul+reduce)", cyc, spr))

            # --- aead_encrypt for various sizes ---
            for msg_len in [0, 64, 128, 512, 1024]:
                tgt = setup_aead_encrypt(transport, labels, msg_len)
                cyc, spr = _u64_measure_one(tgt)
                results.append((f"aead_encrypt n={msg_len:4d}", cyc, spr))

            # --- aead_decrypt for various sizes (resetup per sample) ---
            for msg_len in [0, 64, 128, 512, 1024]:
                # In-place decrypt destroys the ciphertext; resetup
                # before each sample by re-running aead_encrypt.
                vals = []
                for _ in range(samples):
                    tgt = _u64_setup_aead_decrypt(target, labels, msg_len)
                    patch_target(transport, tgt)
                    run_subroutine(target, LONG_WRAPPER_ADDR, timeout=600.0)
                    vals.append(read_timer(transport) - overhead)
                results.append((
                    f"aead_decrypt n={msg_len:4d}",
                    min(vals), max(vals) - min(vals),
                ))

    return results


# ---------------------------------------------------------------------------
# Result formatter (shared by both backends — preserves byte-identical output)
# ---------------------------------------------------------------------------

def _print_results(results):
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


def run(samples=DEFAULT_SAMPLES, backend="vice"):
    # Start emulator / connect to hardware
    if not os.path.exists(PRG_PATH):
        subprocess.run(["make"], cwd=PROJECT_ROOT, check=True)

    if backend == "u64":
        results = _run_u64(samples)
        _print_results(results)
        return results

    cfg = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)
    labels = Labels.from_file(LABELS_PATH)

    results = []  # list of (name, cycles, spread)

    with create_manager(backend=backend, vice_config=cfg) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        # Let BASIC settle.
        time.sleep(1.0)

        install_wrapper(transport)
        calib_samples = 10
        overhead, calib_spread = calibrate(transport, samples=calib_samples)
        verify_wrapper(transport, overhead, calib_spread, calib_samples)

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

    _print_results(results)
    return results


def main():
    global VERBOSE
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=DEFAULT_SAMPLES)
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument(
        "--seed", type=int, default=None,
        help="Accepted for CLI compatibility with audit_cross_check; the "
             "bench uses fixed RFC 7539 vectors and ignores --seed.",
    )
    ap.add_argument(
        "--backend",
        choices=("vice", "u64"),
        default=os.environ.get("C64_BACKEND", "vice").lower(),
        help="Backend to bench against. Defaults to $C64_BACKEND or 'vice'.",
    )
    args = ap.parse_args()
    VERBOSE = args.verbose
    run(samples=args.samples, backend=args.backend)


if __name__ == "__main__":
    main()
