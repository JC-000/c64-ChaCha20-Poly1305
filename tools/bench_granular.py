#!/usr/bin/env python3
"""
bench_granular.py — Per-function granular benchmark for the
ChaCha20-Poly1305 C64 library.

Reuses the chained CIA #1 Timer A+B 32-bit wrapper at $C080 from
benchmark_chacha20_poly1305.py (which is itself ported from c64-polyval)
and extends it to bench every public-and-test-private routine that
affects the production hot path:

  - chacha20_quarter_round
  - chacha20_block          (also covered by the legacy bench)
  - chacha20_encrypt        (n=64, 1024)
  - poly1305_multiply       (direct, with clamped r + representative h)
  - poly1305_reduce         (direct, on a populated poly_product)
  - poly1305_block          (also covered by the legacy bench)
  - aead_compute_tag        (separate from full aead_encrypt)
  - aead_verify_tag         (constant-time eq, all-equal happy path)
  - sqtab_init              (single-shot init cost)
  - ct_mul_8x8              (Profile B only; tight loop over varied A/B)

Methodology mirrors the existing bench: SEI; save CIA; CIA setup; JSR
target; CIA stop; restore CIA; CLI; RTS at $C080. min-of-N reduction.
calibrate() subtracts wrapper overhead. verify_wrapper() sanity-checks
against a 501-cy stub. set_turbo_mhz(client, 1) is called after
client.reset() on the U64 path (per project memory: U64E turbo state
survives client.reset() and CIA timer reads ~1/N at turbo N MHz).

Default mode emits a JSON sidecar at docs/BENCH_REPORT.md.json and a
human-readable docs/BENCH_REPORT.md. `--check <baseline.json>` diffs
the current run against a committed baseline and exits non-zero on any
row drifting >1% (configurable via --tolerance).

Build targets:
    The granular bench prefers Profile B because that profile defines
    `ct_mul_8x8`. Profile A is also benchable (ct_mul_8x8 row is
    skipped). Use --profile {A,B}; default is "B" (preferred when
    bench-checking against the committed baseline).

Usage:
    # collect + write report + JSON sidecar
    python3 tools/bench_granular.py --samples 5 --profile B

    # collect + diff against committed baseline (CI / make bench-check)
    python3 tools/bench_granular.py --check docs/BENCH_REPORT.baseline.json

Backend selection mirrors benchmark_chacha20_poly1305.py:
    --backend vice (default) or --backend u64 (or env C64_BACKEND)
"""

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone

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
from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz

# Reuse the wrapper installation + calibration + measurement primitives
# from the existing bench (single source of truth for the CIA wrapper).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark_chacha20_poly1305 as bench  # noqa: E402
from _u64_helpers import run_subroutine  # noqa: E402

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)
DEFAULT_BUILD_PRG = os.path.join(PROJECT_ROOT, "build", "c64_chacha20_poly1305.prg")
DEFAULT_BUILD_LBL = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Scratch buffer for bench inputs. $C200-$CFFF is free (wrappers live at
# $C000-$C1FF). The legacy bench uses the same region.
SCRATCH_BUF = 0xC200
CT_LOOP_SHIM = 0xC400   # ct_mul_8x8 tight-loop driver
QR_SHIM = 0xC1F0
DEFAULT_SAMPLES = 5
DEFAULT_TOLERANCE_PCT = 1.0


# ---------------------------------------------------------------------------
# Per-target setup helpers. Each returns the *address* to patch into the
# wrapper's JSR slot. Setup runs once per target (before all samples) —
# routines that mutate inputs in a way that invalidates subsequent
# measurements are flagged via a `per_sample_setup` flag in the BENCH_TARGETS
# table below; the runner re-invokes setup before each sample for those.
# ---------------------------------------------------------------------------

def write_ptr(transport, addr, target):
    write_bytes(transport, addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


def setup_chacha20_quarter_round(transport, labels):
    """Pre-fill cc20_work with a representative state and set cc20_qr_idx=0
    so chacha20_quarter_round operates on words 0/4/8/12 (the first column
    round of the standard RFC 7539 §2.3.2 test vector).

    The bench measures one QR JSR-driven call (the test-only entry point);
    the production chacha20_block inlines QRs so this entry is NOT in the
    block hot path, but it IS the symbol consumers see in `.export` for
    isolated QR tests, and benching it directly is the only way to attribute
    perf regressions to the QR primitive.
    """
    # Match the legacy bench's chacha20_block prime: use the RFC test vector
    # state as cc20_work content so the QR is exercised on real-looking data.
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    counter = 1
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))
    state = constants + key_words + [counter] + nonce_words
    state_bytes = struct.pack('<16I', *state)
    # cc20_work lives at $0040..$007F (per zp_config.s).
    write_bytes(transport, labels["cc20_work"], state_bytes)
    # cc20_qr_idx = 0 → first column round (QR(0,4,8,12)).
    write_bytes(transport, labels["cc20_qr_idx"], bytes([0]))
    return labels["chacha20_quarter_round"]


def setup_chacha20_block(transport, labels):
    """Re-uses the legacy bench helper for identical priming."""
    bench.setup_chacha20_block(transport, labels)
    return labels["chacha20_block"]


def setup_chacha20_encrypt(transport, labels, n):
    """Prime ChaCha20 state + place n bytes of plaintext at $5000.

    chacha20_encrypt reads cc20_data_ptr (ZP $16/$17), cc20_remain ($18) /
    cc20_remain_hi for byte count, and uses cc20_state for the keystream
    generator. We initialize the state with the RFC test vector and the
    keystream output buffer (cc20_keystream / cc20_work alias) is implicitly
    populated by chacha20_block's first call inside chacha20_encrypt.
    """
    bench.setup_chacha20_block(transport, labels)
    pt_addr = 0x5000
    write_bytes(transport, pt_addr, bytes((i & 0xFF) for i in range(n)))
    write_ptr(transport, labels["cc20_data_ptr"], pt_addr)
    # cc20_remain is a single byte in ZP; cc20_remain_hi lives in RAM at
    # a separate label (not the byte just past cc20_remain). Write them
    # independently so the 16-bit count is correctly assembled.
    write_bytes(transport, labels["cc20_remain"], bytes([n & 0xFF]))
    write_bytes(transport, labels["cc20_remain_hi"], bytes([(n >> 8) & 0xFF]))
    return labels["chacha20_encrypt"]


def _poly1305_init_with_typical_state(transport, labels, backend_caller):
    """Build a representative (clamped r, h, sqtab) for poly1305_multiply
    and poly1305_reduce direct benches.

    backend_caller(addr) runs a JSR on the right backend (VICE jsr() vs
    U64 run_subroutine() shim).
    """
    # Same RFC 7539 §2.5.2 key the legacy bench uses.
    key = bytes.fromhex(
        "85d6be7857556d337f4452fe42d506a8"  # r
        "0103808afb0db2fd4abff6af4149f51b"  # s
    )
    write_bytes(transport, labels["poly_r"], key[:16])
    write_bytes(transport, labels["poly_s"], key[16:])
    # Build sqtab + shoup tables (Profile A) and clamp r.
    backend_caller(labels["poly1305_init"])
    # Set h to a representative 17-byte value (mid-range, all bits dirty).
    # Use the absorb of one 16-byte block of "Cryptographic Fo" as a starting
    # h — doing one poly1305_block warmup gives us a realistic h for the
    # subsequent direct multiply bench.
    write_bytes(transport, SCRATCH_BUF, b"Cryptographic Fo")
    write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
    # poly1305_block needs A=1 on entry for hibit; install a tiny shim that
    # sets A and JSRs poly1305_block, then RTSs (so the warmup returns
    # cleanly).
    warm_shim = 0xC1E8
    write_bytes(transport, warm_shim, bytes([
        0xA9, 0x01,                          # LDA #$01
        0x20, labels["poly1305_block"] & 0xFF,
             (labels["poly1305_block"] >> 8) & 0xFF,
        0x60,                                # RTS
    ]))
    backend_caller(warm_shim)
    # h is now populated. Save it; subsequent benches that mutate h (multiply
    # itself does not, but reduce reads it) will re-seed before each sample
    # via the per_sample_setup flag in BENCH_TARGETS.


def setup_poly1305_multiply_vice(transport, labels):
    _poly1305_init_with_typical_state(
        transport, labels,
        lambda addr: jsr(transport, addr, timeout=60.0),
    )
    return labels["poly1305_multiply"]


def setup_poly1305_multiply_u64(target, labels):
    _poly1305_init_with_typical_state(
        target.transport, labels,
        lambda addr: run_subroutine(target, addr, timeout=60.0),
    )
    return labels["poly1305_multiply"]


def setup_poly1305_reduce_vice(transport, labels):
    """poly1305_reduce reads poly_product[0..32]. The state from a fresh
    poly1305_multiply leaves it populated, so we run init + one warmup
    block + one multiply, and then bench poly1305_reduce directly.

    Note: poly1305_multiply itself falls through into poly1305_reduce in
    the production code. The bench JSRs poly1305_reduce directly with a
    pre-populated product; this reflects "given a freshly-computed
    poly_product, how long does the reduction take?".
    """
    _poly1305_init_with_typical_state(
        transport, labels,
        lambda addr: jsr(transport, addr, timeout=60.0),
    )
    # Run poly1305_multiply once to fill poly_product. Note: multiply also
    # falls through into reduce, so the state after this call is "h has
    # been reduced". Re-populate poly_product by manually filling it with
    # a deterministic pattern that's a valid intermediate (max-byte values).
    # The reduce time is dominated by straight-line code (no data-dep
    # branches except the ripple), so the exact byte values do not change
    # the cycle count materially.
    write_bytes(
        transport,
        labels["poly_product"],
        bytes([(i * 17 + 31) & 0xFF for i in range(33)]),
    )
    return labels["poly1305_reduce"]


def setup_poly1305_reduce_u64(target, labels):
    transport = target.transport
    _poly1305_init_with_typical_state(
        transport, labels,
        lambda addr: run_subroutine(target, addr, timeout=60.0),
    )
    write_bytes(
        transport,
        labels["poly_product"],
        bytes([(i * 17 + 31) & 0xFF for i in range(33)]),
    )
    return labels["poly1305_reduce"]


def setup_poly1305_block(transport, labels):
    return bench.setup_poly1305_block(transport, labels)


def setup_aead_encrypt(transport, labels, n):
    return bench.setup_aead_encrypt(transport, labels, n)


def setup_aead_compute_tag_vice(transport, labels):
    """Run aead_encrypt once so poly_r/s/h and the ciphertext + lengths are
    primed, then bench aead_compute_tag in isolation.

    Note: aead_compute_tag mutates poly_h (it absorbs the input + lengths
    pad block). So we either:
      (a) reset poly_h to zero between samples (per_sample_setup), or
      (b) compute against a representative h-after-first-pass state.

    We choose (a): zero h before each sample to keep the measurement
    isolated to "one tag compute from scratch given primed r/s and
    ciphertext".
    """
    bench.setup_aead_encrypt(transport, labels, 1024)
    # Warm up the keystream + ciphertext (so the buffer at $5000 is now
    # ciphertext, not plaintext, matching the production decrypt path).
    jsr(transport, labels["aead_encrypt"], timeout=600.0)
    return labels["aead_compute_tag"]


def setup_aead_compute_tag_u64(target, labels):
    bench.setup_aead_encrypt(target.transport, labels, 1024)
    run_subroutine(target, labels["aead_encrypt"], timeout=600.0)
    return labels["aead_compute_tag"]


def reseed_poly_h_zero(transport, labels):
    """Zero poly_h (17 bytes) — used as per-sample setup for compute_tag."""
    write_bytes(transport, labels["poly_h"], bytes(17))


def setup_aead_verify_tag_vice(transport, labels):
    """Prime poly1305_tag and aead_tag to equal values (happy-path branch:
    constant-time eq accumulator stays zero throughout).

    aead_verify_tag is fully straight-line over a 16-byte fixed loop; the
    body length does not depend on byte values (it's CT). Benching the
    happy-path is sufficient.
    """
    tag = bytes((i * 31 + 7) & 0xFF for i in range(16))
    write_bytes(transport, labels["poly1305_tag"], tag)
    write_bytes(transport, labels["aead_tag"], tag)
    return labels["aead_verify_tag"]


def setup_aead_verify_tag_u64(target, labels):
    return setup_aead_verify_tag_vice(target.transport, labels)


def setup_sqtab_init(transport, labels):
    """sqtab_init is a single-shot table builder. We bench it once and
    accept the n=1 sample (the routine is fully straight-line, so the
    measurement is exact). The runner overrides samples=1 for this target
    via the SQTAB_INIT_SINGLE_SHOT flag.
    """
    # Mark sqtab as not-ready so the next poly1305_init would rebuild;
    # but here we JSR sqtab_init directly so the readiness flag is
    # untouched.
    return labels["sqtab_init"]


# ct_mul_8x8 driver: a tight loop of N JSRs to ct_mul_8x8 with varied
# (a, b) immediate bytes baked into the SMC slots before each call. We
# can't directly poke the SMC immediates from the host between calls
# inside the wrapper (the wrapper times the whole shim), so instead we
# bake a deterministic A/B pattern into the shim itself and divide the
# measured cycles by the loop count to get cycles/call.
#
# Strategy: install a shim that pre-loads (Y=b, SMC-bakes a) and JSRs
# ct_mul_8x8 K times with varied (a, b). K=64 is enough to amortize the
# loop control without making the wrapper run absurdly long.
#
# The SMC bytes inside ct_mul_8x8 are at smc_sum_a_imm+1 and
# smc_diff_a_imm+1. We bake them in the shim's setup pass per iteration.

def _build_ct_mul_shim(labels, k=64):
    """Build a shim that calls ct_mul_8x8 K times with varied (a, b).

    Layout at CT_LOOP_SHIM:
        for i in 0..K-1:
            LDA #a_i
            STA smc_sum_a_imm+1
            STA smc_diff_a_imm+1
            LDY #b_i
            JSR ct_mul_8x8
        RTS

    a_i = (i * 47 + 11) & $FF
    b_i = (i * 91 + 73) & $FF
    These are co-prime stepping through (0..255) so the operand mix is
    representative (avoids the trivial all-zero or all-FF cases).
    """
    # The SMC macro emits `<name>_SMC` as the actual label; the immediate
    # operand sits at label+1 (LSB of the `adc #imm` / `sbc #imm`).
    sum_a = labels["smc_sum_a_imm_SMC"] + 1
    diff_a = labels["smc_diff_a_imm_SMC"] + 1
    target_addr = labels["ct_mul_8x8"]
    out = bytearray()
    for i in range(k):
        a = (i * 47 + 11) & 0xFF
        b = (i * 91 + 73) & 0xFF
        out += bytes([
            0xA9, a,                               # LDA #a
            0x8D, sum_a & 0xFF, (sum_a >> 8) & 0xFF,    # STA smc_sum_a_imm+1
            0x8D, diff_a & 0xFF, (diff_a >> 8) & 0xFF,  # STA smc_diff_a_imm+1
            0xA0, b,                               # LDY #b
            0x20, target_addr & 0xFF, (target_addr >> 8) & 0xFF,  # JSR ct_mul_8x8
        ])
    out += bytes([0x60])                            # RTS
    return bytes(out)


def setup_ct_mul_8x8_vice(transport, labels, k=64):
    """Build sqtab (so sqtab_lo/hi exist) and the SMC-driven shim."""
    # poly1305_lib_init builds sqtab unconditionally.
    jsr(transport, labels["poly1305_lib_init"], timeout=60.0)
    shim = _build_ct_mul_shim(labels, k=k)
    write_bytes(transport, CT_LOOP_SHIM, shim)
    return CT_LOOP_SHIM, k


def setup_ct_mul_8x8_u64(target, labels, k=64):
    transport = target.transport
    run_subroutine(target, labels["poly1305_lib_init"], timeout=60.0)
    shim = _build_ct_mul_shim(labels, k=k)
    write_bytes(transport, CT_LOOP_SHIM, shim)
    return CT_LOOP_SHIM, k


# ---------------------------------------------------------------------------
# Target descriptor table
# ---------------------------------------------------------------------------

# Per-target: (name, vice_setup, u64_setup, options)
# Options:
#   per_sample_setup: callable(transport_or_target, labels) run before each
#                     sample (in addition to the one-shot setup that returned
#                     the JSR address)
#   profile_b_only:   skip on Profile A
#   single_shot:      override samples=1 for this target
#   notes:            short string written into the JSON sidecar
#
# Setup callables: vice_setup(transport, labels) -> jsr_addr
#                  u64_setup(target, labels) -> jsr_addr
# For ct_mul_8x8 the setup returns (addr, loop_count) and the runner divides
# measured cycles by loop_count.

BENCH_TARGETS = [
    {
        "name": "chacha20_quarter_round",
        "vice_setup": setup_chacha20_quarter_round,
        "u64_setup": (lambda t, l: setup_chacha20_quarter_round(t.transport, l)),
        "notes": "test-only entry; QR(0,4,8,12) over RFC-7539-primed cc20_work",
        "small_routine": True,
    },
    {
        "name": "chacha20_block",
        "vice_setup": setup_chacha20_block,
        "u64_setup": (lambda t, l: setup_chacha20_block(t.transport, l)),
        "notes": "one 64-byte keystream block, warm state",
    },
    {
        "name": "chacha20_encrypt n=64",
        "vice_setup": (lambda t, l: setup_chacha20_encrypt(t, l, 64)),
        "u64_setup": (lambda t, l: setup_chacha20_encrypt(t.transport, l, 64)),
        "notes": "single full block, key/nonce primed, in-place XOR",
        "per_sample_setup_vice":
            (lambda t, l: setup_chacha20_encrypt(t, l, 64)),
        "per_sample_setup_u64":
            (lambda t, l: setup_chacha20_encrypt(t.transport, l, 64)),
    },
    {
        "name": "chacha20_encrypt n=1024",
        "vice_setup": (lambda t, l: setup_chacha20_encrypt(t, l, 1024)),
        "u64_setup": (lambda t, l: setup_chacha20_encrypt(t.transport, l, 1024)),
        "notes": "16 blocks, key/nonce primed, in-place XOR",
        "per_sample_setup_vice":
            (lambda t, l: setup_chacha20_encrypt(t, l, 1024)),
        "per_sample_setup_u64":
            (lambda t, l: setup_chacha20_encrypt(t.transport, l, 1024)),
    },
    {
        "name": "poly1305_multiply",
        "vice_setup": setup_poly1305_multiply_vice,
        "u64_setup": setup_poly1305_multiply_u64,
        "notes": "one 17x16 mul over clamped RFC r and primed h",
    },
    {
        "name": "poly1305_reduce",
        "vice_setup": setup_poly1305_reduce_vice,
        "u64_setup": setup_poly1305_reduce_u64,
        "notes": "one mod-2^130-5 reduction over fixed poly_product pattern",
        "small_routine": True,
        "per_sample_setup_vice":
            (lambda t, l: write_bytes(
                t, l["poly_product"],
                bytes([(i * 17 + 31) & 0xFF for i in range(33)]),
            )),
        "per_sample_setup_u64":
            (lambda t, l: write_bytes(
                t.transport, l["poly_product"],
                bytes([(i * 17 + 31) & 0xFF for i in range(33)]),
            )),
    },
    {
        "name": "poly1305_block",
        "vice_setup": setup_poly1305_block,
        "u64_setup": (lambda t, l: bench._u64_setup_poly1305_block(t, l)),
        "notes": "one 16 B block: add + multiply + reduce (A=1 shim)",
    },
    {
        "name": "aead_compute_tag",
        "vice_setup": setup_aead_compute_tag_vice,
        "u64_setup": setup_aead_compute_tag_u64,
        "notes": "tag compute over n=1024 ciphertext + 0-byte AAD + lengths",
        "per_sample_setup_vice": reseed_poly_h_zero,
        "per_sample_setup_u64":
            (lambda t, l: reseed_poly_h_zero(t.transport, l)),
    },
    {
        "name": "aead_verify_tag",
        "vice_setup": setup_aead_verify_tag_vice,
        "u64_setup": setup_aead_verify_tag_u64,
        "notes": "CT-eq, 16-byte happy path (all bytes equal)",
        "small_routine": True,
    },
    {
        "name": "sqtab_init",
        "vice_setup": setup_sqtab_init,
        "u64_setup": (lambda t, l: setup_sqtab_init(t.transport, l)),
        "notes": "one-shot quarter-square table build (single sample)",
        "single_shot": True,
    },
    {
        "name": "ct_mul_8x8",
        "vice_setup": setup_ct_mul_8x8_vice,
        "u64_setup": setup_ct_mul_8x8_u64,
        "notes": ("Profile B 8x8->16 multiply primitive; loop-of-64 with "
                  "varied (a,b) operands; reported as cycles/call after "
                  "dividing wrapper measurement by loop count"),
        "profile_b_only": True,
        "loop_count": 64,
    },
    # Existing AEAD coverage (kept here so a single JSON has all numbers).
    {
        "name": "aead_encrypt n=0",
        "vice_setup": (lambda t, l: setup_aead_encrypt(t, l, 0)),
        "u64_setup": (lambda t, l: setup_aead_encrypt(t.transport, l, 0)),
        "notes": "AEAD per-packet fixed cost (OTK derive + 0-byte tag)",
    },
    {
        "name": "aead_encrypt n=64",
        "vice_setup": (lambda t, l: setup_aead_encrypt(t, l, 64)),
        "u64_setup": (lambda t, l: setup_aead_encrypt(t.transport, l, 64)),
        "notes": "AEAD over one 64-byte plaintext block",
    },
    {
        "name": "aead_encrypt n=1024",
        "vice_setup": (lambda t, l: setup_aead_encrypt(t, l, 1024)),
        "u64_setup": (lambda t, l: setup_aead_encrypt(t.transport, l, 1024)),
        "notes": "AEAD over 16 blocks of plaintext",
    },
]


# ---------------------------------------------------------------------------
# VICE driver
# ---------------------------------------------------------------------------

def _run_vice(samples, profile, sweep_targets):
    cfg = ViceConfig(
        prg_path=DEFAULT_BUILD_PRG,
        warp=True,
        ntsc=True,
        sound=False,
        extra_args=["-autostartprgmode", "1"],
    )
    labels = Labels.from_file(DEFAULT_BUILD_LBL)
    rows = []
    with create_manager(backend="vice", vice_config=cfg) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        time.sleep(1.0)
        bench.install_wrapper(transport)
        calib_samples = 10
        overhead, calib_spread = bench.calibrate(
            transport, samples=calib_samples
        )
        bench.verify_wrapper(transport, overhead, calib_spread, calib_samples)

        for tgt in sweep_targets:
            if tgt.get("profile_b_only") and profile != "B":
                rows.append((tgt["name"], None, None, "skipped (profile A)"))
                continue
            n_samples = 1 if tgt.get("single_shot") else samples
            # Very small routines (sub-1k cy) need more samples to reliably
            # converge the min past wrapper jitter (~43 cy CIA-arm
            # variance observed on VICE for routines that finish in
            # ~hundreds of cycles). Bump small-routine samples to 10× of
            # the user-requested count if the target is flagged.
            if tgt.get("small_routine"):
                n_samples = max(n_samples, samples * 10)
            loop_count = tgt.get("loop_count", 1)

            # ct_mul_8x8 setup returns (addr, K); everything else returns addr.
            # If a setup references a label that doesn't exist in the current
            # link (e.g. chacha20_quarter_round under -DLIB_VARIANT_AEAD_ONLY=1
            # where the body is gated out), record n/a and continue.
            try:
                raw_addr = tgt["vice_setup"](transport, labels)
            except KeyError as exc:
                rows.append(
                    (tgt["name"], None, None,
                     f"n/a (not emitted: missing label {exc})")
                )
                continue
            if isinstance(raw_addr, tuple):
                addr, loop_count = raw_addr
            else:
                addr = raw_addr

            psetup = tgt.get("per_sample_setup_vice")
            bench.patch_target(transport, addr)
            results = []
            for _ in range(n_samples):
                if psetup is not None:
                    psetup(transport, labels)
                    bench.patch_target(transport, addr)
                bench.run_wrapper(transport)
                cy = bench.read_timer(transport) - overhead
                if loop_count > 1:
                    cy = cy / loop_count
                results.append(cy)
            cy_min = min(results)
            spread = max(results) - cy_min
            rows.append((tgt["name"], cy_min, spread, tgt["notes"]))

        mgr.release(inst)
    return rows


# ---------------------------------------------------------------------------
# U64 driver
# ---------------------------------------------------------------------------

def _run_u64(samples, profile, sweep_targets):
    labels = Labels.from_file(DEFAULT_BUILD_LBL)
    rows = []
    mgr = create_manager(backend="u64")
    inner = getattr(mgr, "_manager", None)
    if inner is not None and hasattr(inner, "_lock_timeout"):
        inner._lock_timeout = 1800.0
    with mgr:
        with mgr.instance() as target:
            transport = target.transport
            client = transport._client
            client.WRITE_MEM_QUERY_THRESHOLD = 128
            client.reset()
            time.sleep(2.0)
            # Belt-and-braces — see project memory: U64E turbo state
            # survives client.reset() and CIA timer reads ~1/N at N MHz.
            set_turbo_mhz(client, 1)
            _ = wait_for_text(transport, "READY", timeout=30.0)
            with open(DEFAULT_BUILD_PRG, "rb") as f:
                prg = f.read()
            load_addr = prg[0] | (prg[1] << 8)
            write_bytes(transport, load_addr, prg[2:])
            keyboard.send_text(transport, "RUN\r")
            time.sleep(2.0)
            _ = wait_for_text(transport, "READY", timeout=30.0)

            bench.install_wrapper(transport)
            calib_samples = 20
            overhead, calib_spread = bench._u64_calibrate(
                target, samples=calib_samples
            )
            bench._u64_verify_wrapper(
                target, overhead, calib_spread, calib_samples
            )

            for tgt in sweep_targets:
                if tgt.get("profile_b_only") and profile != "B":
                    rows.append(
                        (tgt["name"], None, None, "skipped (profile A)")
                    )
                    continue
                n_samples = 1 if tgt.get("single_shot") else samples
                if tgt.get("small_routine"):
                    n_samples = max(n_samples, samples * 10)
                loop_count = tgt.get("loop_count", 1)
                try:
                    raw_addr = tgt["u64_setup"](target, labels)
                except KeyError as exc:
                    rows.append(
                        (tgt["name"], None, None,
                         f"n/a (not emitted: missing label {exc})")
                    )
                    continue
                if isinstance(raw_addr, tuple):
                    addr, loop_count = raw_addr
                else:
                    addr = raw_addr
                psetup = tgt.get("per_sample_setup_u64")
                bench.patch_target(transport, addr)
                results = []
                for _ in range(n_samples):
                    if psetup is not None:
                        psetup(target, labels)
                        bench.patch_target(transport, addr)
                    run_subroutine(
                        target, bench.LONG_WRAPPER_ADDR, timeout=600.0
                    )
                    cy = bench.read_timer(transport) - overhead
                    if loop_count > 1:
                        cy = cy / loop_count
                    results.append(cy)
                cy_min = min(results)
                spread = max(results) - cy_min
                rows.append((tgt["name"], cy_min, spread, tgt["notes"]))
    return rows


# ---------------------------------------------------------------------------
# Reporting + JSON I/O
# ---------------------------------------------------------------------------

def _prg_md5(path):
    try:
        with open(path, "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    except OSError:
        return "unknown"


def _git_commit_short():
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def _format_cycles(cy):
    if cy is None:
        return "skipped"
    if isinstance(cy, float) and cy != int(cy):
        return f"{cy:,.1f}"
    return f"{int(cy):,}"


def _render_markdown(payload):
    lines = []
    lines.append(f"# Granular per-function bench (HEAD `{payload['commit']}`)")
    lines.append("")
    lines.append(f"- **Commit**: `{payload['commit']}`")
    lines.append(f"- **Generated**: {payload['generated']}")
    lines.append(f"- **Backend**: {payload['backend']}")
    lines.append(f"- **Profile**: {payload['profile']}")
    lines.append(f"- **Samples**: {payload['samples']} "
                 "(min reported, except single-shot rows)")
    lines.append(f"- **PRG md5**: `{payload['prg_md5']}`")
    lines.append("- **Methodology**: chained CIA #1 Timer A+B 32-bit cycle "
                 "counter wrapper at $C080; SEI/save/CIA-arm/JSR/stop/restore/"
                 "CLI/RTS. min-of-N reduction; wrapper overhead subtracted "
                 "via the no-op (RTS) stub calibration; verified against a "
                 "501-cy LDX #100 / DEX / BNE / RTS stub. See "
                 "`tools/bench_granular.py` and `tools/benchmark_chacha20_"
                 "poly1305.py` for the wrapper bytes.")
    lines.append("")
    lines.append("| Symbol | Cycles | Spread | Notes |")
    lines.append("|--------|-------:|-------:|-------|")
    for row in payload["rows"]:
        cy = row["cycles"]
        spr = row["spread"]
        notes = row["notes"]
        cy_s = _format_cycles(cy)
        spr_s = "—" if spr is None else f"{int(spr):,}"
        lines.append(f"| `{row['name']}` | {cy_s} | {spr_s} | {notes} |")
    lines.append("")
    lines.append("Regenerate with: `make bench` (this report) or "
                 "`make bench-check` (diff against committed baseline).")
    lines.append("")
    return "\n".join(lines)


def _build_payload(rows, samples, backend, profile):
    return {
        "commit": _git_commit_short(),
        "generated": datetime.now(timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        ),
        "backend": backend,
        "profile": profile,
        "samples": samples,
        "prg_md5": _prg_md5(DEFAULT_BUILD_PRG),
        "rows": [
            {
                "name": name,
                "cycles": cycles,
                "spread": spread,
                "notes": notes,
            }
            for (name, cycles, spread, notes) in rows
        ],
    }


def _write_outputs(payload, md_path):
    json_path = md_path + ".json"
    os.makedirs(os.path.dirname(md_path) or ".", exist_ok=True)
    with open(md_path, "w") as f:
        f.write(_render_markdown(payload))
    with open(json_path, "w") as f:
        json.dump(payload, f, indent=2, sort_keys=True)
    print(f"Wrote {md_path}")
    print(f"Wrote {json_path}")


def _diff_against_baseline(payload, baseline_path, tolerance_pct,
                           md5_check=True):
    """Return (ok, lines) — ok is True if every row is within tolerance."""
    with open(baseline_path, "r") as f:
        baseline = json.load(f)
    base_rows = {r["name"]: r for r in baseline.get("rows", [])}
    lines = []
    lines.append(f"bench-check against {baseline_path}:")
    lines.append(f"  baseline commit:  {baseline.get('commit', '?')}  "
                 f"prg_md5: {baseline.get('prg_md5', '?')}")
    lines.append(f"  current  commit:  {payload['commit']}  "
                 f"prg_md5: {payload['prg_md5']}")
    lines.append(f"  tolerance: ±{tolerance_pct:.2f}%")
    fail_rows = []
    detail_lines = []
    for row in payload["rows"]:
        name = row["name"]
        cy = row["cycles"]
        base = base_rows.get(name)
        if base is None:
            detail_lines.append(
                f"  ?  {name:<32s} cur={_format_cycles(cy):>14s} "
                f"baseline=MISSING"
            )
            fail_rows.append(name)
            continue
        base_cy = base.get("cycles")
        if base_cy is None or cy is None:
            # If both are None (e.g. skipped on profile A) — OK
            if base_cy is None and cy is None:
                detail_lines.append(
                    f"  =  {name:<32s} cur=skipped baseline=skipped"
                )
                continue
            detail_lines.append(
                f"  !  {name:<32s} cur={_format_cycles(cy):>14s} "
                f"baseline={_format_cycles(base_cy):>14s}  "
                f"(presence mismatch)"
            )
            fail_rows.append(name)
            continue
        if base_cy == 0:
            drift_pct = 0.0 if cy == 0 else 100.0
        else:
            drift_pct = 100.0 * (cy - base_cy) / base_cy
        marker = "OK" if abs(drift_pct) <= tolerance_pct else "FAIL"
        sign = "+" if drift_pct >= 0 else ""
        detail_lines.append(
            f"  {marker:<4s} {name:<32s} "
            f"cur={_format_cycles(cy):>14s}  "
            f"baseline={_format_cycles(base_cy):>14s}  "
            f"Δ={sign}{drift_pct:+.3f}%"
        )
        if marker == "FAIL":
            fail_rows.append((name, base_cy, cy, drift_pct))
    lines += detail_lines
    if md5_check:
        cur_md5 = payload.get("prg_md5", "")
        base_md5 = baseline.get("prg_md5", "")
        if cur_md5 != base_md5:
            lines.append(
                f"  note: PRG md5 differs (cur={cur_md5} vs "
                f"baseline={base_md5}). Per-symbol cycle gate is the "
                f"hard check; md5 drift is logged but not a failure on "
                f"its own."
            )
    lines.append("")
    if fail_rows:
        lines.append(
            f"bench-check: FAIL ({len(fail_rows)} row(s) outside "
            f"±{tolerance_pct:.2f}%):"
        )
        for item in fail_rows:
            if isinstance(item, tuple):
                name, base_cy, cy, drift_pct = item
                lines.append(
                    f"  - {name}: baseline {_format_cycles(base_cy)} -> "
                    f"current {_format_cycles(cy)} "
                    f"(Δ={drift_pct:+.3f}%)"
                )
            else:
                lines.append(f"  - {name}: presence mismatch")
        return False, lines
    lines.append(
        f"bench-check: OK (all {len(payload['rows'])} rows within "
        f"±{tolerance_pct:.2f}%)"
    )
    return True, lines


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--samples", type=int, default=DEFAULT_SAMPLES,
                    help="samples per target (min reported)")
    ap.add_argument("--backend",
                    choices=("vice", "u64"),
                    default=os.environ.get("C64_BACKEND", "vice").lower())
    ap.add_argument("--profile",
                    choices=("A", "B"),
                    default="B",
                    help="profile the currently built PRG is from "
                         "(default B, which includes ct_mul_8x8)")
    ap.add_argument("--md",
                    default=os.path.join(PROJECT_ROOT, "docs",
                                         "BENCH_REPORT.md"),
                    help="path to markdown report (sidecar JSON: <path>.json)")
    ap.add_argument("--check",
                    default=None,
                    help="diff result against this baseline JSON; exit "
                         "non-zero on any drift >--tolerance")
    ap.add_argument("--tolerance", type=float, default=DEFAULT_TOLERANCE_PCT,
                    help=f"check tolerance %% (default {DEFAULT_TOLERANCE_PCT})")
    ap.add_argument("--no-write", action="store_true",
                    help="skip writing the markdown/JSON report (still "
                         "performs --check if requested)")
    args = ap.parse_args()

    if not os.path.exists(DEFAULT_BUILD_PRG):
        sys.exit(
            f"FATAL: {DEFAULT_BUILD_PRG} missing. Build the target profile "
            f"with `make profile-a` or `make profile-b` first."
        )

    print(f"Bench: backend={args.backend} profile={args.profile} "
          f"samples={args.samples}")
    print(f"  PRG: {DEFAULT_BUILD_PRG}  md5={_prg_md5(DEFAULT_BUILD_PRG)}")

    if args.backend == "u64":
        rows = _run_u64(args.samples, args.profile, BENCH_TARGETS)
    else:
        rows = _run_vice(args.samples, args.profile, BENCH_TARGETS)

    # Console summary
    print()
    print("=" * 78)
    print(f"{'symbol':<32s} {'cycles':>14s} {'spread':>10s}  notes")
    print("-" * 78)
    for name, cy, spr, notes in rows:
        cy_s = _format_cycles(cy)
        spr_s = "—" if spr is None else _format_cycles(spr)
        print(f"{name:<32s} {cy_s:>14s} {spr_s:>10s}  {notes}")
    print("=" * 78)

    payload = _build_payload(rows, args.samples, args.backend, args.profile)

    if not args.no_write:
        _write_outputs(payload, args.md)

    if args.check:
        ok, lines = _diff_against_baseline(
            payload, args.check, args.tolerance
        )
        print()
        print("\n".join(lines))
        if not ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
