#!/usr/bin/env python3
"""audit_cross_check.py — deep AEAD-layer cross-check vs pyca/cryptography.

Written for the v0.3.0 deep-audit (sprint task #12). Extends the
Poly1305-only cross-checks from `tools/step7_cross_check.py` /
`tools/step12_cross_check.py` (10 000 tags each) to the **full AEAD
stack** (ChaCha20 keystream + Poly1305 tag + AEAD encrypt + AEAD
decrypt + AEAD decrypt-tamper-reject), totalling 15 000 random
vectors drawn from a deterministic seed.

Unlike the step-scoped scripts, this one exercises five categories:

    1. `chacha20_block` keystream ....................... 1 000 vectors
    2. `poly1305_init + poly1305_update + poly1305_final` 1 000 vectors
    3. `aead_encrypt` ciphertext + tag .................. 5 000 vectors
    4. `aead_decrypt` plaintext recovery ................ 5 000 vectors
    5. `aead_decrypt` tamper rejection .................. 3 000 vectors
                                                         ------
                                                          15 000

Vectors 3 and 4 share the same (key, nonce, aad, plaintext) tuples so
that every encrypt is decrypted, ensuring the decrypt path is a true
inverse. Vector category 5 re-uses the same tuples and single-bit-flips
either the ciphertext, the tag, or the AAD (uniform choice from the
rng); `aead_decrypt` must report tag-fail (A != 0) on **all 3 000**.

The script runs against whichever PRG is currently installed at
`build/c64_chacha20_poly1305.prg`. Caller selects profile by rebuilding
the project (`make profile-a` or `make profile-b`) *before* invoking
this script — the same pattern step7 / step12 use. The `--profile`
argument exists purely to tag the output log file and does not drive
the build.

Usage:
    make profile-a
    python3 tools/audit_cross_check.py --profile a --seed 20260413 \
        --log ~/.claude/tasks/c64-chacha20poly1305-port-sprint/audit_drafts/cross_check_results_profile_a.log

    make profile-b
    python3 tools/audit_cross_check.py --profile b --seed 20260413 \
        --log ~/.claude/tasks/c64-chacha20poly1305-port-sprint/audit_drafts/cross_check_results_profile_b.log

Optional arguments let smaller sample counts be used for local smoke
testing, but the audit verdict is defined against the full 15 000-vector
run.
"""
import argparse
import os
import random
import struct
import sys
import time

from cryptography.hazmat.primitives.ciphers import (
    Cipher as _PycaCipher,
    algorithms as _pyca_algs,
)
from cryptography.hazmat.primitives.ciphers.aead import (
    ChaCha20Poly1305 as _PycaChaCha20Poly1305,
)
from cryptography.hazmat.primitives.poly1305 import Poly1305 as _PycaPoly1305

from c64_test_harness import (
    Labels,
    ViceConfig,
    create_manager,
    keyboard,
    read_bytes,
    write_bytes,
    wait_for_text,
)

# Backend-agnostic JSR shim: VICE thin-wraps harness jsr(); U64 drives a
# trampoline + sentinel poll. Returns the post-JSR A register value.
from _u64_helpers import run_subroutine

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64_chacha20_poly1305.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")

# Scratch region used for plaintext / ciphertext / AAD staging. Matches
# test_chacha20_poly1305.py's SCRATCH_BUF convention ($C000..$CFFF).
SCRATCH_BUF = 0xC000
# poly1305_update's cc20_remain is 8-bit, so max chunk ≤ 255. Use the
# same 240-byte multiple-of-16 chunk size as step7/step12.
POLY_CHUNK = 240
# AEAD data/AAD buffers are bounded by plaintext length ≤ 1024, so the
# 4 KiB scratch region comfortably holds an aad (≤255) + a gap + the
# full plaintext without overlap.
MAX_AAD_LEN = 255
MAX_PT_LEN = 1024


# ---------------------------------------------------------------------------
# Helpers: write 16-bit LE pointer; batch-log writer
# ---------------------------------------------------------------------------

def write_ptr(transport, addr, target):
    write_bytes(transport, addr, bytes([target & 0xFF, (target >> 8) & 0xFF]))


class LogWriter:
    """Tee stdout + optional log file, auto-flush every line."""

    def __init__(self, path=None):
        self.path = path
        self.fh = open(path, "w") if path else None

    def write(self, s):
        sys.stdout.write(s)
        sys.stdout.flush()
        if self.fh:
            self.fh.write(s)
            self.fh.flush()

    def line(self, s=""):
        self.write(s + "\n")

    def close(self):
        if self.fh:
            self.fh.close()


# ---------------------------------------------------------------------------
# pyca reference wrappers
# ---------------------------------------------------------------------------

def pyca_chacha20_keystream(key, counter, nonce):
    """Return exactly 64 bytes of ChaCha20 keystream at (counter, nonce)."""
    full_nonce = counter.to_bytes(4, "little") + nonce
    cipher = _PycaCipher(_pyca_algs.ChaCha20(key, full_nonce), mode=None)
    enc = cipher.encryptor()
    return enc.update(b"\x00" * 64) + enc.finalize()


def pyca_poly1305_tag(key, message):
    mac = _PycaPoly1305(key)
    mac.update(message)
    return mac.finalize()


def pyca_aead_encrypt(key, nonce, aad, plaintext):
    """Return (ciphertext, tag) split from pyca's concatenated output."""
    aead = _PycaChaCha20Poly1305(key)
    combined = aead.encrypt(nonce, plaintext, aad if aad else None)
    return combined[:-16], combined[-16:]


# ---------------------------------------------------------------------------
# C64 drivers (mirror test_chacha20_poly1305.py conventions)
# ---------------------------------------------------------------------------

def c64_chacha20_keystream(target, labels, key, nonce, counter):
    """Drive `chacha20_init` + `chacha20_block` and read 64 B keystream."""
    transport = target.transport
    write_bytes(transport, labels["cc20_key"], key)
    write_bytes(transport, labels["cc20_nonce"], nonce)
    write_bytes(transport, labels["cc20_counter"], counter.to_bytes(4, "little"))
    run_subroutine(target, labels["chacha20_init"], timeout=30.0)
    run_subroutine(target, labels["chacha20_block"], timeout=120.0)
    return bytes(read_bytes(transport, labels["cc20_keystream"], 64))


def c64_poly1305_mac(target, labels, key, message):
    """MAC an arbitrary-length message via init + (chunked) update + final."""
    transport = target.transport
    write_bytes(transport, labels["poly_r"], key[:16])
    write_bytes(transport, labels["poly_s"], key[16:])
    run_subroutine(target, labels["poly1305_init"], timeout=60.0)

    pos = 0
    n = len(message)
    while n - pos > POLY_CHUNK:
        chunk = message[pos:pos + POLY_CHUNK]
        write_bytes(transport, SCRATCH_BUF, chunk)
        write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
        write_bytes(transport, labels["cc20_remain"], bytes([len(chunk)]))
        run_subroutine(target, labels["poly1305_update"], timeout=240.0)
        pos += POLY_CHUNK

    tail = message[pos:]
    if tail:
        write_bytes(transport, SCRATCH_BUF, tail)
        write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
        write_bytes(transport, labels["cc20_remain"], bytes([len(tail)]))
        run_subroutine(target, labels["poly1305_update"], timeout=240.0)

    run_subroutine(target, labels["poly1305_final"], timeout=30.0)
    return bytes(read_bytes(transport, labels["poly1305_tag"], 16))


def _aead_setup_buffers(transport, labels, key, nonce, aad):
    """Write key/nonce/aad and return the (aad_buf, data_buf) staging addrs."""
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)
    aad_buf = SCRATCH_BUF
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_ptr(transport, labels["aead_aad_ptr"], aad_buf)
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))
    data_buf = aad_buf + max(len(aad), 1) + 16  # 16-byte gap between buffers
    return aad_buf, data_buf


def c64_aead_encrypt(target, labels, key, nonce, aad, plaintext):
    transport = target.transport
    _, data_buf = _aead_setup_buffers(transport, labels, key, nonce, aad)
    if plaintext:
        write_bytes(transport, data_buf, plaintext)
    write_ptr(transport, labels["aead_data_ptr"], data_buf)
    write_bytes(transport, labels["aead_data_len"],
                struct.pack("<H", len(plaintext)))
    run_subroutine(target, labels["aead_encrypt"], timeout=600.0)
    ct = bytes(read_bytes(transport, data_buf, len(plaintext)))
    tag = bytes(read_bytes(transport, labels["poly1305_tag"], 16))
    return ct, tag


def c64_aead_decrypt(target, labels, key, nonce, aad, ciphertext, tag):
    transport = target.transport
    _, data_buf = _aead_setup_buffers(transport, labels, key, nonce, aad)
    if ciphertext:
        write_bytes(transport, data_buf, ciphertext)
    write_ptr(transport, labels["aead_data_ptr"], data_buf)
    write_bytes(transport, labels["aead_data_len"],
                struct.pack("<H", len(ciphertext)))
    write_bytes(transport, labels["aead_tag"], tag)
    # aead_decrypt returns A=0 on success, A != 0 on auth failure.
    # run_subroutine returns that A byte directly on both VICE and U64.
    status = run_subroutine(target, labels["aead_decrypt"], timeout=600.0)
    pt = bytes(read_bytes(transport, data_buf, len(ciphertext)))
    return pt, status


# ---------------------------------------------------------------------------
# Vector generators
# ---------------------------------------------------------------------------

def rand_bytes(rng, n):
    return bytes(rng.randint(0, 255) for _ in range(n))


def gen_pt_len(rng):
    """Uniform in [0, 1024] with block-multiple boundaries oversampled.

    50% of vectors draw from the "boundary mix" — sizes that historically
    break ChaCha20 / Poly1305 tail handling (±1 around block multiples).
    The other 50% draw a uniform-random length in [0, 1024].
    """
    boundary_mix = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65,
                    127, 128, 129, 255, 256, 511, 512, 1023, 1024]
    if rng.random() < 0.5:
        return rng.choice(boundary_mix)
    return rng.randint(0, 1024)


def gen_aad_len(rng):
    """Uniform in [0, 255] with a bias toward 0 / small / boundary lengths."""
    boundary_mix = [0, 1, 15, 16, 17, 31, 32, 64, 128, 255]
    if rng.random() < 0.5:
        return rng.choice(boundary_mix)
    return rng.randint(0, 255)


# ---------------------------------------------------------------------------
# Category runners
# ---------------------------------------------------------------------------

def run_category_chacha20(target, labels, rng, count, log):
    log.line(f"\n[1/5] chacha20_block keystream: {count} vectors")
    t0 = time.time()
    passed = failed = 0
    first_fail = None
    for i in range(count):
        key = rand_bytes(rng, 32)
        nonce = rand_bytes(rng, 12)
        counter = rng.randint(0, 0xFFFFFFFF)

        expected = pyca_chacha20_keystream(key, counter, nonce)
        got = c64_chacha20_keystream(target, labels, key, nonce, counter)

        if got == expected:
            passed += 1
        else:
            failed += 1
            if first_fail is None:
                first_fail = (i, key, nonce, counter, expected, got)
            if failed >= 3:
                break

        if (i + 1) % 100 == 0:
            el = time.time() - t0
            log.line(f"  [{i+1}/{count}] pass={passed} fail={failed} "
                     f"elapsed={el:.1f}s")

    elapsed = time.time() - t0
    log.line(f"  result: {passed}/{count} pass, {failed} fail ({elapsed:.1f}s)")
    if first_fail:
        i, k, n, c, e, g = first_fail
        log.line(f"  FIRST FAIL vector #{i} counter={c}")
        log.line(f"    key:      {k.hex()}")
        log.line(f"    nonce:    {n.hex()}")
        log.line(f"    expected: {e.hex()}")
        log.line(f"    got:      {g.hex()}")
    return passed, failed, elapsed


def run_category_poly1305(target, labels, rng, count, log):
    log.line(f"\n[2/5] poly1305 tag: {count} vectors")
    t0 = time.time()
    passed = failed = 0
    first_fail = None
    for i in range(count):
        msg_len = gen_pt_len(rng)
        key = rand_bytes(rng, 32)
        msg = rand_bytes(rng, msg_len)

        expected = pyca_poly1305_tag(key, msg)
        got = c64_poly1305_mac(target, labels, key, msg)

        if got == expected:
            passed += 1
        else:
            failed += 1
            if first_fail is None:
                first_fail = (i, msg_len, key, msg, expected, got)
            if failed >= 3:
                break

        if (i + 1) % 100 == 0:
            el = time.time() - t0
            log.line(f"  [{i+1}/{count}] pass={passed} fail={failed} "
                     f"elapsed={el:.1f}s")

    elapsed = time.time() - t0
    log.line(f"  result: {passed}/{count} pass, {failed} fail ({elapsed:.1f}s)")
    if first_fail:
        i, L, k, m, e, g = first_fail
        log.line(f"  FIRST FAIL vector #{i} len={L}")
        log.line(f"    key:      {k.hex()}")
        log.line(f"    msg:      {m.hex()}")
        log.line(f"    expected: {e.hex()}")
        log.line(f"    got:      {g.hex()}")
    return passed, failed, elapsed


def run_category_aead(target, labels, rng, count, log):
    """Combined AEAD encrypt + decrypt cross-check.

    Each vector produces TWO checks (encrypt match and decrypt recovery),
    so the AEAD category's "count" argument covers both encrypt and
    decrypt in the total vector budget. Encrypted vectors are also saved
    into `decrypt_vectors` (returned) so the tamper-reject category can
    reuse them without re-running encrypt.
    """
    log.line(f"\n[3/5 + 4/5] aead_encrypt + aead_decrypt: {count} vectors "
             f"(= {count} encrypt + {count} decrypt)")
    t0 = time.time()
    enc_pass = enc_fail = 0
    dec_pass = dec_fail = 0
    first_enc_fail = None
    first_dec_fail = None
    decrypt_vectors = []  # list of (key, nonce, aad, pt, ct, tag)

    for i in range(count):
        pt_len = gen_pt_len(rng)
        aad_len = gen_aad_len(rng)
        key = rand_bytes(rng, 32)
        nonce = rand_bytes(rng, 12)
        aad = rand_bytes(rng, aad_len)
        pt = rand_bytes(rng, pt_len)

        exp_ct, exp_tag = pyca_aead_encrypt(key, nonce, aad, pt)

        got_ct, got_tag = c64_aead_encrypt(
            target, labels, key, nonce, aad, pt)
        if got_ct == exp_ct and got_tag == exp_tag:
            enc_pass += 1
        else:
            enc_fail += 1
            if first_enc_fail is None:
                first_enc_fail = (i, pt_len, aad_len, key, nonce, aad, pt,
                                  exp_ct, exp_tag, got_ct, got_tag)
            if enc_fail >= 3:
                break

        rec_pt, status = c64_aead_decrypt(
            target, labels, key, nonce, aad, exp_ct, exp_tag)
        if status == 0 and rec_pt == pt:
            dec_pass += 1
        else:
            dec_fail += 1
            if first_dec_fail is None:
                first_dec_fail = (i, pt_len, aad_len, key, nonce, aad, pt,
                                  exp_ct, exp_tag, rec_pt, status)
            if dec_fail >= 3:
                break

        decrypt_vectors.append((key, nonce, aad, pt, exp_ct, exp_tag))

        if (i + 1) % 50 == 0:
            el = time.time() - t0
            log.line(f"  [{i+1}/{count}] enc={enc_pass}/{enc_pass+enc_fail} "
                     f"dec={dec_pass}/{dec_pass+dec_fail} elapsed={el:.1f}s")

    elapsed = time.time() - t0
    log.line(f"  encrypt result: {enc_pass}/{count} pass, {enc_fail} fail")
    log.line(f"  decrypt result: {dec_pass}/{count} pass, {dec_fail} fail")
    log.line(f"  elapsed: {elapsed:.1f}s")
    if first_enc_fail:
        i, L, A, k, n, a, p, ec, et, gc, gt = first_enc_fail
        log.line(f"  FIRST ENCRYPT FAIL vector #{i} pt_len={L} aad_len={A}")
        log.line(f"    key:          {k.hex()}")
        log.line(f"    nonce:        {n.hex()}")
        log.line(f"    aad:          {a.hex()}")
        log.line(f"    pt:           {p.hex()}")
        log.line(f"    expected ct:  {ec.hex()}")
        log.line(f"    expected tag: {et.hex()}")
        log.line(f"    got ct:       {gc.hex()}")
        log.line(f"    got tag:      {gt.hex()}")
    if first_dec_fail:
        i, L, A, k, n, a, p, ec, et, rp, st = first_dec_fail
        log.line(f"  FIRST DECRYPT FAIL vector #{i} pt_len={L} aad_len={A} "
                 f"status=0x{st:02x}")
        log.line(f"    key:      {k.hex()}")
        log.line(f"    nonce:    {n.hex()}")
        log.line(f"    aad:      {a.hex()}")
        log.line(f"    exp pt:   {p.hex()}")
        log.line(f"    got pt:   {rp.hex()}")
    return enc_pass, enc_fail, dec_pass, dec_fail, elapsed, decrypt_vectors


def run_category_decrypt_tamper(target, labels, rng, decrypt_vectors,
                                count, log):
    """Flip a single bit in ciphertext, tag, or aad and expect auth-fail.

    For vectors where pt_len==0 we can't flip a ct bit (ct is empty), so
    we pick a tag/aad target instead. Similarly if aad is empty we skip
    the aad target and pick ct/tag. Choice is rng-driven but gracefully
    falls back to the non-empty targets.
    """
    log.line(f"\n[5/5] aead_decrypt tamper rejection: {count} vectors")
    t0 = time.time()
    passed = failed = 0
    first_fail = None

    # Cycle through the encrypted-vector pool if fewer than `count`.
    pool = decrypt_vectors
    if not pool:
        log.line("  SKIP: no encrypt vectors available (upstream failures)")
        return 0, count, 0.0

    for i in range(count):
        key, nonce, aad, pt, ct, tag = pool[i % len(pool)]

        # Decide which field to tamper. Preference order: ct, tag, aad.
        choices = []
        if len(ct) > 0:
            choices.append("ct")
        choices.append("tag")  # always 16 bytes, always flippable
        if len(aad) > 0:
            choices.append("aad")
        # Don't shadow the `target` parameter — pick a different local name.
        tamper_field = rng.choice(choices)

        if tamper_field == "ct":
            idx = rng.randint(0, len(ct) - 1)
            bit = 1 << rng.randint(0, 7)
            tampered_ct = bytes(b ^ bit if j == idx else b
                                for j, b in enumerate(ct))
            tampered_tag = tag
            tampered_aad = aad
        elif tamper_field == "tag":
            idx = rng.randint(0, 15)
            bit = 1 << rng.randint(0, 7)
            tampered_ct = ct
            tampered_tag = bytes(b ^ bit if j == idx else b
                                 for j, b in enumerate(tag))
            tampered_aad = aad
        else:  # aad
            idx = rng.randint(0, len(aad) - 1)
            bit = 1 << rng.randint(0, 7)
            tampered_ct = ct
            tampered_tag = tag
            tampered_aad = bytes(b ^ bit if j == idx else b
                                 for j, b in enumerate(aad))

        _, status = c64_aead_decrypt(
            target, labels, key, nonce, tampered_aad,
            tampered_ct, tampered_tag)

        # aead_decrypt returns A=0 on success, A != 0 on auth failure.
        if status != 0:
            passed += 1
        else:
            failed += 1
            if first_fail is None:
                first_fail = (i, tamper_field, idx, bit, key, nonce, aad, pt,
                              ct, tag, tampered_ct, tampered_tag, tampered_aad)
            if failed >= 3:
                break

        if (i + 1) % 100 == 0:
            el = time.time() - t0
            log.line(f"  [{i+1}/{count}] reject={passed} accept={failed} "
                     f"elapsed={el:.1f}s")

    elapsed = time.time() - t0
    log.line(f"  result: {passed}/{count} rejected, {failed} wrongly accepted "
             f"({elapsed:.1f}s)")
    if first_fail:
        i, tgt, idx, bit, k, n, a, p, ct, tag, tct, ttag, taad = first_fail
        log.line(f"  FIRST TAMPER-MISS vector #{i} target={tgt} idx={idx} "
                 f"bit=0x{bit:02x}")
        log.line(f"    key:       {k.hex()}")
        log.line(f"    nonce:     {n.hex()}")
        log.line(f"    orig aad:  {a.hex()}")
        log.line(f"    orig pt:   {p.hex()}")
        log.line(f"    orig ct:   {ct.hex()}")
        log.line(f"    orig tag:  {tag.hex()}")
        log.line(f"    t. aad:    {taad.hex()}")
        log.line(f"    t. ct:     {tct.hex()}")
        log.line(f"    t. tag:    {ttag.hex()}")
    return passed, failed, elapsed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True,
                    help="PRNG seed for deterministic vector generation")
    ap.add_argument("--profile", choices=["a", "b"], required=True,
                    help="Label the log file with profile a or b (caller "
                         "must rebuild the PRG for the desired profile "
                         "before invoking)")
    ap.add_argument("--log", type=str, default=None,
                    help="Optional log file (tee'd with stdout)")
    ap.add_argument("--cc20-count", type=int, default=1000,
                    help="Number of chacha20_block vectors (default 1000)")
    ap.add_argument("--poly-count", type=int, default=1000,
                    help="Number of poly1305 vectors (default 1000)")
    ap.add_argument("--aead-count", type=int, default=5000,
                    help="Number of AEAD encrypt+decrypt vector pairs "
                         "(default 5000; counts as 10 000 vectors toward "
                         "the 15 000 total)")
    ap.add_argument("--tamper-count", type=int, default=3000,
                    help="Number of tamper-rejection vectors (default 3000)")
    ap.add_argument("--vectors", type=int, default=None,
                    help="Total vector budget: scales the per-category "
                         "counts proportionally to the 1000:1000:5000:5000:"
                         "3000 default ratio. Useful for runtime budgeting "
                         "(e.g. --vectors 1000 on U64 hardware vs. the "
                         "implicit 15000 on VICE). Overrides per-category "
                         "flags; pass them explicitly to opt out.")
    args = ap.parse_args()

    if args.vectors is not None:
        # Proportionally scale per-category counts. The default ratio is
        # 1000:1000:5000:5000:3000 (cc20:poly:aead_enc:aead_dec:tamper),
        # and aead_count is counted twice (encrypt + decrypt), so total =
        # cc20 + poly + 2*aead + tamper. Solve for a scale factor s such
        # that s*(1000+1000+2*5000+3000) == args.vectors -> s = N/15000.
        scale = args.vectors / 15000.0
        args.cc20_count = max(1, int(round(1000 * scale)))
        args.poly_count = max(1, int(round(1000 * scale)))
        args.aead_count = max(1, int(round(5000 * scale)))
        args.tamper_count = max(1, int(round(3000 * scale)))

    log = LogWriter(args.log)
    try:
        rng = random.Random(args.seed)

        labels = Labels.from_file(LABELS_PATH)
        config = ViceConfig(
            prg_path=PRG_PATH,
            warp=True,
            ntsc=True,
            sound=False,
            # macOS-26 + VICE 3.10 hangs in kernal IEC busy-wait under the
            # default VirtualFS autostart (mode 0); RAM-injection (mode 1)
            # bypasses the IEC path and boots cleanly.
            extra_args=["-autostartprgmode", "1"],
        )

        total_vectors = (args.cc20_count + args.poly_count
                         + 2 * args.aead_count + args.tamper_count)
        log.line("=" * 64)
        log.line(f"audit_cross_check.py — profile {args.profile}")
        log.line(f"PRG:    {PRG_PATH}")
        log.line(f"labels: {LABELS_PATH}")
        log.line(f"seed:   {args.seed}")
        log.line(f"vectors: cc20={args.cc20_count} poly={args.poly_count} "
                 f"aead_pairs={args.aead_count} tamper={args.tamper_count}")
        log.line(f"         total = {total_vectors}")
        log.line("=" * 64)

        backend = os.environ.get("C64_BACKEND", "u64").lower()

        t0 = time.time()
        with create_manager(backend=backend, vice_config=config) as mgr:
            inst = mgr.acquire()

            # UnifiedManager.acquire() does not auto-load a PRG on the
            # U64 backend. Side-load via PUT writemem (avoiding the POST
            # endpoints that returned 'Could not read data from
            # attachment' on degraded U64E fw 3.14d state) and drive
            # `RUN` through the keyboard buffer to autostart.
            if inst.backend == "u64":
                client = inst.transport._client
                client.WRITE_MEM_QUERY_THRESHOLD = 128
                client.reset()
                # Belt-and-braces: client.reset() is a 6510 reset and does
                # NOT touch FPGA-level turbo. Leftover turbo from a sibling
                # agent's bench leaves the device at e.g. 48 MHz, which
                # this tool doesn't time-sensitive read directly but would
                # poison any subsequent bench reuse of the same locked
                # device. Force 1 MHz so the device is in a known state.
                from c64_test_harness.backends.ultimate64_helpers import (
                    set_turbo_mhz,
                )
                set_turbo_mhz(client, 1)
                time.sleep(2.0)
                grid = wait_for_text(inst.transport, "READY", timeout=30.0)
                if grid is None:
                    log.line("  warning: BASIC READY prompt not seen "
                             "within 30s after reset")
                with open(PRG_PATH, "rb") as f:
                    prg = f.read()
                load_addr = prg[0] | (prg[1] << 8)
                log.line(f"Sideloading PRG: load_addr=${load_addr:04X}, "
                         f"body={len(prg) - 2} bytes")
                t_load = time.time()
                write_bytes(inst.transport, load_addr, prg[2:])
                log.line(f"  sideload done in {time.time() - t_load:.1f}s")
                keyboard.send_text(inst.transport, "RUN\r")
                time.sleep(2.0)
                grid = wait_for_text(inst.transport, "READY", timeout=30.0)
                if grid is None:
                    log.line("  warning: BASIC READY prompt not seen "
                             "within 30s after RUN")
            else:
                time.sleep(1.5)  # KERNAL settle

            cc20_pass, cc20_fail, cc20_el = run_category_chacha20(
                inst, labels, rng, args.cc20_count, log)
            poly_pass, poly_fail, poly_el = run_category_poly1305(
                inst, labels, rng, args.poly_count, log)
            enc_pass, enc_fail, dec_pass, dec_fail, aead_el, dec_vecs = \
                run_category_aead(inst, labels, rng,
                                  args.aead_count, log)
            tamp_pass, tamp_fail, tamp_el = run_category_decrypt_tamper(
                inst, labels, rng, dec_vecs, args.tamper_count, log)

            mgr.release(inst)

        elapsed = time.time() - t0
        total_pass = cc20_pass + poly_pass + enc_pass + dec_pass + tamp_pass
        total_fail = cc20_fail + poly_fail + enc_fail + dec_fail + tamp_fail
        log.line("")
        log.line("=" * 64)
        log.line(f"SUMMARY — profile {args.profile} — seed {args.seed}")
        log.line("=" * 64)
        log.line(f"  chacha20 keystream : {cc20_pass}/{args.cc20_count} "
                 f"pass ({cc20_el:.1f}s)")
        log.line(f"  poly1305 tag       : {poly_pass}/{args.poly_count} "
                 f"pass ({poly_el:.1f}s)")
        log.line(f"  aead encrypt       : {enc_pass}/{args.aead_count} "
                 f"pass")
        log.line(f"  aead decrypt       : {dec_pass}/{args.aead_count} "
                 f"pass ({aead_el:.1f}s combined)")
        log.line(f"  aead tamper reject : {tamp_pass}/{args.tamper_count} "
                 f"pass ({tamp_el:.1f}s)")
        log.line(f"  TOTAL              : {total_pass}/{total_vectors} "
                 f"pass, {total_fail} fail")
        log.line(f"  wall time          : {elapsed:.1f}s")
        log.line("=" * 64)
        sys.exit(0 if total_fail == 0 else 1)
    finally:
        log.close()


if __name__ == "__main__":
    main()
