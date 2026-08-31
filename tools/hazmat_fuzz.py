#!/usr/bin/env python3
"""hazmat_fuzz.py — adversarial differential fuzz vs pyca/cryptography hazmat.

Complements `tools/test_chacha20_poly1305.py` (RFC 8439 KATs + random
round-trips) and `tools/audit_cross_check.py` (15 000 uniformly random
vectors) with an *adversarial* corpus: the inputs are chosen to sit on
the arithmetic and length edges where a 6502 port is most likely to
diverge from the reference. The oracle is pyca `cryptography` hazmat
(`ChaCha20Poly1305`, `ChaCha20`, `Poly1305`) throughout; nothing here is
compared against a hand-rolled Python reference.

Case classes (every one is a hard pass/fail unless marked NOTE):

    chacha20_block     fixed/all-FF/ramp keys and nonces x block counters
                       {0, 1, 2, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFF,
                       0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF};
                       keystream AND the post-increment counter (32-bit
                       wrap, RFC 8439 state word 12) are both checked.
    chacha20_encrypt   multi-block streams that cross the byte / 16-bit /
                       24-bit / 32-bit counter carries, plus the length
                       grid {0, 1, 63, 64, 65, 255, 256, 257, 1024, 1025,
                       3840}; oracle is per-block so a 32-bit wrap is by
                       definition "wrap the low word only".
    poly1305           adversarial keys (r=0, r=all-FF pre-clamp, r at the
                       clamp fixed point, r=1, r=2, s=0/all-FF/2^127) x
                       all-FF / all-00 messages at 0..4000 bytes; messages
                       constructed so the accumulator lands at p-3..p+2
                       before the final reduction; every length 16k+0..15.
    aead_verify_tag    the constant-time compare entry called directly:
                       equal, single-bit differences at byte 0/7/15, all
                       different, zero-vs-zero.
    wrap guard         SPEC §14.1 entry domain, BOTH input buffers:
                       aead_data_ptr + aead_data_len <= $10000 and
                       aead_aad_ptr + aead_aad_len <= $10000. A fixed,
                       uncounted list of four accept cases (incl. both
                       exact-$10000 boundaries, data $FF00+$0100 and AAD
                       $FF01+$FF) and five reject cases, each reject case
                       run against BOTH entry points. Accept legs are
                       full KATs (ciphertext + tag); reject legs poison
                       first and then assert the tag output, a 256-byte
                       sentinel across the front of the data buffer,
                       aead_scratch, and the key/nonce inputs are all
                       untouched, plus the documented A=$01 status.
                       aead_scratch is the load-bearing witness for the
                       AAD legs, whose walker only reads.
    aead               encrypt + decrypt over the length grid pt in
                       {0..3840 edges} x aad in {0..255 edges}, with the
                       tag read from BOTH the documented output symbol
                       `aead_tag` (docs/API.md) and the internal
                       `poly1305_tag`; each must equal the hazmat tag.
    aead tamper        for every third case and every case with pt<=64:
                       tag bit flips (bytes 0/7/15), ct bit flips (first /
                       last / middle byte), aad bit flips (first / last),
                       aad length +-1, all-zero tag, wrong key, wrong
                       nonce. Each must be rejected (A != 0) AND leave the
                       ciphertext buffer byte-for-byte intact.
    residue            NOTE only: what a failed decrypt leaves in RAM
                       (correct tag in `poly1305_tag`, OTK keystream in
                       `cc20_keystream`). Printed, never asserted.

The harness is deterministic given `--seed`; every mismatch is printed
with the full inputs and both outputs, and the exit status is non-zero
if any mismatch occurred. Logs go to stdout only.

Runs against the per-profile build directory `build/profile-<a|b>/`
(`make profile-a` / `make profile-b` first, or just `make test-fuzz`).
Backend defaults to VICE; set `C64_BACKEND=u64 U64_HOST=...` for
Ultimate 64 hardware (see README "Test/audit/bench backends").

Usage:
    make profile-a profile-b
    python3 tools/hazmat_fuzz.py --profile a --quick      # ~1-2 min on VICE
    python3 tools/hazmat_fuzz.py --profile b --seed 1234  # full corpus
"""
import argparse
import json
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
PRG_NAME = "c64_chacha20_poly1305.prg"
LABELS_NAME = "labels.txt"
VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc7539_vectors.json")

# Scratch RAM: $C000-$CFFF is free of the PRG ($0801-$9xxx), the sqtab
# ($8000-$83FF, Profile B), the Shoup tables ($6000-$7FFF, Profile A) and
# the harness trampolines ($0334 / $0360). AAD at $C000 (<= 255 bytes),
# data at $C100 (<= 3840 bytes).
AAD_BUF = 0xC000
DATA_BUF = 0xC100
DATA_MAX = 0xD000 - DATA_BUF   # 3840

# poly1305_update takes an 8-bit length in cc20_remain; feed multiples of
# 16 up to 240 per call, as audit_cross_check.py does.
POLY_CHUNK = 240

# Full corpus (default) vs --quick. Explicit --n-* flags override either.
FULL_COUNTS = {"aead": 130, "poly": 200, "block": 60, "enc": 30}
QUICK_COUNTS = {"aead": 70, "poly": 120, "block": 30, "enc": 16}

REQUIRED_LABELS = [
    "chacha20_init", "chacha20_block", "chacha20_encrypt",
    "cc20_key", "cc20_nonce", "cc20_counter", "cc20_state", "cc20_keystream",
    "cc20_data_ptr", "cc20_remain", "cc20_remain_hi",
    "poly1305_init", "poly1305_update", "poly1305_final",
    "poly_r", "poly_s", "poly1305_tag",
    "aead_encrypt", "aead_decrypt", "aead_verify_tag",
    "aead_key", "aead_nonce", "aead_aad_ptr", "aead_aad_len",
    "aead_data_ptr", "aead_data_len", "aead_tag", "aead_scratch",
    "zp_ptr1",
]

FAILS = []


def _fmt(v):
    if isinstance(v, (bytes, bytearray)):
        if len(v) <= 96:
            return v.hex()
        return f"{v[:48].hex()}...{v[-16:].hex()} (len={len(v)})"
    return v


def fail(kind, **kw):
    FAILS.append((kind, kw))
    print(f"  MISMATCH [{kind}]")
    for k, v in kw.items():
        print(f"      {k}: {_fmt(v)}")


# ---------------------------------------------------------------------------
# pyca oracles
# ---------------------------------------------------------------------------

def hz_block(key, counter, nonce):
    """64 bytes of ChaCha20 keystream at (counter, nonce)."""
    full_nonce = counter.to_bytes(4, "little") + nonce
    enc = _PycaCipher(_pyca_algs.ChaCha20(key, full_nonce), mode=None).encryptor()
    return enc.update(b"\x00" * 64) + enc.finalize()


def hz_stream_wrap(key, counter, nonce, data):
    """Per-block oracle so a 32-bit counter wrap is by definition 'wrap the
    low word only' (RFC 8439 state word 12 is 32-bit). pyca's own streaming
    ChaCha20 carries into the nonce on wrap, which is NOT the RFC model."""
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = hz_block(key, (counter + i // 64) & 0xFFFFFFFF, nonce)
        out += bytes(a ^ b for a, b in zip(data[i:i + 64], ks))
    return bytes(out)


def hz_poly(key, msg):
    mac = _PycaPoly1305(key)
    mac.update(msg)
    return mac.finalize()


def hz_aead(key, nonce, aad, pt):
    ct = _PycaChaCha20Poly1305(key).encrypt(nonce, pt, aad if aad else None)
    return ct[:-16], ct[-16:]


# ---------------------------------------------------------------------------
# C64 glue
# ---------------------------------------------------------------------------

class C64:
    def __init__(self, target, labels):
        self.target = target
        self.t = target.transport
        self.L = labels
        self.calls = 0

    def w(self, addr, data):
        write_bytes(self.t, addr, bytes(data))

    def r(self, addr, n):
        return read_bytes(self.t, addr, n)

    def call(self, name, timeout=600.0):
        self.calls += 1
        return run_subroutine(self.target, self.L[name], timeout=timeout)

    def ptr(self, name, addr):
        self.w(self.L[name], struct.pack("<H", addr))

    # -- chacha20
    def chacha_init(self, key, nonce, counter):
        self.w(self.L["cc20_key"], key)
        self.w(self.L["cc20_nonce"], nonce)
        self.w(self.L["cc20_counter"], counter.to_bytes(4, "little"))
        self.call("chacha20_init")

    def chacha_block(self):
        self.call("chacha20_block")
        return self.r(self.L["cc20_keystream"], 64)

    def counter_after(self):
        return int.from_bytes(self.r(self.L["cc20_state"] + 48, 4), "little")

    def chacha_encrypt(self, key, nonce, counter, data):
        self.chacha_init(key, nonce, counter)
        if data:
            self.w(DATA_BUF, data)
        self.ptr("cc20_data_ptr", DATA_BUF)
        self.w(self.L["cc20_remain"], [len(data) & 0xFF])
        self.w(self.L["cc20_remain_hi"], [len(data) >> 8])
        self.call("chacha20_encrypt")
        return self.r(DATA_BUF, len(data)) if data else b"", self.counter_after()

    # -- poly1305
    def poly_mac(self, key, msg):
        self.w(self.L["poly_r"], key[:16])
        self.w(self.L["poly_s"], key[16:])
        self.call("poly1305_init")
        pos = 0
        while pos < len(msg):
            n = min(POLY_CHUNK, len(msg) - pos)
            self.w(DATA_BUF, msg[pos:pos + n])
            self.ptr("zp_ptr1", DATA_BUF)
            self.w(self.L["cc20_remain"], [n])
            self.call("poly1305_update")
            pos += n
        self.call("poly1305_final")
        return self.r(self.L["poly1305_tag"], 16)

    # -- AEAD
    def aead_setup(self, key, nonce, aad, data):
        self.w(self.L["aead_key"], key)
        self.w(self.L["aead_nonce"], nonce)
        if aad:
            self.w(AAD_BUF, aad)
        self.ptr("aead_aad_ptr", AAD_BUF)
        self.w(self.L["aead_aad_len"], [len(aad)])
        if data:
            self.w(DATA_BUF, data)
        self.ptr("aead_data_ptr", DATA_BUF)
        self.w(self.L["aead_data_len"], struct.pack("<H", len(data)))

    def aead_encrypt(self, key, nonce, aad, pt):
        """Returns (ct, poly1305_tag, aead_tag). `aead_tag` is poisoned
        before the call so a library that never writes it is caught."""
        self.aead_setup(key, nonce, aad, pt)
        self.w(self.L["aead_tag"], b"\xEE" * 16)
        self.call("aead_encrypt")
        ct = self.r(DATA_BUF, len(pt)) if pt else b""
        return ct, self.r(self.L["poly1305_tag"], 16), self.r(self.L["aead_tag"], 16)

    def aead_decrypt(self, key, nonce, aad, ct, tag):
        """Returns (status, buffer_after, poly1305_tag)."""
        self.aead_setup(key, nonce, aad, ct)
        self.w(self.L["aead_tag"], tag)
        # poison poly1305_tag to observe what the failure path leaves there
        self.w(self.L["poly1305_tag"], b"\xDD" * 16)
        status = self.call("aead_decrypt")
        buf = self.r(DATA_BUF, len(ct)) if ct else b""
        return status, buf, self.r(self.L["poly1305_tag"], 16)


# ---------------------------------------------------------------------------
# case generators + test classes
# ---------------------------------------------------------------------------

def rb(rng, n):
    return bytes(rng.getrandbits(8) for _ in range(n))


BLOCK_COUNTERS = [0, 1, 2, 0xFF, 0x100, 0xFFFF, 0x10000, 0xFFFFFF, 0x7FFFFFFF,
                  0x80000000, 0xFFFFFFFE, 0xFFFFFFFF]


def t_chacha_block(c, rng, n):
    print(f"\n[chacha20_block] {n} cases (keystream + 32-bit counter post-increment)")
    keys = [bytes(32), b"\xff" * 32, bytes(range(32))]
    nonces = [bytes(12), b"\xff" * 12]
    cases = [(k, nn, ct) for k in keys for nn in nonces for ct in (0, 1, 0xFFFFFFFF)]
    for ct in BLOCK_COUNTERS:
        cases.append((rb(rng, 32), rb(rng, 12), ct))
    while len(cases) < n:
        cases.append((rb(rng, 32), rb(rng, 12), rng.getrandbits(32)))
    cases = cases[:n]
    ok = 0
    for key, nonce, ctr in cases:
        c.chacha_init(key, nonce, ctr)
        got = c.chacha_block()
        exp = hz_block(key, ctr, nonce)
        got_ctr = c.counter_after()
        exp_ctr = (ctr + 1) & 0xFFFFFFFF
        if got == exp and got_ctr == exp_ctr:
            ok += 1
        else:
            fail("chacha20_block", key=key, nonce=nonce, counter=ctr, ours=got,
                 hazmat=exp, ours_ctr_after=got_ctr, exp_ctr_after=exp_ctr)
    print(f"  {ok}/{len(cases)} match")
    return ok, len(cases)


def t_chacha_encrypt(c, rng, n):
    print(f"\n[chacha20_encrypt] {n} cases (incl. byte/16-bit/24-bit/32-bit counter carries)")
    cases = []
    for ln in (65, 128, 130, 200):
        cases.append((rb(rng, 32), rb(rng, 12), 0xFFFFFFFF, rb(rng, ln)))
    cases.append((rb(rng, 32), rb(rng, 12), 0xFFFFFFFE, rb(rng, 200)))
    cases.append((rb(rng, 32), rb(rng, 12), 0xFFFF, rb(rng, 130)))
    cases.append((rb(rng, 32), rb(rng, 12), 0xFF, rb(rng, 130)))
    cases.append((rb(rng, 32), rb(rng, 12), 0xFFFFFF, rb(rng, 130)))
    for ln in (0, 1, 63, 64, 65, 255, 256, 257, 1024, 1025, DATA_MAX):
        cases.append((rb(rng, 32), rb(rng, 12), 1, rb(rng, ln)))
    while len(cases) < n:
        cases.append((rb(rng, 32), rb(rng, 12), rng.getrandbits(32),
                      rb(rng, rng.randint(0, 600))))
    cases = cases[:n]
    ok = 0
    for key, nonce, ctr, data in cases:
        got, got_ctr = c.chacha_encrypt(key, nonce, ctr, data)
        exp = hz_stream_wrap(key, ctr, nonce, data)
        exp_ctr = (ctr + (len(data) + 63) // 64) & 0xFFFFFFFF
        if got == exp and got_ctr == exp_ctr:
            ok += 1
        else:
            fail("chacha20_encrypt", key=key, nonce=nonce, counter=ctr,
                 length=len(data), data=data, ours=got, hazmat=exp,
                 ours_ctr_after=got_ctr, exp_ctr_after=exp_ctr)
    print(f"  {ok}/{len(cases)} match")
    return ok, len(cases)


def poly_edge_cases(rng):
    """Adversarial (name, key, msg) triples."""
    cases = []
    r_max = b"\xff" * 16                                          # pre-clamp all FF
    r_cmax = bytes.fromhex("fffffff0fcfffff0fcfffff0fcfffff0")     # clamp fixed point
    s_ff = b"\xff" * 16
    keys = {
        "zero": bytes(32),
        "r0_sff": bytes(16) + s_ff,
        "rFF_s0": r_max + bytes(16),
        "rFF_sFF": r_max + s_ff,
        "rclampmax_sFF": r_cmax + s_ff,
        "r1_s0": b"\x01" + bytes(15) + bytes(16),
        "r1_sFF": b"\x01" + bytes(15) + s_ff,
        "r1_s_2^127": b"\x01" + bytes(15) + bytes(15) + b"\x80",
    }
    msgs = {
        "empty": b"",
        "1xFF": b"\xff",
        "15xFF": b"\xff" * 15,
        "16xFF": b"\xff" * 16,
        "17xFF": b"\xff" * 17,
        "32xFF": b"\xff" * 32,
        "64x00": bytes(64),
        "255xFF": b"\xff" * 255,
        "256xFF": b"\xff" * 256,
        "1024xFF": b"\xff" * 1024,
        "4000xFF": b"\xff" * 4000,
    }
    for kn, k in keys.items():
        for mn, m in msgs.items():
            cases.append((f"{kn}/{mn}", k, m))
    # Accumulator exactly around p before the final reduction: with r=1,
    # h = n1 + n2 (mod p), n1 = 2^129-1 (16 x FF), n2 = 2^128 + m2; choose
    # h_pre = p-3 .. p+2.
    for k in range(-2, 4):
        m2 = (1 << 128) - 4 + k
        if 0 <= m2 < (1 << 128):
            msg = b"\xff" * 16 + m2.to_bytes(16, "little")
            for sname, s in (("s0", bytes(16)), ("sFF", s_ff), ("srand", rb(rng, 16))):
                cases.append((f"h=p{k - 1:+d}/r=1/{sname}", b"\x01" + bytes(15) + s, msg))
    # r=2: push h just above p via doubling.
    for k in range(3):
        m2 = (1 << 128) - 4 + k
        msg = b"\xff" * 16 + m2.to_bytes(16, "little")
        cases.append((f"r=2/near-p/{k}", b"\x02" + bytes(15) + s_ff, msg))
    # Every residue 16k + 0..15 around the chunk boundaries.
    for base in (0, 16, 32, 240, 256):
        for extra in range(16):
            ln = base + extra
            cases.append((f"len={ln}", rb(rng, 32), rb(rng, ln)))
    return cases


def t_poly(c, rng, n):
    cases = poly_edge_cases(rng)
    while len(cases) < n:
        ln = rng.choice([rng.randint(0, 64), rng.randint(0, 300), rng.randint(0, 2048)])
        cases.append((f"rand/len={ln}", rb(rng, 32), rb(rng, ln)))
    cases = cases[:n]
    print(f"\n[poly1305 init/update/final] {len(cases)} cases (adversarial keys, near-p states)")
    ok = 0
    for name, key, msg in cases:
        got = c.poly_mac(key, msg)
        exp = hz_poly(key, msg)
        if got == exp:
            ok += 1
        else:
            fail("poly1305", case=name, key=key, msg=msg, ours=got, hazmat=exp)
    print(f"  {ok}/{len(cases)} match")
    return ok, len(cases)


PT_EDGE = [0, 1, 2, 15, 16, 17, 31, 32, 33, 47, 48, 49, 63, 64, 65, 79, 80, 81,
           95, 96, 97, 111, 112, 113, 127, 128, 129, 191, 192, 193, 255, 256, 257,
           511, 512, 513, 1023, 1024, 1025, 1500, 2047, 2048, 2049, DATA_MAX]
AAD_EDGE = [0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 254, 255]


def aead_cases(rng, n):
    cases = []
    for pl in PT_EDGE:
        cases.append((rng.choice(AAD_EDGE), pl))
    for al in AAD_EDGE:
        for pl in (0, 1, 16, 64, 65, 257):
            cases.append((al, pl))
    while len(cases) < n:
        cases.append((rng.choice(AAD_EDGE + [rng.randint(0, 255)]),
                      rng.choice(PT_EDGE + [rng.randint(0, DATA_MAX)])))
    return cases[:n]


def tamper_variants(aad, ct, tag, al, pl):
    variants = []
    for bi, bit in ((0, 0x01), (15, 0x80), (7, 0x10)):
        tg = bytearray(tag)
        tg[bi] ^= bit
        variants.append((f"tag[{bi}]^{bit:02x}", aad, ct, bytes(tg)))
    if pl:
        for bi, bit in ((0, 0x01), (pl - 1, 0x80), (pl // 2, 0x08)):
            cm = bytearray(ct)
            cm[bi] ^= bit
            variants.append((f"ct[{bi}]^{bit:02x}", aad, bytes(cm), tag))
    if al:
        for bi, bit in ((0, 0x01), (al - 1, 0x80)):
            am = bytearray(aad)
            am[bi] ^= bit
            variants.append((f"aad[{bi}]^{bit:02x}", bytes(am), ct, tag))
    if al < 255:
        variants.append(("aad_len+1", aad + b"\x00", ct, tag))
    else:
        variants.append(("aad_len-1", aad[:-1], ct, tag))
    variants.append(("zero-tag", aad, ct, bytes(16)))
    return variants


def t_aead(c, rng, n, tamper_every=3):
    cases = aead_cases(rng, n)
    print(f"\n[aead_encrypt/decrypt] {len(cases)} cases "
          f"(tamper set on every {tamper_every}rd + all pt<=64)")
    ok = tot = 0
    aead_tag_ok = poly_tag_ok = 0
    tamper_ok = tamper_tot = 0
    fixed_keys = [bytes(32), b"\xff" * 32]
    fixed_nonces = [bytes(12), b"\xff" * 12]
    for i, (al, pl) in enumerate(cases):
        if i < 4:
            key, nonce = fixed_keys[i % 2], fixed_nonces[(i // 2) % 2]
        else:
            key, nonce = rb(rng, 32), rb(rng, 12)
        aad, pt = rb(rng, al), rb(rng, pl)
        exp_ct, exp_tag = hz_aead(key, nonce, aad, pt)

        # --- encrypt: ciphertext, documented tag output, internal tag
        tot += 1
        got_ct, got_ptag, got_atag = c.aead_encrypt(key, nonce, aad, pt)
        if got_atag == exp_tag:
            aead_tag_ok += 1
        else:
            fail("aead_encrypt/aead_tag", aad_len=al, pt_len=pl, key=key, nonce=nonce,
                 ours_aead_tag=got_atag, hazmat_tag=exp_tag,
                 note="docs/API.md: aead_tag is the documented encrypt output")
        if got_ptag == exp_tag:
            poly_tag_ok += 1
        if got_ct == exp_ct and got_ptag == exp_tag:
            ok += 1
        else:
            fail("aead_encrypt", aad_len=al, pt_len=pl, key=key, nonce=nonce, aad=aad,
                 pt=pt, ours_ct=got_ct, hazmat_ct=exp_ct, ours_poly1305_tag=got_ptag,
                 hazmat_tag=exp_tag)
            continue

        # --- decrypt (valid)
        tot += 1
        st, got_pt, _ = c.aead_decrypt(key, nonce, aad, exp_ct, exp_tag)
        if st == 0 and got_pt == pt:
            ok += 1
        else:
            fail("aead_decrypt-valid", aad_len=al, pt_len=pl, key=key, nonce=nonce,
                 aad=aad, ct=exp_ct, tag=exp_tag, status=st, ours_pt=got_pt,
                 expected_pt=pt)

        # --- tamper set: must reject AND leave the buffer intact
        if i % tamper_every == 0 or pl <= 64:
            for vname, a2, c2, t2 in tamper_variants(aad, exp_ct, exp_tag, al, pl):
                tamper_tot += 1
                st, buf_after, _ = c.aead_decrypt(key, nonce, a2, c2, t2)
                if st != 0 and buf_after == c2:
                    tamper_ok += 1
                else:
                    fail("aead_decrypt-tamper", variant=vname, aad_len=len(a2),
                         pt_len=pl, key=key, nonce=nonce, aad=a2, ct=c2, tag=t2,
                         status=st, buffer_changed=(buf_after != c2),
                         buffer_after=buf_after)
            for vname, k2, n2 in (
                ("wrong-key", bytes([key[0] ^ 1]) + key[1:], nonce),
                ("wrong-nonce", key, nonce[:11] + bytes([nonce[11] ^ 0x80])),
            ):
                tamper_tot += 1
                st, buf_after, _ = c.aead_decrypt(k2, n2, aad, exp_ct, exp_tag)
                if st != 0 and buf_after == exp_ct:
                    tamper_ok += 1
                else:
                    fail("aead_decrypt-tamper", variant=vname, key=k2, nonce=n2,
                         aad=aad, ct=exp_ct, tag=exp_tag, status=st,
                         buffer_changed=(buf_after != exp_ct))
        if (i + 1) % 25 == 0:
            print(f"  [{i + 1}/{len(cases)}] aead ok={ok}/{tot} "
                  f"aead_tag ok={aead_tag_ok}/{i + 1} tamper ok={tamper_ok}/{tamper_tot}")
    print(f"  encrypt+decrypt (ct + poly1305_tag): {ok}/{tot} match")
    print(f"  aead_tag (documented output) == hazmat tag: {aead_tag_ok}/{len(cases)}")
    print(f"  poly1305_tag (internal)      == hazmat tag: {poly_tag_ok}/{len(cases)}")
    print(f"  tamper rejected + buffer intact: {tamper_ok}/{tamper_tot}")
    return {"encdec_ok": ok, "encdec_total": tot,
            "aead_tag_ok": aead_tag_ok, "poly1305_tag_ok": poly_tag_ok,
            "cases": len(cases), "tamper_ok": tamper_ok, "tamper_total": tamper_tot}


def t_verify_tag(c, rng):
    print("\n[aead_verify_tag] direct constant-time compare entry")
    ok = tot = 0
    base = rb(rng, 16)
    variants = [("equal", base, base, True)]
    for bi in (0, 7, 15):
        for bit in (0x01, 0x80):
            o = bytearray(base)
            o[bi] ^= bit
            variants.append((f"diff[{bi}]^{bit:02x}", base, bytes(o), False))
    variants.append(("all-diff", base, bytes(x ^ 0xFF for x in base), False))
    variants.append(("zero-vs-zero", bytes(16), bytes(16), True))
    for name, computed, provided, want_equal in variants:
        tot += 1
        c.w(c.L["poly1305_tag"], computed)
        c.w(c.L["aead_tag"], provided)
        st = c.call("aead_verify_tag")
        if (st == 0) == want_equal:
            ok += 1
        else:
            fail("aead_verify_tag", variant=name, computed=computed, provided=provided,
                 status=st)
    print(f"  {ok}/{tot} correct status")
    return ok, tot


# ---------------------------------------------------------------------------
# SPEC 14.1 domain guards: ptr + len <= $10000, for BOTH input buffers
# ---------------------------------------------------------------------------
# FIXED, UNCOUNTED case lists. Deliberately not part of t_aead's corpus and
# deliberately without a QUICK_COUNTS entry: the counted generators slice
# `cases[:n]`, so a counted edge-case list would be silently eaten in quick
# mode. Deliberately not in tools/test_chacha20_poly1305.py either -- that
# runner reports an empty group as OK, so a case list that silently emptied
# would read green.

AEAD_OK = 0x00
AEAD_ERR_DOMAIN = 0x01
AEAD_ERR_AUTH = 0xFF

# --- data buffer: 16-bit length, so every shape is reachable.
# ptr + len == $10000 is the last LEGAL value (buffer ends exactly at $FFFF).
WRAP_ACCEPT = [(0xC100, 0x0001), (0xFF00, 0x0100)]
# One past the boundary; a 16-bit-wrapping length; and a case whose high
# bytes alone ($09 + $FF) do not tell you the answer.
WRAP_REJECT = [(0xFF00, 0x0101), (0xFF00, 0xFFFF), (0x0900, 0xFFFF)]

# --- AAD: aead_aad_len is ONE BYTE, which constrains the case list.
# $0100 cannot be written to an 8-bit field, so the data path's
# "one past the boundary" shape is spelled ($FF02, $FF) here; and no
# low-pointer case can violate the relation at all, since ptr_hi must be
# $FF for ptr + len to reach $10000 with len <= $FF. The reachable
# violation set is exactly {ptr in $FF02..$FFFF}.
WRAP_ACCEPT_AAD = [(0xC000, 0x08), (0xFF01, 0xFF)]
WRAP_REJECT_AAD = [(0xFF02, 0xFF), (0xFFFF, 0xFF)]

SENTINEL = 0xA5
SENTINEL_LEN = 256          # window at the FRONT of the buffer: a guard
                            # placed after the ChaCha20 loop has started
                            # clobbers the front first.
POISON_TAG = b"\xEE" * 16
POISON_SCRATCH = b"\x5A" * 16
POISON_PTAG = b"\xDB" * 16


def _pad16(b):
    return b"\x00" * ((-len(b)) % 16)


def _rfc7539_tag(key, nonce, aad, ct_as_cpu_reads_it):
    """The RFC 7539 2.8 tag, built from the same pyca oracles hz_aead uses
    but with the Poly1305 message spelled out, so it can be evaluated over
    bytes that differ from `hz_aead`'s own ciphertext. Needed at $FF00,
    where the CPU reads ROM and writes RAM (see _wrap_probe_ffxx)."""
    otk = hz_block(key, 0, nonce)[:32]
    m = ct_as_cpu_reads_it
    msg = (aad + _pad16(aad) + m + _pad16(m)
           + struct.pack("<QQ", len(aad), len(m)))
    return hz_poly(otk, msg)


def _wrap_setup(c, key, nonce, data_ptr, data_len, aad_ptr, aad_len):
    """Populate the AEAD inputs with EXPLICIT (ptr, len) pairs for both
    buffers, and without touching either buffer's contents -- c.aead_setup()
    always points at DATA_BUF/AAD_BUF and always writes the data, neither of
    which works here."""
    c.w(c.L["aead_key"], key)
    c.w(c.L["aead_nonce"], nonce)
    c.ptr("aead_aad_ptr", aad_ptr)
    c.w(c.L["aead_aad_len"], [aad_len])
    c.ptr("aead_data_ptr", data_ptr)
    c.w(c.L["aead_data_len"], struct.pack("<H", data_len))


def _wrap_probe_ffxx(c, rng):
    """Establish what $FF00-$FFFF actually is before asserting over it.

    That window is RAM underneath KERNAL ROM. With $01 = $37 (the power-on
    value, which this library never changes) CPU *writes* land in RAM but
    CPU *reads* come from ROM, while the harness's own reads go through the
    monitor / DMA and normally see RAM. So `hz_aead` does NOT model an AEAD
    call whose DATA buffer is in that window, and a sentinel written there
    is only observable if harness reads really do see RAM. Both facts are
    measured, not assumed.

    Method: run chacha20_encrypt over the window twice with two different
    keystreams ks1, ks2 and read back out1, out2.

        CPU reads ROM (R), harness reads RAM: out1=R^ks1, out2=R^ks2
                                              -> out1^out2 == ks1^ks2
        CPU reads RAM:                        out2 = out1^ks2
                                              -> out1^out2 == ks2
        harness reads ROM:                    out1 == out2
                                              -> out1^out2 == 0

    Returns (mode, cpu_view) where mode is "cpu_rom" / "cpu_ram" /
    "opaque" and cpu_view is the 256 bytes the CPU reads at $FF00 (only
    meaningful for "cpu_rom")."""
    def stream(key, nonce, ctr):
        c.chacha_init(key, nonce, ctr)
        c.ptr("cc20_data_ptr", 0xFF00)
        c.w(c.L["cc20_remain"], [0x00])
        c.w(c.L["cc20_remain_hi"], [0x01])
        c.call("chacha20_encrypt")
        return c.r(0xFF00, 256)

    k1, n1 = rb(rng, 32), rb(rng, 12)
    k2, n2 = rb(rng, 32), rb(rng, 12)
    ks1 = hz_stream_wrap(k1, 1, n1, bytes(256))
    ks2 = hz_stream_wrap(k2, 1, n2, bytes(256))
    out1 = stream(k1, n1, 1)
    out2 = stream(k2, n2, 1)
    delta = bytes(a ^ b for a, b in zip(out1, out2))
    if delta == bytes(a ^ b for a, b in zip(ks1, ks2)):
        return "cpu_rom", bytes(a ^ b for a, b in zip(out1, ks1))
    if delta == ks2:
        return "cpu_ram", None
    return "opaque", None


def _wrap_accept_data(c, rng, ptr, length, mode, cpu_view):
    """Accept leg for the DATA relation. Full KAT -- ciphertext AND tag,
    every byte -- so that a guard which silently truncates the length to
    some ceiling fails here instead of passing a status-only check."""
    key, nonce, aad = rb(rng, 32), rb(rng, 12), rb(rng, 7)
    label = f"accept data ptr=${ptr:04X} len=${length:04X}"
    c.w(AAD_BUF, aad)

    if ptr + length <= 0xE000 or mode == "cpu_ram":
        # Plain RAM: the buffer the harness writes is the buffer the CPU
        # reads, so hz_aead models the call exactly.
        c.w(ptr, rb(rng, length))
        pt = c.r(ptr, length)
        exp_ct, exp_tag = hz_aead(key, nonce, aad, pt)
    elif mode == "cpu_rom":
        # $FF00-$FFFF: the CPU reads KERNAL ROM and writes the RAM
        # underneath. Every ChaCha20 read and every Poly1305 read of the
        # data buffer therefore sees `cpu_view`, including the read-back
        # inside aead_compute_tag AFTER the ciphertext has been written.
        # So the expected RAM contents are cpu_view ^ keystream, and the
        # expected tag is over cpu_view -- NOT over the ciphertext. This
        # is still a full-content KAT against pyca; it is just not
        # expressible as a call to hz_aead().
        exp_ct = hz_stream_wrap(key, 1, nonce, cpu_view)
        exp_tag = _rfc7539_tag(key, nonce, aad, cpu_view)
    else:
        exp_ct = exp_tag = None

    _wrap_setup(c, key, nonce, ptr, length, AAD_BUF, len(aad))
    c.w(c.L["aead_tag"], POISON_TAG)
    st = c.call("aead_encrypt")
    got_ct = c.r(ptr, length)
    got_tag = c.r(c.L["aead_tag"], 16)

    checks = [("status", st == AEAD_OK)]
    if exp_ct is None:
        print(f"  NOTE {label}: $FF00 window is opaque to the harness "
              f"(mode={mode}); content NOT verified, status only")
        checks.append(("tag-written", got_tag != POISON_TAG))
    else:
        checks.append(("ciphertext", got_ct == exp_ct))
        checks.append(("tag", got_tag == exp_tag))

    # aead_decrypt must accept the same boundary. In cpu_rom mode the tag
    # recomputes over the same ROM bytes, so a valid tag still verifies.
    _wrap_setup(c, key, nonce, ptr, length, AAD_BUF, len(aad))
    c.w(c.L["aead_tag"], got_tag)
    st_d = c.call("aead_decrypt")
    checks.append(("decrypt-status", st_d == AEAD_OK))

    bad = [n for n, good in checks if not good]
    if bad:
        fail("wrap_guard-accept", case=label, failed=",".join(bad),
             mode=mode, status=st, decrypt_status=st_d,
             ours_ct=got_ct, expected_ct=exp_ct,
             ours_tag=got_tag, expected_tag=exp_tag,
             key=key, nonce=nonce, aad=aad)
    return len(checks) - len(bad), len(checks), 0, 0


def _wrap_accept_aad(c, rng, aad_ptr, aad_len, mode, cpu_view):
    """Accept leg for the AAD relation. The data buffer stays in ordinary
    RAM, so even at the $FF01 boundary -- where the AAD itself is read from
    KERNAL ROM -- this is a plain hz_aead KAT: the bytes the CPU reads as
    AAD are cpu_view[1:], which is exactly what we hand the oracle."""
    key, nonce = rb(rng, 32), rb(rng, 12)
    label = f"accept aad ptr=${aad_ptr:04X} len=${aad_len:02X}"
    data_len = 96
    c.w(DATA_BUF, rb(rng, data_len))
    pt = c.r(DATA_BUF, data_len)

    if aad_ptr + aad_len <= 0xE000 or mode == "cpu_ram":
        c.w(aad_ptr, rb(rng, aad_len))
        aad = c.r(aad_ptr, aad_len)
    elif mode == "cpu_rom":
        off = aad_ptr - 0xFF00
        aad = cpu_view[off:off + aad_len]
    else:
        aad = None

    _wrap_setup(c, key, nonce, DATA_BUF, data_len, aad_ptr, aad_len)
    c.w(c.L["aead_tag"], POISON_TAG)
    st = c.call("aead_encrypt")
    got_ct = c.r(DATA_BUF, data_len)
    got_tag = c.r(c.L["aead_tag"], 16)

    checks = [("status", st == AEAD_OK)]
    if aad is None:
        print(f"  NOTE {label}: AAD window opaque to the harness "
              f"(mode={mode}); content NOT verified, status only")
        checks.append(("tag-written", got_tag != POISON_TAG))
        exp_ct = exp_tag = None
    else:
        exp_ct, exp_tag = hz_aead(key, nonce, aad, pt)
        checks.append(("ciphertext", got_ct == exp_ct))
        checks.append(("tag", got_tag == exp_tag))

    bad = [n for n, good in checks if not good]
    if bad:
        fail("wrap_guard-accept-aad", case=label, failed=",".join(bad),
             mode=mode, status=st, ours_ct=got_ct, expected_ct=exp_ct,
             ours_tag=got_tag, expected_tag=exp_tag, key=key, nonce=nonce,
             aad=aad)
    return len(checks) - len(bad), len(checks), 0, 0


def _wrap_reject(c, rng, entry, mode, *, data=None, aad=None):
    """Reject leg, for either relation. Poison first, then check.

    ASSERTION CLASSIFICATION. Not every check here can fail, and saying so
    matters: a passing count that silently includes unfalsifiable checks
    reassures without carrying the information it appears to carry, which
    is the defect this whole change is about. Each check below is tagged
    DISCRIMINATING (it can fail if the guard is removed, on this entry
    point) or TRIPWIRE (it cannot currently fail, and is retained only to
    catch a future regression). Tripwires are counted and reported
    SEPARATELY so they never inflate the headline number.

      status                  DISCRIMINATING on both entries. Without the
                              guard the call returns $00 or $ff, not $01.

      aead_scratch-untouched  DISCRIMINATING on both entries.
                              aead_compute_tag copies the AAD into
                              aead_scratch and both entry points reach it,
                              so it is the earliest observable evidence the
                              call proceeded. Execution confirms it fires
                              on all four AAD legs. On the decrypt legs it
                              and poly1305_tag are the two memory
                              witnesses -- the front sentinel cannot fire
                              there (see below), so between them they are
                              what makes those legs discriminate at all.

      poly1305_tag-untouched  DISCRIMINATING on both entries. poly1305_final
                              writes it (poly1305_lib.s:1278) and both
                              entries reach it via aead_compute_tag. This
                              is also the only test anywhere of the
                              docs/API.md claim that a rejected call leaves
                              poly1305_tag alone.

      aead_tag-untouched      DISCRIMINATING on aead_encrypt only, where the
                              publish loop writes it. aead_decrypt NEVER
                              writes aead_tag -- it only reads it to verify
                              -- so the check is vacuous by construction
                              there and is NOT run on decrypt legs.

      front-sentinel          DISCRIMINATING on aead_encrypt (the ChaCha20
                              loop writes the buffer). TRIPWIRE on
                              aead_decrypt for a structural reason: decrypt
                              verifies BEFORE it decrypts, so an
                              out-of-domain call without the guard computes
                              a tag over wrapped memory, mismatches, and
                              never reaches the write. It cannot fire there
                              no matter what the fixture does -- and this is
                              not fixable by a better fixture, because an
                              out-of-domain input has no computable valid
                              tag: the reference cannot express what the CPU
                              would read across the wrap.

      key/nonce-unchanged     TRIPWIRE on both entries. The library contains
                              no `sta aead_key` or `sta aead_nonce` on any
                              path, so these cannot fail today. Kept because
                              clobbering a caller's input buffer is a real
                              regression class and this is the natural place
                              to notice it.
    """
    key, nonce = rb(rng, 32), rb(rng, 12)
    data_ptr, data_len = data if data else (DATA_BUF, 64)
    aad_ptr, aad_len = aad if aad else (AAD_BUF, 8)
    which = "data" if data else "aad"
    label = (f"reject {which} {entry} "
             f"data=(${data_ptr:04X},${data_len:04X}) "
             f"aad=(${aad_ptr:04X},${aad_len:02X})")
    window_observable = data_ptr < 0xE000 or mode in ("cpu_ram", "cpu_rom")
    encrypting = entry == "aead_encrypt"

    # $0900 holds live code (lib_entry + the CODE/LIB_..._CODE alignment
    # fill); $FF00 holds RAM under the KERNAL vectors. Save and restore
    # either way -- the guard must not write, but a BROKEN guard would,
    # and the next case should not inherit the damage.
    saved = c.r(data_ptr, SENTINEL_LEN)
    c.w(data_ptr, bytes([SENTINEL]) * SENTINEL_LEN)

    _wrap_setup(c, key, nonce, data_ptr, data_len, aad_ptr, aad_len)
    c.w(c.L["aead_tag"], POISON_TAG)
    c.w(c.L["aead_scratch"], POISON_SCRATCH)
    c.w(c.L["poly1305_tag"], POISON_PTAG)
    st = c.call(entry)

    got_front = c.r(data_ptr, SENTINEL_LEN)
    got_tag = c.r(c.L["aead_tag"], 16)
    got_scratch = c.r(c.L["aead_scratch"], 16)
    got_ptag = c.r(c.L["poly1305_tag"], 16)
    got_key = c.r(c.L["aead_key"], 32)
    got_nonce = c.r(c.L["aead_nonce"], 12)
    c.w(data_ptr, saved)

    intact = bytes([SENTINEL]) * SENTINEL_LEN
    # (name, passed, is_discriminating)
    checks = [
        ("status", st == AEAD_ERR_DOMAIN, True),
        ("aead_scratch-untouched", got_scratch == POISON_SCRATCH, True),
        ("poly1305_tag-untouched", got_ptag == POISON_PTAG, True),
    ]
    if encrypting:
        # Vacuous on decrypt: that entry point never writes aead_tag.
        checks.append(("aead_tag-untouched", got_tag == POISON_TAG, True))
    if window_observable:
        checks.append(("front-sentinel", got_front == intact, encrypting))
    else:
        print(f"  NOTE {label}: buffer window opaque to the harness "
              f"(mode={mode}); sentinel NOT checked")
    checks.append(("key-unchanged", got_key == key, False))
    checks.append(("nonce-unchanged", got_nonce == nonce, False))

    bad = [n for n, good, _ in checks if not good]
    if bad:
        fail("wrap_guard-reject", case=label, failed=",".join(bad), mode=mode,
             status=st, expected_status=AEAD_ERR_DOMAIN, ours_tag=got_tag,
             ours_scratch=got_scratch, ours_poly1305_tag=got_ptag,
             front_changed=(got_front != intact),
             front_after=got_front, key_changed=(got_key != key),
             nonce_changed=(got_nonce != nonce))
    disc = [(n, g) for n, g, d in checks if d]
    trip = [(n, g) for n, g, d in checks if not d]
    return (sum(1 for _, g in disc if g), len(disc),
            sum(1 for _, g in trip if g), len(trip))


def t_wrap_guard(c, rng):
    """SPEC 14.1 entry guards: ptr + len <= $10000 for both input buffers."""
    print("\n[wrap guard] 14.1 domain: data and AAD, ptr + len <= $10000")

    # Host-side self-check of the _rfc7539_tag model used by the $FF00 data
    # leg, against hz_aead on a case where both are valid. If this ever
    # fails, that KAT is measuring the model, not the library.
    _k, _n, _a, _p = rb(rng, 32), rb(rng, 12), rb(rng, 7), rb(rng, 133)
    _ct, _tag = hz_aead(_k, _n, _a, _p)
    if (hz_stream_wrap(_k, 1, _n, _p), _rfc7539_tag(_k, _n, _a, _ct)) != (_ct, _tag):
        fail("wrap_guard-model", note="_rfc7539_tag does not reproduce hz_aead")
        return {"discriminating_ok": 0, "discriminating_total": 1,
                "tripwire_ok": 0, "tripwire_total": 0}

    ok = tot = trip_ok = trip_tot = 0

    def add(r):
        nonlocal ok, tot, trip_ok, trip_tot
        d_ok, d_tot, t_ok, t_tot = r
        ok += d_ok; tot += d_tot; trip_ok += t_ok; trip_tot += t_tot

    # 1. Ordinary in-domain calls, plain RAM. Full KATs.
    add(_wrap_accept_data(c, rng, *WRAP_ACCEPT[0], "cpu_ram", None))
    add(_wrap_accept_aad(c, rng, *WRAP_ACCEPT_AAD[0], "cpu_ram", None))

    # 2. What is $FF00-$FFFF on this machine? Needed by 3, 4 and 5.
    mode, cpu_view = _wrap_probe_ffxx(c, rng)
    desc = {"cpu_rom": "CPU reads ROM / writes the RAM underneath",
            "cpu_ram": "plain RAM",
            "opaque": "not observable by the harness"}[mode]
    print(f"  $FF00 window: mode={mode} ({desc})")

    # 3. Reject legs, both relations, both entry points. These write
    #    nothing, so they are safe to run before the accept legs below.
    for ptr, length in WRAP_REJECT:
        for entry in ("aead_encrypt", "aead_decrypt"):
            add(_wrap_reject(c, rng, entry, mode, data=(ptr, length)))
    for ptr, length in WRAP_REJECT_AAD:
        for entry in ("aead_encrypt", "aead_decrypt"):
            add(_wrap_reject(c, rng, entry, mode, aad=(ptr, length)))

    # 4. The AAD boundary at $FF01 + $FF == $10000. Reads KERNAL ROM but
    #    writes nothing there, so it is safe ahead of the data boundary.
    add(_wrap_accept_aad(c, rng, *WRAP_ACCEPT_AAD[1], mode, cpu_view))

    # 5. LAST: the data boundary at $FF00 + $0100 == $10000. This one
    #    genuinely writes 256 bytes of RAM beneath the KERNAL vectors.
    #    Harmless while ROM is banked in ($01 = $37, which this library
    #    never changes) but it does not survive a reset, so it runs last
    #    and its ciphertext is read back before anything else runs.
    add(_wrap_accept_data(c, rng, *WRAP_ACCEPT[1], mode, cpu_view))

    n_accept = len(WRAP_ACCEPT) + len(WRAP_ACCEPT_AAD)
    n_reject = len(WRAP_REJECT) + len(WRAP_REJECT_AAD)
    print(f"  {ok}/{tot} DISCRIMINATING assertions hold "
          f"({n_accept} accept, {n_reject} reject x 2 entries)")
    print(f"  {trip_ok}/{trip_tot} TRIPWIRE assertions hold — reported "
          f"separately because they CANNOT currently fail, so they are not "
          f"evidence the guards work:")
    print(f"      key/nonce-unchanged: the library has no `sta aead_key` or "
          f"`sta aead_nonce` on any path.")
    print(f"      front-sentinel on decrypt legs: aead_decrypt verifies "
          f"before it decrypts, so an out-of-domain call mismatches and "
          f"never reaches the write.")
    return {"discriminating_ok": ok, "discriminating_total": tot,
            "tripwire_ok": trip_ok, "tripwire_total": trip_tot}



def t_decrypt_fail_residue(c, rng):
    """NOTE only: what does the failure path leave behind in RAM?"""
    print("\n[aead_decrypt failure residue] (NOTE — reported, not asserted)")
    key, nonce, aad, pt = rb(rng, 32), rb(rng, 12), rb(rng, 8), rb(rng, 40)
    ct, tag = hz_aead(key, nonce, aad, pt)
    bad = bytearray(tag)
    bad[0] ^= 1
    st, buf, ptag = c.aead_decrypt(key, nonce, aad, ct, bytes(bad))
    ks = c.r(c.L["cc20_keystream"], 64)
    otk = hz_block(key, 0, nonce)
    print(f"  status={st:#x} buffer==ct:{buf == ct} "
          f"poly1305_tag==correct_tag:{ptag == tag} "
          f"cc20_keystream==OTK block(counter 0):{ks == otk}")
    return {"status": st, "buf_intact": buf == ct,
            "tag_resident": ptag == tag, "otk_resident": ks == otk}


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Adversarial differential fuzz vs pyca/cryptography hazmat")
    ap.add_argument("--profile", choices=["a", "b"], required=True,
                    help="Run against build/profile-<a|b>/ (pre-built via "
                         "`make profile-a` / `make profile-b`)")
    ap.add_argument("--seed", type=int, default=20260828,
                    help="PRNG seed for deterministic case generation "
                         "(default 20260828)")
    ap.add_argument("--quick", action="store_true",
                    help=f"Reduced corpus, ~1-2 min per profile on VICE "
                         f"({QUICK_COUNTS}); default is the full corpus "
                         f"({FULL_COUNTS})")
    ap.add_argument("--n-aead", type=int, default=None, help="Override AEAD case count")
    ap.add_argument("--n-poly", type=int, default=None, help="Override Poly1305 case count")
    ap.add_argument("--n-block", type=int, default=None, help="Override chacha20_block case count")
    ap.add_argument("--n-enc", type=int, default=None, help="Override chacha20_encrypt case count")
    args = ap.parse_args()

    counts = dict(QUICK_COUNTS if args.quick else FULL_COUNTS)
    for k in counts:
        v = getattr(args, f"n_{k}")
        if v is not None:
            counts[k] = v

    pdir = os.path.join(PROJECT_ROOT, "build", f"profile-{args.profile}")
    prg_path = os.path.join(pdir, PRG_NAME)
    labels_path = os.path.join(pdir, LABELS_NAME)
    if not os.path.exists(prg_path):
        print(f"FATAL: {prg_path} not found.")
        print(f"Pre-build the target profile first: make profile-{args.profile}")
        sys.exit(1)

    labels = Labels.from_file(labels_path)
    missing = [n for n in REQUIRED_LABELS if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing in {labels_path}: {missing}")
        sys.exit(1)

    rng = random.Random(args.seed)
    mode = "quick" if args.quick else "full"
    print("=" * 64)
    print(f"hazmat_fuzz.py — profile {args.profile} ({mode})")
    print(f"PRG:    {prg_path}")
    print(f"labels: {labels_path} ({len(REQUIRED_LABELS)} required labels verified)")
    print(f"seed:   {args.seed} (reproduce with --seed {args.seed})")
    print(f"counts: {counts}")
    print("=" * 64)

    config = ViceConfig(
        prg_path=prg_path,
        warp=True,
        ntsc=True,
        sound=False,
        # macOS-26 + VICE 3.10 hangs in kernal IEC busy-wait under the
        # default VirtualFS autostart (mode 0); RAM-injection (mode 1)
        # bypasses the IEC path and boots cleanly.
        extra_args=["-autostartprgmode", "1"],
    )

    backend = os.environ.get("C64_BACKEND", "vice").lower()

    t0 = time.time()
    summary = {}
    with create_manager(backend=backend, vice_config=config) as mgr:
        inst = mgr.acquire()
        print(f"Backend={mgr.backend} PID={inst.pid}")

        if inst.backend == "u64":
            # UnifiedManager.acquire() does not auto-load a PRG on the U64
            # backend. Side-load via PUT writemem and drive `RUN` through
            # the keyboard buffer, exactly as test_chacha20_poly1305.py.
            client = inst.transport.client
            client.WRITE_MEM_QUERY_THRESHOLD = 128
            client.reset()
            from c64_test_harness.backends.ultimate64_helpers import set_turbo_mhz
            set_turbo_mhz(client, 1)
            time.sleep(2.0)
            if wait_for_text(inst.transport, "READY", timeout=30.0) is None:
                print("  warning: BASIC READY prompt not seen within 30s after reset")
            with open(prg_path, "rb") as f:
                prg = f.read()
            load_addr = prg[0] | (prg[1] << 8)
            write_bytes(inst.transport, load_addr, prg[2:])
            keyboard.send_text(inst.transport, "RUN\r")
            time.sleep(2.0)
            if wait_for_text(inst.transport, "READY", timeout=30.0) is None:
                print("  warning: BASIC READY prompt not seen within 30s after RUN")
            if hasattr(inst, "_u64_shim_state"):
                delattr(inst, "_u64_shim_state")
        else:
            # VICE: the library entry is a thin shell that RTSes back to
            # BASIC; give KERNAL a moment to finish autoload.
            time.sleep(2.0)

        c = C64(inst, labels)

        # Harness sanity: RFC 8439 §2.8.2 AEAD KAT through the same glue.
        with open(VECTORS_PATH) as f:
            vec = json.load(f)["aead_encrypt"][0]
        ct, ptag, _ = c.aead_encrypt(
            bytes.fromhex(vec["key"]), bytes.fromhex(vec["nonce"]),
            bytes.fromhex(vec["aad"]), bytes.fromhex(vec["plaintext"]))
        if ct != bytes.fromhex(vec["ciphertext"]) or ptag != bytes.fromhex(vec["tag"]):
            print("FATAL: RFC 8439 §2.8.2 KAT failed through the glue — harness broken?")
            mgr.release(inst)
            sys.exit(1)
        print("RFC 8439 §2.8.2 KAT ok (harness sanity)")

        summary["chacha20_block"] = t_chacha_block(c, rng, counts["block"])
        summary["chacha20_encrypt"] = t_chacha_encrypt(c, rng, counts["enc"])
        summary["poly1305"] = t_poly(c, rng, counts["poly"])
        summary["aead_verify_tag"] = t_verify_tag(c, rng)
        summary["wrap_guard"] = t_wrap_guard(c, rng)
        summary["aead"] = t_aead(c, rng, counts["aead"])
        summary["residue"] = t_decrypt_fail_residue(c, rng)
        mgr.release(inst)

    elapsed = time.time() - t0
    by_kind = {}
    for kind, _ in FAILS:
        by_kind[kind] = by_kind.get(kind, 0) + 1
    print(f"\n{'=' * 64}")
    print(f"profile {args.profile} ({mode}) seed {args.seed}: {c.calls} jsr calls, "
          f"{len(FAILS)} mismatches, {elapsed:.0f}s")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    if by_kind:
        print("  mismatches by kind: " + ", ".join(f"{k}={v}" for k, v in by_kind.items()))
    print(f"RESULT: {'FAIL' if FAILS else 'PASS'}")
    print("=" * 64)
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
