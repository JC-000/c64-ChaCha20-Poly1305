#!/usr/bin/env python3
"""test_chacha20_poly1305.py - Direct-memory ChaCha20-Poly1305 AEAD tests.

Exercises rotl32/rotr32 word primitives, ChaCha20 (quarter-round, block,
encrypt), Poly1305 (clamp, update, final), and AEAD (encrypt, decrypt) of
the c64-ChaCha20-Poly1305 library against RFC 7539 vectors and Python
reference implementations via jsr() calls.

Uses the current c64-test-harness API: ViceInstanceManager context manager
+ direct memory read/write + jsr(). All labels are loaded from
build/labels.txt; no memory addresses are hardcoded.

Usage:
    python3 tools/test_chacha20_poly1305.py [--seed S] [--verbose]
"""

import json
import os
import random
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

PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)
PRG_PATH = os.path.join(PROJECT_ROOT, "build", "c64_chacha20_poly1305.prg")
LABELS_PATH = os.path.join(PROJECT_ROOT, "build", "labels.txt")
VECTORS_PATH = os.path.join(PROJECT_ROOT, "test", "rfc7539_vectors.json")

# Scratch buffer for test inputs/outputs. $C000-$C3FF is free memory on the
# C64 (not used by BASIC, KERNAL, or the library PRG at $0810-$12bb). The
# library needs room for up to 114 + 16 bytes for the RFC AEAD vector.
SCRATCH_BUF = 0xC000
SCRATCH_LEN = 0x400

VERBOSE = False


# ============================================================================
# Python reference implementations
# ============================================================================

def rotl32(val, n):
    return ((val << n) | (val >> (32 - n))) & 0xFFFFFFFF


def rotr32(val, n):
    return ((val >> n) | (val << (32 - n))) & 0xFFFFFFFF


def chacha20_quarter_round_ref(state, a, b, c, d):
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] ^= state[a]
    state[d] = rotl32(state[d], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] ^= state[c]
    state[b] = rotl32(state[b], 7)


def chacha20_block_ref(key, counter, nonce):
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words = list(struct.unpack('<8I', key))
    nonce_words = list(struct.unpack('<3I', nonce))
    state = constants + key_words + [counter] + nonce_words
    working = list(state)
    for _ in range(10):
        chacha20_quarter_round_ref(working, 0, 4, 8, 12)
        chacha20_quarter_round_ref(working, 1, 5, 9, 13)
        chacha20_quarter_round_ref(working, 2, 6, 10, 14)
        chacha20_quarter_round_ref(working, 3, 7, 11, 15)
        chacha20_quarter_round_ref(working, 0, 5, 10, 15)
        chacha20_quarter_round_ref(working, 1, 6, 11, 12)
        chacha20_quarter_round_ref(working, 2, 7, 8, 13)
        chacha20_quarter_round_ref(working, 3, 4, 9, 14)
    result = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack('<16I', *result)


def chacha20_encrypt_ref(key, counter, nonce, plaintext):
    result = bytearray()
    for i in range(0, len(plaintext), 64):
        block = chacha20_block_ref(key, counter + i // 64, nonce)
        chunk = plaintext[i:i + 64]
        result.extend(b ^ k for b, k in zip(chunk, block))
    return bytes(result)


def poly1305_ref(key, message):
    r_bytes = bytearray(key[:16])
    s_bytes = key[16:]
    r_bytes[3] &= 0x0f
    r_bytes[7] &= 0x0f
    r_bytes[11] &= 0x0f
    r_bytes[15] &= 0x0f
    r_bytes[4] &= 0xfc
    r_bytes[8] &= 0xfc
    r_bytes[12] &= 0xfc
    r = int.from_bytes(r_bytes, 'little')
    s = int.from_bytes(s_bytes, 'little')
    p = (1 << 130) - 5
    h = 0
    for i in range(0, len(message), 16):
        block = message[i:i + 16]
        n = int.from_bytes(block, 'little')
        n += 1 << (8 * len(block))
        h = ((h + n) * r) % p
    h = (h + s) & ((1 << 128) - 1)
    return h.to_bytes(16, 'little')


def aead_encrypt_ref(key, nonce, aad, plaintext):
    otk = chacha20_block_ref(key, 0, nonce)[:32]
    ciphertext = chacha20_encrypt_ref(key, 1, nonce, plaintext)
    mac_data = bytearray()
    mac_data.extend(aad)
    if len(aad) % 16:
        mac_data.extend(b'\x00' * (16 - len(aad) % 16))
    mac_data.extend(ciphertext)
    if len(ciphertext) % 16:
        mac_data.extend(b'\x00' * (16 - len(ciphertext) % 16))
    mac_data.extend(struct.pack('<Q', len(aad)))
    mac_data.extend(struct.pack('<Q', len(ciphertext)))
    tag = poly1305_ref(otk, mac_data)
    return ciphertext, tag


# ============================================================================
# C64 helper functions
# ============================================================================

def write_ptr(transport, label_addr, target_addr):
    """Write a 16-bit little-endian pointer at label_addr."""
    write_bytes(transport, label_addr,
                bytes([target_addr & 0xFF, (target_addr >> 8) & 0xFF]))


def set_w32_dst(transport, labels, addr):
    write_ptr(transport, labels["w32_dst"], addr)


def c64_chacha20_init(transport, labels, key, nonce, counter=0):
    write_bytes(transport, labels["cc20_key"], key)
    write_bytes(transport, labels["cc20_nonce"], nonce)
    write_bytes(transport, labels["cc20_counter"],
                counter.to_bytes(4, 'little'))
    jsr(transport, labels["chacha20_init"], timeout=30.0)


def c64_chacha20_block(transport, labels):
    jsr(transport, labels["chacha20_block"], timeout=120.0)
    return read_bytes(transport, labels["cc20_keystream"], 64)


def c64_chacha20_encrypt(transport, labels, key, nonce, data, counter=1):
    c64_chacha20_init(transport, labels, key, nonce, counter)
    buf = SCRATCH_BUF
    write_bytes(transport, buf, data)
    write_ptr(transport, labels["cc20_data_ptr"], buf)
    # 16-bit length (cc20_remain low, cc20_remain_hi high)
    write_bytes(transport, labels["cc20_remain"], bytes([len(data) & 0xFF]))
    write_bytes(transport, labels["cc20_remain_hi"],
                bytes([(len(data) >> 8) & 0xFF]))
    jsr(transport, labels["chacha20_encrypt"], timeout=300.0)
    return read_bytes(transport, buf, len(data))


def c64_poly1305_init(transport, labels, otk):
    write_bytes(transport, labels["poly_r"], otk[:16])
    write_bytes(transport, labels["poly_s"], otk[16:])
    jsr(transport, labels["poly1305_init"], timeout=60.0)


def c64_poly1305_update(transport, labels, data, buf=SCRATCH_BUF):
    """Single-shot update — max 255 bytes (poly1305_update uses 8-bit count)."""
    if len(data) == 0:
        return
    assert len(data) <= 255, "poly1305_update cc20_remain is 8-bit"
    write_bytes(transport, buf, data)
    write_ptr(transport, labels["zp_ptr1"], buf)
    write_bytes(transport, labels["cc20_remain"], bytes([len(data)]))
    jsr(transport, labels["poly1305_update"], timeout=120.0)


def c64_poly1305_final(transport, labels):
    jsr(transport, labels["poly1305_final"], timeout=30.0)
    return read_bytes(transport, labels["poly1305_tag"], 16)


def c64_poly1305_mac(transport, labels, key, message):
    c64_poly1305_init(transport, labels, key)
    c64_poly1305_update(transport, labels, message)
    return c64_poly1305_final(transport, labels)


def c64_aead_encrypt(transport, labels, key, nonce, aad, plaintext):
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    aad_buf = SCRATCH_BUF
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_ptr(transport, labels["aead_aad_ptr"], aad_buf)
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))

    pt_buf = aad_buf + max(len(aad), 1) + 16  # keep a gap between buffers
    if plaintext:
        write_bytes(transport, pt_buf, plaintext)
    write_ptr(transport, labels["aead_data_ptr"], pt_buf)
    write_bytes(transport, labels["aead_data_len"],
                struct.pack('<H', len(plaintext)))

    jsr(transport, labels["aead_encrypt"], timeout=600.0)

    ct = read_bytes(transport, pt_buf, len(plaintext))
    tag = read_bytes(transport, labels["poly1305_tag"], 16)
    return ct, tag


def c64_aead_decrypt(transport, labels, key, nonce, aad, ciphertext, tag):
    write_bytes(transport, labels["aead_key"], key)
    write_bytes(transport, labels["aead_nonce"], nonce)

    aad_buf = SCRATCH_BUF
    if aad:
        write_bytes(transport, aad_buf, aad)
    write_ptr(transport, labels["aead_aad_ptr"], aad_buf)
    write_bytes(transport, labels["aead_aad_len"], bytes([len(aad)]))

    ct_buf = aad_buf + max(len(aad), 1) + 16
    if ciphertext:
        write_bytes(transport, ct_buf, ciphertext)
    write_ptr(transport, labels["aead_data_ptr"], ct_buf)
    write_bytes(transport, labels["aead_data_len"],
                struct.pack('<H', len(ciphertext)))
    write_bytes(transport, labels["aead_tag"], tag)

    jsr(transport, labels["aead_decrypt"], timeout=600.0)
    pt = read_bytes(transport, ct_buf, len(ciphertext))
    return pt, ct_buf


# ============================================================================
# Tests
# ============================================================================

def test_rotations(transport, labels):
    """Test rotl32_{4,7,8,12} and rotr32_{1,4,7,8,12,16}."""
    passed = failed = 0
    test_values = [0x12345678, 0x80000001, 0xDEADBEEF, 0x00000001,
                   0xFFFFFFFF, 0x01020304, 0xF0E0D0C0]
    rotl = [4, 7, 8, 12]
    rotr = [1, 4, 7, 8, 12, 16]
    scratch = SCRATCH_BUF

    for val in test_values:
        val_bytes = val.to_bytes(4, 'little')

        for n in rotl:
            label = f"rotl32_{n}"
            if labels.address(label) is None:
                continue
            write_bytes(transport, scratch, val_bytes)
            set_w32_dst(transport, labels, scratch)
            jsr(transport, labels[label], timeout=30.0)
            got = int.from_bytes(read_bytes(transport, scratch, 4), 'little')
            expected = rotl32(val, n)
            if got == expected:
                passed += 1
                if VERBOSE:
                    print(f"  PASS {label}: 0x{val:08X} -> 0x{expected:08X}")
            else:
                failed += 1
                print(f"  FAIL {label}: 0x{val:08X} got 0x{got:08X} "
                      f"want 0x{expected:08X}")

        for n in rotr:
            label = f"rotr32_{n}"
            if labels.address(label) is None:
                continue
            write_bytes(transport, scratch, val_bytes)
            set_w32_dst(transport, labels, scratch)
            jsr(transport, labels[label], timeout=30.0)
            got = int.from_bytes(read_bytes(transport, scratch, 4), 'little')
            expected = rotr32(val, n)
            if got == expected:
                passed += 1
                if VERBOSE:
                    print(f"  PASS {label}: 0x{val:08X} -> 0x{expected:08X}")
            else:
                failed += 1
                print(f"  FAIL {label}: 0x{val:08X} got 0x{got:08X} "
                      f"want 0x{expected:08X}")

    return passed, failed


def test_chacha20_quarter_round(transport, labels):
    """RFC 7539 §2.1.1: QR on isolated {a,b,c,d} = {0,1,2,3}."""
    passed = failed = 0
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)

    for vec in vectors["chacha20_quarter_round"]:
        for i, hex_val in enumerate(vec["input"]):
            val = int(hex_val, 16)
            write_bytes(transport, labels["cc20_work"] + i * 4,
                        val.to_bytes(4, 'little'))

        # The QR function indexes into cc20_qr_table via cc20_qr_idx.
        # Temporarily overwrite the first table entry with {0,1,2,3} so that
        # the routine operates on cc20_work words 0..3.
        orig_table = read_bytes(transport, labels["cc20_qr_table"], 4)
        write_bytes(transport, labels["cc20_qr_table"], bytes([0, 1, 2, 3]))
        write_bytes(transport, labels["cc20_qr_idx"], bytes([0]))

        jsr(transport, labels["chacha20_quarter_round"], timeout=30.0)

        write_bytes(transport, labels["cc20_qr_table"], orig_table)

        all_match = True
        for i, hex_val in enumerate(vec["expected"]):
            expected = int(hex_val, 16)
            got = int.from_bytes(
                read_bytes(transport, labels["cc20_work"] + i * 4, 4),
                'little',
            )
            if got != expected:
                all_match = False
                print(f"  FAIL QR word {i}: got 0x{got:08X}, "
                      f"expected 0x{expected:08X}")

        if all_match:
            passed += 1
            if VERBOSE:
                print(f"  PASS quarter-round: {vec['desc']}")
        else:
            failed += 1
    return passed, failed


def test_chacha20_block(transport, labels):
    passed = failed = 0
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)
    for vec in vectors["chacha20_block"]:
        key = bytes.fromhex(vec["key"])
        nonce = bytes.fromhex(vec["nonce"])
        counter = vec["counter"]
        expected = bytes.fromhex(vec["expected_keystream"])

        c64_chacha20_init(transport, labels, key, nonce, counter)
        result = c64_chacha20_block(transport, labels)

        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS block: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL block {vec['desc']}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")
    return passed, failed


def test_chacha20_encrypt(transport, labels):
    passed = failed = 0
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)
    for vec in vectors["chacha20_encrypt"]:
        key = bytes.fromhex(vec["key"])
        nonce = bytes.fromhex(vec["nonce"])
        counter = vec["counter"]
        plaintext = bytes.fromhex(vec["plaintext"])
        expected = bytes.fromhex(vec["ciphertext"])

        result = c64_chacha20_encrypt(transport, labels, key, nonce,
                                      plaintext, counter)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS encrypt: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL encrypt {vec['desc']}:")
            for i in range(len(expected)):
                if i >= len(result) or result[i] != expected[i]:
                    print(f"    first diff at byte {i}: "
                          f"got 0x{result[i]:02X}, "
                          f"expected 0x{expected[i]:02X}")
                    break
    return passed, failed


def test_chacha20_encrypt_random(transport, labels, rng):
    passed = failed = 0
    for size in [1, 63, 64, 127]:
        key = bytes(rng.randint(0, 255) for _ in range(32))
        nonce = bytes(rng.randint(0, 255) for _ in range(12))
        plaintext = bytes(rng.randint(0, 255) for _ in range(size))

        expected = chacha20_encrypt_ref(key, 1, nonce, plaintext)
        result = c64_chacha20_encrypt(transport, labels, key, nonce, plaintext)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS random encrypt {size}B")
        else:
            failed += 1
            print(f"  FAIL random encrypt ({size} bytes):")
            print(f"    expected: {expected[:32].hex()}...")
            print(f"    got:      {result[:32].hex()}...")
    return passed, failed


def test_poly1305_clamp(transport, labels):
    passed = failed = 0

    def do_clamp(r_val):
        write_bytes(transport, labels["poly_r"], r_val)
        write_bytes(transport, labels["poly_s"], bytes(16))
        jsr(transport, labels["poly1305_clamp"], timeout=30.0)
        return read_bytes(transport, labels["poly_r"], 16)

    def expected_clamp(r):
        e = bytearray(r)
        for i in (3, 7, 11, 15):
            e[i] &= 0x0f
        for i in (4, 8, 12):
            e[i] &= 0xfc
        return bytes(e)

    for label, r in [("sequential", bytes(range(16))),
                     ("all-FF", bytes([0xFF] * 16))]:
        result = do_clamp(r)
        want = expected_clamp(r)
        if result == want:
            passed += 1
            if VERBOSE:
                print(f"  PASS poly1305_clamp: {label}")
        else:
            failed += 1
            print(f"  FAIL poly1305_clamp {label}:")
            print(f"    expected: {want.hex()}")
            print(f"    got:      {result.hex()}")
    return passed, failed


def test_poly1305_tag(transport, labels):
    passed = failed = 0
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)
    for vec in vectors["poly1305_tag"]:
        key = bytes.fromhex(vec["key"])
        message = bytes.fromhex(vec["message"])
        expected = bytes.fromhex(vec["tag"])
        result = c64_poly1305_mac(transport, labels, key, message)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS poly1305: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL poly1305 {vec['desc']}:")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")
    return passed, failed


def test_poly1305_random(transport, labels, rng, count=4):
    passed = failed = 0
    for i in range(count):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        msg_len = rng.randint(0, 64)
        message = bytes(rng.randint(0, 255) for _ in range(msg_len))

        expected = poly1305_ref(key, message)
        result = c64_poly1305_mac(transport, labels, key, message)
        if result == expected:
            passed += 1
            if VERBOSE:
                print(f"  PASS random poly1305 #{i}: {msg_len}B")
        else:
            failed += 1
            print(f"  FAIL random poly1305 #{i} ({msg_len} bytes):")
            print(f"    key:      {key.hex()}")
            print(f"    message:  {message.hex()}")
            print(f"    expected: {expected.hex()}")
            print(f"    got:      {result.hex()}")
    return passed, failed


def test_aead_encrypt(transport, labels):
    passed = failed = 0
    with open(VECTORS_PATH) as f:
        vectors = json.load(f)
    for vec in vectors["aead_encrypt"]:
        key = bytes.fromhex(vec["key"])
        nonce = bytes.fromhex(vec["nonce"])
        aad = bytes.fromhex(vec["aad"])
        plaintext = bytes.fromhex(vec["plaintext"])
        expected_ct = bytes.fromhex(vec["ciphertext"])
        expected_tag = bytes.fromhex(vec["tag"])

        ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad,
                                    plaintext)
        ct_ok = ct == expected_ct
        tag_ok = tag == expected_tag
        if ct_ok and tag_ok:
            passed += 1
            if VERBOSE:
                print(f"  PASS AEAD encrypt: {vec['desc']}")
        else:
            failed += 1
            print(f"  FAIL AEAD encrypt {vec['desc']}:")
            if not ct_ok:
                print(f"    CT expected: {expected_ct[:32].hex()}...")
                print(f"    CT got:      {ct[:32].hex()}...")
            if not tag_ok:
                print(f"    tag expected: {expected_tag.hex()}")
                print(f"    tag got:      {tag.hex()}")
    return passed, failed


def test_aead_random(transport, labels, rng, count=3):
    passed = failed = 0
    for i in range(count):
        key = bytes(rng.randint(0, 255) for _ in range(32))
        nonce = bytes(rng.randint(0, 255) for _ in range(12))
        aad_len = rng.randint(0, 16)
        pt_len = rng.randint(1, 64)
        aad = bytes(rng.randint(0, 255) for _ in range(aad_len))
        plaintext = bytes(rng.randint(0, 255) for _ in range(pt_len))

        ct, tag = c64_aead_encrypt(transport, labels, key, nonce, aad,
                                    plaintext)
        expected_ct, expected_tag = aead_encrypt_ref(key, nonce, aad, plaintext)

        if ct == expected_ct and tag == expected_tag:
            passed += 1
            if VERBOSE:
                print(f"  PASS random AEAD #{i}: aad={aad_len}, pt={pt_len}")
        else:
            failed += 1
            print(f"  FAIL random AEAD #{i} (aad={aad_len}, pt={pt_len}):")
            if ct != expected_ct:
                print(f"    CT expected: {expected_ct.hex()}")
                print(f"    CT got:      {ct.hex()}")
            if tag != expected_tag:
                print(f"    tag expected: {expected_tag.hex()}")
                print(f"    tag got:      {tag.hex()}")
    return passed, failed


def test_aead_decrypt(transport, labels, rng):
    """AEAD decrypt: valid tag should recover plaintext; tampered tag should
    leave ciphertext unmodified."""
    passed = failed = 0

    # --- Valid path ---
    key = bytes(rng.randint(0, 255) for _ in range(32))
    nonce = bytes(rng.randint(0, 255) for _ in range(12))
    aad = bytes(rng.randint(0, 255) for _ in range(8))
    plaintext = bytes(rng.randint(0, 255) for _ in range(32))
    ct, tag = aead_encrypt_ref(key, nonce, aad, plaintext)

    pt_result, _ = c64_aead_decrypt(transport, labels, key, nonce, aad, ct, tag)
    if pt_result == plaintext:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD decrypt: valid tag")
    else:
        failed += 1
        print("  FAIL AEAD decrypt valid:")
        print(f"    expected: {plaintext.hex()}")
        print(f"    got:      {pt_result.hex()}")

    # --- Tampered path: ciphertext buffer should NOT be modified ---
    bad_tag = bytearray(tag)
    bad_tag[0] ^= 0x01
    pt_result2, ct_buf = c64_aead_decrypt(transport, labels, key, nonce, aad,
                                           ct, bytes(bad_tag))
    # Re-read ciphertext region to see if routine touched it.
    ct_after = read_bytes(transport, ct_buf, len(ct))
    if ct_after == ct:
        passed += 1
        if VERBOSE:
            print("  PASS AEAD decrypt: tampered tag rejected")
    else:
        failed += 1
        print("  FAIL AEAD decrypt tampered: ciphertext was modified")
        print(f"    before: {ct.hex()}")
        print(f"    after:  {ct_after.hex()}")
    return passed, failed


# ============================================================================
# Runner
# ============================================================================

def run_tests(transport, labels, seed):
    rng = random.Random(seed)
    total_passed = 0
    total_failed = 0

    test_groups = [
        ("rotation functions", lambda: test_rotations(transport, labels)),
        ("ChaCha20 quarter-round",
         lambda: test_chacha20_quarter_round(transport, labels)),
        ("ChaCha20 block", lambda: test_chacha20_block(transport, labels)),
        ("ChaCha20 encrypt (RFC)",
         lambda: test_chacha20_encrypt(transport, labels)),
        ("ChaCha20 encrypt (random)",
         lambda: test_chacha20_encrypt_random(transport, labels, rng)),
        ("Poly1305 clamp", lambda: test_poly1305_clamp(transport, labels)),
        ("Poly1305 tag (RFC)",
         lambda: test_poly1305_tag(transport, labels)),
        ("Poly1305 random",
         lambda: test_poly1305_random(transport, labels, rng)),
        ("AEAD encrypt (RFC)",
         lambda: test_aead_encrypt(transport, labels)),
        ("AEAD random", lambda: test_aead_random(transport, labels, rng)),
        ("AEAD decrypt", lambda: test_aead_decrypt(transport, labels, rng)),
    ]

    for name, fn in test_groups:
        print(f"\n--- {name} ---")
        try:
            p, f = fn()
            total_passed += p
            total_failed += f
            status = "OK" if f == 0 else "FAIL"
            print(f"  {status}: {p}/{p + f} passed")
        except Exception as e:
            total_failed += 1
            print(f"  ERROR: {e}")
            import traceback
            traceback.print_exc()

    return total_passed, total_failed


def main():
    global VERBOSE
    seed = random.randint(0, 2 ** 32 - 1)
    args = sys.argv[1:]
    i = 0
    while i < len(args):
        if args[i] == "--seed" and i + 1 < len(args):
            seed = int(args[i + 1])
            i += 2
        elif args[i] == "--verbose":
            VERBOSE = True
            i += 1
        else:
            i += 1

    random.seed(seed)
    print(f"Random seed: {seed} (reproduce with --seed {seed})")

    # Build unless caller says otherwise
    if not os.environ.get("C64_SKIP_BUILD"):
        print("Building...")
        subprocess.run(["make", "clean"], capture_output=True,
                       cwd=PROJECT_ROOT)
        result = subprocess.run(["make"], capture_output=True, text=True,
                                cwd=PROJECT_ROOT)
        if result.returncode != 0:
            print(f"Build failed:\n{result.stderr}")
            sys.exit(1)

    if not os.path.exists(PRG_PATH):
        print(f"FATAL: {PRG_PATH} not found after build")
        sys.exit(1)
    print(f"Built: {PRG_PATH}")

    labels = Labels.from_file(LABELS_PATH)
    required = [
        "w32_dst", "w32_src1", "w32_src2",
        "rotl32_4", "rotl32_7", "rotl32_8", "rotl32_12",
        "rotr32_1", "rotr32_4", "rotr32_7", "rotr32_8", "rotr32_12", "rotr32_16",
        "chacha20_init", "chacha20_block", "chacha20_quarter_round",
        "chacha20_encrypt",
        "cc20_key", "cc20_nonce", "cc20_counter", "cc20_state", "cc20_work",
        "cc20_keystream", "cc20_data_ptr", "cc20_remain", "cc20_remain_hi",
        "cc20_qr_idx", "cc20_qr_table",
        "poly1305_init", "poly1305_clamp", "poly1305_update", "poly1305_final",
        "poly_r", "poly_s", "poly_h", "poly1305_tag",
        "aead_encrypt", "aead_decrypt",
        "aead_key", "aead_nonce", "aead_aad_ptr", "aead_aad_len",
        "aead_data_ptr", "aead_data_len", "aead_tag",
        "zp_ptr1",
    ]
    missing = [n for n in required if labels.address(n) is None]
    if missing:
        print(f"FATAL: labels missing in {LABELS_PATH}: {missing}")
        sys.exit(1)
    print(f"Labels loaded: {len(required)} required labels verified")

    config = ViceConfig(
        prg_path=PRG_PATH,
        warp=True,
        ntsc=True,
        sound=False,
    )

    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        print(f"VICE PID={inst.pid}, port={inst.port}")
        transport = inst.transport

        # The library PRG is a thin shell whose entry routine just RTSes,
        # so there's no BASIC "ready" prompt to wait on. Give KERNAL a
        # moment to finish autoload, then proceed — subsequent jsr() calls
        # will talk directly to the binary monitor.
        time.sleep(1.5)

        print("VICE ready, running tests...")
        passed, failed = run_tests(transport, labels, seed)
        mgr.release(inst)

    elapsed = time.time() - t0
    total = passed + failed
    print(f"\n{'=' * 60}")
    print(f"Results: {passed}/{total} passed, {failed} failed  "
          f"({elapsed:.1f}s)")
    print(f"{'=' * 60}")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
