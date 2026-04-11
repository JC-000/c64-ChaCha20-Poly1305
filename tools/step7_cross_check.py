#!/usr/bin/env python3
"""step7_cross_check.py - 10 000 random Poly1305 vectors vs pyca reference.

Step 7 (P4 Donna fused wrap reduction) rewrites the poly1305 reduction
primitive. Per the plan, the risk of a subtle wrap/carry bug is high, so
we cross-check 10 000 random (r_s, message) tag computations against
pyca/cryptography's Poly1305 implementation.

Runs under whichever profile is currently built (callers should rebuild
for profile-a or profile-b before invoking this script). Uses the same
direct-memory jsr() harness as the main test suite.

Messages are chunked through c64_poly1305_update in ≤240-byte pieces
that are multiples of 16 bytes, with the tail flushed as the final call
(len < 16 or exactly the remainder). This matches the RFC 7539
Poly1305 semantics the assembly implements.

Usage:
    python3 tools/step7_cross_check.py --seed S [--count N]
"""
import argparse
import os
import random
import sys
import time

from cryptography.hazmat.primitives.poly1305 import Poly1305 as _PycaPoly1305

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

SCRATCH_BUF = 0xC000
CHUNK = 240  # multiple of 16, <=255 (cc20_remain is 8-bit)


def write_ptr(transport, addr, value):
    write_bytes(transport, addr, bytes([value & 0xFF, (value >> 8) & 0xFF]))


def pyca_poly1305(key, message):
    mac = _PycaPoly1305(key)
    mac.update(message)
    return mac.finalize()


def c64_poly1305_mac(transport, labels, key, message):
    """MAC an arbitrary-length message via init + (repeated) update + final.

    We pass CHUNK-sized (multiple-of-16) slices to poly1305_update while
    len(remaining) > CHUNK. When the remainder is ≤ CHUNK, we pass it as
    the final call (which handles the partial-block path internally).
    """
    # Init: write r/s halves and JSR.
    write_bytes(transport, labels["poly_r"], key[:16])
    write_bytes(transport, labels["poly_s"], key[16:])
    jsr(transport, labels["poly1305_init"], timeout=60.0)

    pos = 0
    n = len(message)
    while n - pos > CHUNK:
        chunk = message[pos:pos + CHUNK]
        write_bytes(transport, SCRATCH_BUF, chunk)
        write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
        write_bytes(transport, labels["cc20_remain"], bytes([len(chunk)]))
        jsr(transport, labels["poly1305_update"], timeout=240.0)
        pos += CHUNK

    tail = message[pos:]
    if tail:
        write_bytes(transport, SCRATCH_BUF, tail)
        write_ptr(transport, labels["zp_ptr1"], SCRATCH_BUF)
        write_bytes(transport, labels["cc20_remain"], bytes([len(tail)]))
        jsr(transport, labels["poly1305_update"], timeout=240.0)

    jsr(transport, labels["poly1305_final"], timeout=30.0)
    return bytes(read_bytes(transport, labels["poly1305_tag"], 16))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--count", type=int, default=10000)
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    rng = random.Random(args.seed)

    # Length mix per plan: exercise partial-block tails around block-multiple
    # boundaries that historically break Donna-style wraps.
    length_mix = [1, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65,
                  127, 128, 129, 255, 256, 511, 512, 1023, 1024]
    # Weighted toward block-multiple cases as the "hard" spots.
    block_mult_heavy = [16, 32, 48, 64, 128, 256, 512, 1024]

    labels = Labels.from_file(LABELS_PATH)
    config = ViceConfig(prg_path=PRG_PATH, warp=True, ntsc=True, sound=False)

    t0 = time.time()
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        time.sleep(1.5)

        passed = 0
        failed = 0
        first_fail = None
        for i in range(args.count):
            # 50/50 between general mix and block-multiple-heavy mix.
            if rng.random() < 0.5:
                msg_len = rng.choice(length_mix)
            else:
                msg_len = rng.choice(block_mult_heavy)
            key = bytes(rng.randint(0, 255) for _ in range(32))
            msg = bytes(rng.randint(0, 255) for _ in range(msg_len))

            expected = pyca_poly1305(key, msg)
            got = c64_poly1305_mac(transport, labels, key, msg)

            if got == expected:
                passed += 1
            else:
                failed += 1
                if first_fail is None:
                    first_fail = (i, msg_len, key, msg, expected, got)
                if failed >= 3:
                    break

            if args.verbose and (i + 1) % 100 == 0:
                el = time.time() - t0
                print(f"  [{i+1}/{args.count}] pass={passed} fail={failed} "
                      f"elapsed={el:.1f}s", flush=True)

        mgr.release(inst)

    elapsed = time.time() - t0
    print(f"\nstep7 cross-check: {passed}/{args.count} passed, "
          f"{failed} failed ({elapsed:.1f}s)")
    print(f"seed: {args.seed}")
    if first_fail is not None:
        i, L, k, m, exp, got = first_fail
        print(f"\nFIRST FAILURE: vector #{i}, len={L}")
        print(f"  key:      {k.hex()}")
        print(f"  msg:      {m.hex()}")
        print(f"  expected: {exp.hex()}")
        print(f"  got:      {got.hex()}")
        sys.exit(1)
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
