#!/usr/bin/env python3
"""run_aead_smoke.py — Run the aead_smoke PRG built against a given archive
variant and verify the status byte at $0400 hits $01 (PASS).

Used to functionally verify the aead-only archive variant produces a
byte-identical AEAD output to the full variant for the RFC 7539 §2.8.2
known answer.

Usage:
    python3 run_aead_smoke.py {full|aead}

Exits 0 on pass, 1 on fail, 2 on harness/build error.
"""

import os
import sys
import time

from c64_test_harness import (
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
)

HERE = os.path.dirname(os.path.abspath(__file__))

STATUS_ADDR = 0x0400
STATUS_PASS = 0x01
STATUS_SCREEN_BLANK = 0x20

MSGS = {
    0x01: "PASS",
    0x80: "FAIL: aead_encrypt ciphertext mismatch",
    0x81: "FAIL: aead_encrypt tag mismatch",
    0x82: "FAIL: aead_decrypt auth-verify returned nonzero",
    0x83: "FAIL: aead_decrypt plaintext mismatch",
}


def run(variant: str) -> int:
    prg = os.path.join(HERE, "build", f"aead_smoke-{variant}.prg")
    if not os.path.exists(prg):
        sys.stderr.write(f"missing PRG: {prg}\n")
        return 2

    config = ViceConfig(prg_path=prg, warp=True, ntsc=True, sound=False)
    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"[{variant}] VICE PID={inst.pid} port={inst.port}")

        deadline = time.time() + 60.0
        status = 0
        while time.time() < deadline:
            time.sleep(0.25)
            try:
                status = read_bytes(transport, STATUS_ADDR, 1)[0]
            except Exception as e:
                sys.stderr.write(f"transport read: {e}\n")
                continue
            if status not in (0, STATUS_SCREEN_BLANK):
                break

        mgr.release(inst)

    msg = MSGS.get(status, f"UNKNOWN status ${status:02x}")
    print(f"[{variant}] {msg}")
    return 0 if status == STATUS_PASS else 1


def main():
    variants = sys.argv[1:] or ["full", "aead"]
    fails = 0
    for v in variants:
        if v not in ("full", "aead"):
            sys.stderr.write(f"unknown variant: {v}\n")
            return 2
        rc = run(v)
        if rc != 0:
            fails += 1
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
