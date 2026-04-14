#!/usr/bin/env python3
"""run_smoke_test.py — Drive the consumer-side smoke test in VICE.

Boots one of the two profile PRGs (profile-a or profile-b) built by the
consumer Makefile, lets it auto-run via the BASIC SYS stub, waits for it
to write a status byte to screen RAM ($0400), then reports pass/fail.

The status byte protocol matches smoke_test.s:
    $01 -> PASS
    $80 -> FAIL: aead_encrypt ciphertext mismatch
    $81 -> FAIL: aead_encrypt tag mismatch
    $82 -> FAIL: aead_decrypt auth-verify failed
    $83 -> FAIL: aead_decrypt plaintext mismatch
    $20 -> still running (initial screen-RAM contents after KERNAL clear)

Usage:
    python3 run_smoke_test.py [profile-a|profile-b|both]

Exits 0 on success, 1 on failure, 2 on harness/build error. Requires the
c64-test-harness package to be importable (same dependency as the
upstream library's tools/test_chacha20_poly1305.py).
"""

import os
import subprocess
import sys
import time

from c64_test_harness import (
    ViceConfig,
    ViceInstanceManager,
    read_bytes,
)

HERE = os.path.dirname(os.path.abspath(__file__))

STATUS_ADDR = 0x0400         # screen RAM position 0
STATUS_PASS = 0x01
STATUS_SCREEN_BLANK = 0x20   # KERNAL fills screen RAM with $20 (space)

STATUS_MESSAGES = {
    0x01: "PASS: aead encrypt+decrypt matches RFC 7539 §2.8.2",
    0x80: "FAIL: aead_encrypt ciphertext mismatch",
    0x81: "FAIL: aead_encrypt Poly1305 tag mismatch",
    0x82: "FAIL: aead_decrypt auth-verify returned nonzero",
    0x83: "FAIL: aead_decrypt plaintext mismatch",
}


def build_profile(profile: str) -> str:
    """Invoke the consumer Makefile for the given profile and return PRG path."""
    print(f"[build] make {profile}")
    result = subprocess.run(
        ["make", profile],
        capture_output=True,
        text=True,
        cwd=HERE,
    )
    if result.returncode != 0:
        sys.stderr.write(f"[build] FAILED:\n{result.stdout}\n{result.stderr}\n")
        sys.exit(2)
    prg_path = os.path.join(HERE, "build", profile, "smoke_test.prg")
    if not os.path.exists(prg_path):
        sys.stderr.write(f"[build] PRG missing after build: {prg_path}\n")
        sys.exit(2)
    return prg_path


def run_profile(profile: str) -> bool:
    """Build + run one profile in VICE. Returns True on PASS."""
    prg_path = build_profile(profile)
    print(f"[run ] booting {prg_path} in VICE")

    config = ViceConfig(
        prg_path=prg_path,
        warp=True,
        ntsc=True,
        sound=False,
    )

    with ViceInstanceManager(config=config) as mgr:
        inst = mgr.acquire()
        transport = inst.transport
        print(f"[run ] VICE PID={inst.pid} port={inst.port}")

        # BASIC stub runs "SYS 2304" at autoload. The smoke test itself
        # finishes in well under a second in warp mode, but we give it
        # a generous budget for profile-a (which builds Shoup tables
        # for several hundred thousand cycles on first init).
        deadline = time.time() + 30.0
        status = 0
        while time.time() < deadline:
            time.sleep(0.25)
            try:
                status = read_bytes(transport, STATUS_ADDR, 1)[0]
            except Exception as e:  # pragma: no cover — transport transient
                sys.stderr.write(f"[run ] transport read error: {e}\n")
                continue
            if status != 0 and status != STATUS_SCREEN_BLANK:
                break

        mgr.release(inst)

    msg = STATUS_MESSAGES.get(status, f"UNKNOWN status byte ${status:02x}")
    if status == STATUS_PASS:
        print(f"[{profile}] {msg}")
        return True
    if status == 0 or status == STATUS_SCREEN_BLANK:
        print(f"[{profile}] FAIL: smoke test did not signal within timeout "
              f"(screen RAM = ${status:02x})")
        return False
    print(f"[{profile}] {msg}")
    return False


def main() -> int:
    args = sys.argv[1:]
    if not args or args == ["both"]:
        profiles = ["profile-a", "profile-b"]
    else:
        profiles = args

    results = {}
    for p in profiles:
        if p not in ("profile-a", "profile-b"):
            sys.stderr.write(f"unknown profile: {p}\n")
            return 2
        results[p] = run_profile(p)

    print("\n=== smoke test summary ===")
    for p, ok in results.items():
        print(f"  {p}: {'PASS' if ok else 'FAIL'}")

    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
