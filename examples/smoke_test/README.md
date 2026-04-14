# examples/smoke_test

External-consumer smoke test for `c64-ChaCha20-Poly1305`. Simulates a
downstream ca65 project (e.g. `c64-wireguard`, `c64-https`) that
vendored the library under `third_party/c64-chacha20poly1305-v0.3.0/`
and calls its public API from its own main program.

This example is deliberately **consumer-owned end-to-end**: its own
`smoke_test.s`, its own `smoke_test.cfg` (not the library's `c64.cfg`),
its own `Makefile` (not the root `Makefile`), and its own build output
under `examples/smoke_test/build/` (not the project root `build/`).

What the test program does (see `smoke_test.s`):

1. Calls `poly1305_lib_init` once at startup.
2. Loads the RFC 7539 §2.8.2 AEAD test vector into `aead_key`,
   `aead_nonce`, `aead_aad_ptr`, `aead_data_ptr`.
3. Calls `aead_encrypt` and byte-compares the produced ciphertext and
   tag against the RFC known answers.
4. Calls `aead_decrypt` on the produced ciphertext+tag, checks
   `A == 0` and that the recovered plaintext matches.
5. Writes a status byte to screen RAM `$0400` and spins.
   `$01` = PASS; `$80..$83` = specific failures.

## Running

```
make              # build profile A (default)
make profile-b    # build profile B
make both         # build both
python3 run_smoke_test.py both   # builds + runs both in VICE, reports pass/fail
```

Requires `ca65` / `ld65` (cc65 toolchain), `x64sc` (VICE 3.x), and the
`c64_test_harness` Python package (same one used by the upstream
library's `tools/test_chacha20_poly1305.py`).
