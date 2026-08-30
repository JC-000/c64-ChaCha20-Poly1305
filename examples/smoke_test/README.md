# examples/smoke_test

External-consumer smoke test for `c64-ChaCha20-Poly1305`. Simulates a
downstream ca65 project (e.g. `c64-wireguard`, `c64-https`) that has
adopted the library and calls its public API from its own main program.

This example is deliberately **consumer-owned end-to-end**: its own
`smoke_test.s`, its own `smoke_test.cfg` (not the library's `c64.cfg`),
its own `Makefile` (not the root `Makefile`), and its own build output
under `examples/smoke_test/build/` (not the project root `build/`). Only
the library sources come from outside — it builds `../../src/lib/*.s`
plus `../../src/zp_config.s`, i.e. the current library.

What the test program does (see `smoke_test.s`):

1. Calls `poly1305_lib_init` once at startup.
2. Loads the RFC 7539 §2.8.2 AEAD test vector into `aead_key`,
   `aead_nonce`, `aead_aad_ptr`, `aead_data_ptr`.
3. Poisons `aead_tag` and `poly1305_tag` with `$EE`, calls
   `aead_encrypt`, and byte-compares the produced ciphertext and both
   tag buffers against the RFC known answers.
4. Calls `aead_decrypt` on the produced ciphertext+tag with **no tag
   reload** — `aead_tag` already holds what `aead_encrypt` published —
   then checks `A == 0` and that the recovered plaintext matches.
5. Writes a status byte to screen RAM `$0400` and spins.
   `$01` = PASS; `$80..$84` = specific failures.

## What it asserts, and why in that shape

The tag assertions are poison-then-act. Both tag buffers are filled with
`$EE` *before* `aead_encrypt`, so neither can pass on a value the library
never wrote, and the RFC fixture is never copied into `aead_tag` — the
decrypt leg has to consume the tag encrypt actually produced.

`aead_tag` is the primary assertion, because it is the ABI's documented
`aead_encrypt` output (`docs/API.md` §0 and §4). `poly1305_tag`, the
Poly1305 module's own output buffer, is asserted separately under its own
status byte rather than standing in for `aead_tag`.

This example previously built a frozen snapshot under
`third_party/c64-chacha20poly1305-v0.3.0/`. That snapshot documents
`aead_tag` as `aead_encrypt`'s output but contains no `sta aead_tag`
anywhere — so a test pinned to it could only report PASS by asserting on
something other than the API it claims to validate. It is retained for
reference (see its `ORIGIN.txt`) and is no longer built by anything.

## Adopting the library: what a consumer cfg needs

`smoke_test.cfg` is worth reading alongside `docs/INTEGRATION.md`, since
it carries the three things a consumer link actually has to get right:

- the contract §4 prefixed segments `LIB_CHACHA20_POLY1305_CODE` and
  `LIB_CHACHA20_POLY1305_DATA` — the library emits into these, not into
  plain `CODE`/`DATA`, and omitting them fails the link;
- `align = $100` on `LIB_CHACHA20_POLY1305_CODE`, which is a
  constant-time invariant rather than a perf hint (secret-indexed lookup
  tables must not straddle a page); drop it and `ld65` warns and then
  links them misaligned anyway;
- `define = yes` on `MAIN`, which publishes `__MAIN_LAST__` for the §6.7
  image guard in `smoke_test.s`. The library places its tables by equate,
  not by segment, so `ld65` cannot see the collision on its own.

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
