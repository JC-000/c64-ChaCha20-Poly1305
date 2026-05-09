# c64-ChaCha20-Poly1305

ChaCha20-Poly1305 AEAD (RFC 8439) for the Commodore 64, written in 6502 assembly using the cc65 toolchain (ca65/ld65).

## Purpose
Library-mode AEAD primitive for downstream consumers:
- `c64-wireguard` — Noise IKpsk2 / Type 4 transport
- `c64-https` — TLS 1.3 record layer
- Direct `jsr()` calls from Python test harnesses (c64-test-harness)

Design: library-only, no standalone runtime. Consumers link the `.o` files into their own PRG at their own load address.

## Public API (15 exported entry points, full list in `docs/API.md`)
- ChaCha20: `chacha20_init`, `chacha20_block`, `chacha20_encrypt`
- Poly1305: `poly1305_lib_init`, `poly1305_init`, `poly1305_block`, `poly1305_update`, `poly1305_final`
- AEAD: `aead_encrypt`, `aead_decrypt`

## Status
- Latest tag: **v0.3.1** (current main)
- v0.3.0 introduced constant-time `ct_mul_8x8` (Profile B fix; resolves c64-wireguard issue #16)
- v0.3.1 = release prep, MIT LICENSE, BSD sed portability fix, SMC-macro cosmetic refactor
- Unreleased: REU bank/offset configurability for Profile A (issue #19, PR #20, commit `bc383bb`)
- Planned **v0.4.0** breaking release: ZP slots and table base addresses become `-D`-configurable so consumers can relocate without source patches

## Sibling repos
- `c64-x25519` — sibling crypto ABI
- `c64-https`, `c64-wireguard` — consumers
- `c64-test-harness` — Python driver (VICE + Ultimate 64)
