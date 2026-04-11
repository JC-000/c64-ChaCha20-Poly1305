# c64-ChaCha20-Poly1305

Optimizing ChaCha20-Poly1305 AEAD (RFC 7539 / RFC 8439) for the Commodore 64 / 6502. Library-mode project: assembly sources live under `src/lib/*_lib.asm` with no absolute origin, exposing public symbols for use from host applications (WireGuard, TLS 1.3, etc.) or direct-jsr Python test harnesses. Baseline imported verbatim from the sibling `c64-wireguard` project; optimization work happens on top of that baseline.

## Build

```
make
```

Produces `build/c64_chacha20_poly1305.prg` and `build/labels.txt` (VICE-format label file for harness consumption). Requires ACME.

## Public symbols (library API)

- `chacha20_init` - seed ChaCha20 state from `cc20_key`, `cc20_nonce`, `cc20_counter`
- `chacha20_block` - generate one 64-byte keystream block into `cc20_keystream`
- `chacha20_encrypt` - XOR keystream with data at `cc20_data_ptr` (in place), 16-bit length via `cc20_remain` / `cc20_remain_hi`
- `poly1305_init` - clamp `poly_r`, zero `poly_h`, build quarter-square table
- `poly1305_block` - process one 16-byte block pointed to by `zp_ptr1`
- `poly1305_update` - process a buffer at `zp_ptr1` of length `cc20_remain`
- `poly1305_final` - finalize and write tag to `poly1305_tag`
- `aead_encrypt` - full ChaCha20-Poly1305 AEAD encrypt
- `aead_decrypt` - full ChaCha20-Poly1305 AEAD decrypt (returns A=0 on auth success)

See `src/lib/data_lib.asm` for the input/output data fields (`aead_key`, `aead_nonce`, `aead_aad_ptr`, `aead_aad_len`, `aead_data_ptr`, `aead_data_len`, `aead_tag`).

## Layout

```
src/
  main.asm                     entry stub + BASIC SYS header
  lib/
    constants_lib.asm          ZP equates (library only)
    data_lib.asm               mutable buffers (cc20_*, poly_*, aead_*)
    word32_lib.asm             32-bit add / xor / rotate primitives
    chacha20_lib.asm           ChaCha20 stream cipher
    poly1305_lib.asm           Poly1305 MAC (quarter-square mult table)
    chacha20poly1305_lib.asm   AEAD wrapper
test/                          (TBD - populated by test agent)
tools/                         (TBD - populated by test agent)
```

Tests live under `tools/` and `test/` (to be added).
