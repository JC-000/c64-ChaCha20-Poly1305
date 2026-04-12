# c64-ChaCha20-Poly1305

ChaCha20-Poly1305 AEAD (RFC 8439) for the Commodore 64 / 6502.
Library-mode assembly: sources live under `src/lib/*_lib.asm` with no
absolute origin, exposing public symbols for host applications
(WireGuard, TLS 1.3, DTLS) or direct-jsr Python test harnesses.

## Build

Requires [ACME](https://sourceforge.net/projects/acme-crossass/).

```
make profile-a      # Profile A: Shoup per-r tables, optimized for long messages
make profile-b      # Profile B: stock C64, portable baseline, lower init cost
make                # alias for profile-a
```

Both produce `build/c64_chacha20_poly1305.prg` and `build/labels.txt`
(VICE-format label file for harness consumption).

## Build profiles

- **Profile A** precomputes 8 KB of Shoup per-r multiplication tables
  at `poly1305_init` time (~490 k cy setup cost), reducing
  `poly1305_block` from 38 760 to 12 119 cy. Best for messages longer
  than ~256 bytes, where the table-build amortizes. Target workloads:
  WireGuard data packets (~1280 B), TLS 1.3 bulk records. With
  `POLY1305_REU=1`, backs up the quarter-square table to REU for
  fast restore if clobbered.

- **Profile B** uses the portable quarter-square multiply (1 KB table).
  Lower per-packet init cost (87 k vs 579 k cy at n=0), better for
  short packets such as WireGuard handshakes and TLS 1.3 alerts.
  Runs on any stock C64 without REU.

Both profiles share identical ChaCha20 code, pass the full 214-test
suite, and are constant-time by contract (no data-dependent branches on
secret data).

## Performance

Optimization sprint S0-S10 results (cycles, measured via CIA timer in
VICE):

| routine              | S0 baseline | Profile A (S10) |   change | Profile B (S10) |   change |
|----------------------|------------:|----------------:|---------:|----------------:|---------:|
| `chacha20_block`     |     149 987 |          44 920 |  -70.0%  |          44 922 |  -70.0%  |
| `poly1305_block`     |      53 270 |          12 119 |  -77.2%  |          38 760 |  -27.2%  |
| `aead_encrypt` n=0   |     251 330 |         579 280 | +130.5%  |          87 210 |  -65.3%  |
| `aead_encrypt` n=1024|   5 974 048 |       2 109 228 |  -64.7%  |       3 326 084 |  -44.3%  |

Profile A n=0 is higher than baseline due to Shoup table-build cost
(~490 k cy per-packet); this amortizes rapidly at n >= 256. Step 10
reduced n=0 by 89 k cy (sqtab one-time build). Profile B n=0 dropped
to 87 k cy -- 65% below the original baseline. See
`docs/OPTIMIZATION_PLAN.md` for the full per-step progression table,
per-byte breakdowns, and estimate-vs-measured analysis.

## Constant-time guarantees

All code paths are constant-time with respect to secret data (key, r, s,
h, plaintext, ciphertext, tag). The `poly1305_multiply` schoolbook runs
every partial product unconditionally (no early-exit on zero). Tag
comparison uses an OR-accumulator pattern. The 6502 has no data cache,
so instruction timing is deterministic.

## Public symbols (library API)

- `chacha20_init` -- seed ChaCha20 state from `cc20_key`, `cc20_nonce`, `cc20_counter`
- `chacha20_block` -- generate one 64-byte keystream block into `cc20_keystream`
- `chacha20_encrypt` -- XOR keystream with data at `cc20_data_ptr` (in place)
- `poly1305_lib_init` -- one-time library init: build quarter-square table, set `sqtab_ready` flag. Call once before first `aead_encrypt`/`aead_decrypt`. Optional: if omitted, `poly1305_init` auto-builds on first call. With `POLY1305_REU=1` (Profile A), also DMA-backs sqtab to REU.
- `poly1305_reu_restore` -- (Profile A + `POLY1305_REU=1` only) DMA sqtab from REU back to main RAM (~1.1 k cy). Use if external code clobbers `$8000-$83FF`.
- `poly1305_init` -- clamp `poly_r`, zero `poly_h`, build multiplication tables (Shoup per-r in Profile A, quarter-square in Profile B). Skips sqtab build if already done.
- `poly1305_block` -- process one 16-byte block pointed to by `zp_ptr1`
- `poly1305_update` -- process a buffer at `zp_ptr1` of length `cc20_remain`
- `poly1305_final` -- finalize and write tag to `poly1305_tag`
- `aead_encrypt` -- full ChaCha20-Poly1305 AEAD encrypt
- `aead_decrypt` -- full ChaCha20-Poly1305 AEAD decrypt (returns A=0 on auth success)

See `src/lib/data_lib.asm` for input/output data fields (`aead_key`,
`aead_nonce`, `aead_aad_ptr`, `aead_aad_len`, `aead_data_ptr`,
`aead_data_len`, `aead_tag`).

## Layout

```
src/
  main.asm                     entry stub + BASIC SYS header
  lib/
    constants_lib.asm          ZP equates, profile flags
    data_lib.asm               mutable buffers (cc20_*, poly_*, aead_*)
    word32_lib.asm             32-bit add / xor / rotate primitives
    chacha20_lib.asm           ChaCha20 stream cipher (inlined QRs, rot-rename)
    poly1305_lib.asm           Poly1305 MAC (Shoup table / quarter-square)
    chacha20poly1305_lib.asm   AEAD wrapper
test/
  rfc7539_vectors.json         RFC 8439 test vectors
tools/
  test_chacha20_poly1305.py    214-test suite (VICE + harness)
  benchmark_chacha20_poly1305.py  CIA-timer benchmark suite
```
