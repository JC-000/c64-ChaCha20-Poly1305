# Granular per-function bench (HEAD `36ec121`)

- **Commit**: `36ec121`
- **Generated**: 2026-05-20 21:03:26 UTC
- **Backend**: vice
- **Profile**: B
- **Samples**: 3 (min reported, except single-shot rows)
- **PRG md5**: `4afe54d466ad92ca38b91c94a2ea2b36`
- **Methodology**: chained CIA #1 Timer A+B 32-bit cycle counter wrapper at $C080; SEI/save/CIA-arm/JSR/stop/restore/CLI/RTS. min-of-N reduction; wrapper overhead subtracted via the no-op (RTS) stub calibration; verified against a 501-cy LDX #100 / DEX / BNE / RTS stub. See `tools/bench_granular.py` and `tools/benchmark_chacha20_poly1305.py` for the wrapper bytes.

| Symbol | Cycles | Spread | Notes |
|--------|-------:|-------:|-------|
| `chacha20_quarter_round` | 1,676 | 172 | test-only entry; QR(0,4,8,12) over RFC-7539-primed cc20_work |
| `chacha20_block` | 39,318 | 347 | one 64-byte keystream block, warm state |
| `chacha20_encrypt n=64` | 41,026 | 300 | single full block, key/nonce primed, in-place XOR |
| `chacha20_encrypt n=1024` | 658,274 | 341 | 16 blocks, key/nonce primed, in-place XOR |
| `poly1305_multiply` | 37,664 | 608 | one 17x16 mul over clamped RFC r and primed h |
| `poly1305_reduce` | 1,846 | 172 | one mod-2^130-5 reduction over fixed poly_product pattern |
| `poly1305_block` | 38,002 | 236 | one 16 B block: add + multiply + reduce (A=1 shim) |
| `aead_compute_tag` | 2,495,091 | 47 | tag compute over n=1024 ciphertext + 0-byte AAD + lengths |
| `aead_verify_tag` | 313 | 43 | CT-eq, 16-byte happy path (all bytes equal) |
| `sqtab_init` | 89,103 | 0 | one-shot quarter-square table build (single sample) |
| `ct_mul_8x8` | 101.3 | 6 | Profile B 8x8->16 multiply primitive; loop-of-64 with varied (a,b) operands; reported as cycles/call after dividing wrapper measurement by loop count |
| `aead_encrypt n=0` | 80,513 | 389 | AEAD per-packet fixed cost (OTK derive + 0-byte tag) |
| `aead_encrypt n=64` | 274,794 | 1,338 | AEAD over one 64-byte plaintext block |
| `aead_encrypt n=1024` | 3,195,600 | 1,621 | AEAD over 16 blocks of plaintext |

Regenerate with: `make bench` (this report) or `make bench-check` (diff against committed baseline).
