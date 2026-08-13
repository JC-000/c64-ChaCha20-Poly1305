# Granular per-function bench (HEAD `f7cc990`)

- **Commit**: `f7cc990`
- **Generated**: 2026-08-13 15:41:11 UTC
- **Backend**: vice
- **Profile**: B
- **Samples**: 5 (min reported, except single-shot rows)
- **PRG md5**: `6e9a989f21940826153a63c2d709216f`
- **Methodology**: chained CIA #1 Timer A+B 32-bit cycle counter wrapper at $C080; SEI/save/CIA-arm/JSR/stop/restore/CLI/RTS. min-of-N reduction; wrapper overhead subtracted via the no-op (RTS) stub calibration; verified against a 501-cy LDX #100 / DEX / BNE / RTS stub. See `tools/bench_granular.py` and `tools/benchmark_chacha20_poly1305.py` for the wrapper bytes.

| Symbol | Cycles | Spread | Notes |
|--------|-------:|-------:|-------|
| `chacha20_quarter_round` | 1,676 | 172 | test-only entry; QR(0,4,8,12) over RFC-7539-primed cc20_work |
| `chacha20_block` | 39,319 | 385 | one 64-byte keystream block, warm state |
| `chacha20_encrypt n=64` | 40,946 | 385 | single full block, key/nonce primed, in-place XOR |
| `chacha20_encrypt n=1024` | 658,271 | 343 | 16 blocks, key/nonce primed, in-place XOR |
| `poly1305_multiply` | 37,445 | 831 | one 17x16 mul over clamped RFC r and primed h |
| `poly1305_reduce` | 1,846 | 172 | one mod-2^130-5 reduction over fixed poly_product pattern |
| `poly1305_block` | 37,891 | 491 | one 16 B block: add + multiply + reduce (A=1 shim) |
| `aead_compute_tag` | 2,495,147 | 39 | tag compute over n=1024 ciphertext + 0-byte AAD + lengths |
| `aead_verify_tag` | 313 | 43 | CT-eq, 16-byte happy path (all bytes equal) |
| `sqtab_init` | 89,147 | 0 | one-shot quarter-square table build (single sample) |
| `ct_mul_8x8` | 101.4 | 5 | Profile B 8x8->16 multiply primitive; loop-of-64 with varied (a,b) operands; reported as cycles/call after dividing wrapper measurement by loop count |
| `aead_encrypt n=0` | 80,516 | 388 | AEAD per-packet fixed cost (OTK derive + 0-byte tag) |
| `aead_encrypt n=64` | 274,763 | 1,368 | AEAD over one 64-byte plaintext block |
| `aead_encrypt n=1024` | 3,195,683 | 1,530 | AEAD over 16 blocks of plaintext |

Regenerate with: `make bench` (this report) or `make bench-check` (diff against committed baseline).
