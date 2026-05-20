# Granular per-symbol benchmark

This doc describes the per-function granular benchmark added under
`tools/bench_granular.py` and the `make bench` / `make bench-check`
targets. It complements the coarse-grained
`tools/benchmark_chacha20_poly1305.py` (which measures only the public
API entry points) with one row per *internal* hot-path symbol so a
perf regression can be attributed to a specific routine rather than
the whole AEAD pipeline.

## What it measures

The granular bench runs each row below through the same chained
CIA #1 Timer A+B 32-bit cycle counter wrapper at `$C080` that the
legacy bench uses (`tools/benchmark_chacha20_poly1305.py`
§"Chained CIA Timer A+B 32-bit wrapper"). Calibration measures wrapper
overhead and subtracts it per sample; `verify_wrapper()` sanity-checks
against a 501-cy stub. min-of-N reduction is reported.

| Row | Symbol | Methodology | Notes |
|-----|--------|-------------|-------|
| `chacha20_quarter_round` | One QR(0,4,8,12) on the RFC 7539 §2.3.2 test-vector state copied into `cc20_work`, `cc20_qr_idx=0`. Test-only entry (production `chacha20_block` inlines QRs). | small_routine (samples ×10 to converge past CIA wrapper jitter floor of ~43 cy) |
| `chacha20_block` | Same prime as the legacy bench; warm state. | |
| `chacha20_encrypt n=64` | Inputs primed via `setup_chacha20_block` + ZP `cc20_data_ptr`, `cc20_remain`, `cc20_remain_hi`. Per-sample re-seed (encrypt is in-place XOR; counter advances). | |
| `chacha20_encrypt n=1024` | Same as n=64 but 1024 bytes of plaintext (16 blocks). | |
| `poly1305_multiply` | RFC 7539 §2.5.2 r/s, `poly1305_init` builds clamped r + sqtab (+ Shoup tables on Profile A), one warmup `poly1305_block` of "Cryptographic Fo" populates a representative h. | |
| `poly1305_reduce` | Pre-populates `poly_product[0..32]` with a fixed deterministic pattern (`(i*17+31) & $FF`); cycle count is dominated by straight-line code, so the byte values do not change the result materially. Per-sample re-seed (reduce reads + writes the product buffer). | small_routine |
| `poly1305_block` | Same prime as legacy bench: r/s/sqtab ready, A=1 shim at `$C1E0` sets the hibit byte and JMPs to `poly1305_block`. | |
| `aead_compute_tag` | `aead_encrypt` warmup primes r/s/h and ciphertext at `$5000`; per-sample re-zero of `poly_h` so each sample is "one tag compute from scratch". | |
| `aead_verify_tag` | Constant-time eq, happy-path: `poly1305_tag` == `aead_tag` with a fixed-pattern tag. | small_routine |
| `sqtab_init` | Single-shot table builder; reports the n=1 sample. | single_shot |
| `ct_mul_8x8` | Profile B only. SMC-driven shim at `$C400` loops K=64 calls with varied (a,b) operands (`a = (i*47+11)&$FF`, `b = (i*91+73)&$FF`); reported cycles are wrapper total / K. SMC operands baked into `smc_sum_a_imm_SMC+1` and `smc_diff_a_imm_SMC+1` before each call. | profile_b_only |
| `aead_encrypt n=0` | Legacy coverage, kept here so a single JSON has all numbers. | |
| `aead_encrypt n=64` | " | |
| `aead_encrypt n=1024` | " | |

## How to run

Default invocation (Profile B, VICE, 5 samples, writes report +
sidecar JSON to `docs/BENCH_REPORT.md` / `docs/BENCH_REPORT.md.json`):

```sh
make bench
```

Override knobs:

```sh
# Profile A (skips the ct_mul_8x8 row — Profile A uses Shoup tables instead)
make bench BENCH_PROFILE=A

# Ultimate 64 hardware (requires U64_HOST env var)
C64_BACKEND=u64 U64_HOST=10.43.23.81 make bench BENCH_BACKEND=u64

# Bump samples (useful when first establishing a baseline)
make bench BENCH_SAMPLES=10
```

## Regression gate

Once you are happy with a measurement, copy the JSON sidecar to the
baseline path and commit:

```sh
make bench BENCH_SAMPLES=5
cp docs/BENCH_REPORT.md.json docs/BENCH_REPORT.baseline.json
git add docs/BENCH_REPORT.baseline.json
```

`make bench-check` then re-runs the bench and diffs every row against
the committed baseline. Exits non-zero on any row drifting more than
±1% (override with `BENCH_TOLERANCE=2.0`). The PRG md5 is recorded in
the sidecar; a divergence between baseline and current md5 is logged
but **not** a hard fail — the per-symbol cycle count is the gate, so a
PRG that compiled to a different binary but happens to keep the cycle
counts unchanged still passes.

Example failure output (synthetic 4×`nop` injected at
`aead_verify_tag`):

```
bench-check against docs/BENCH_REPORT.baseline.json:
  baseline commit:  36ec121  prg_md5: 4afe54d4...
  current  commit:  36ec121  prg_md5: 30050bf2...
  tolerance: ±1.00%
  OK   chacha20_block                   cur=        39,319  baseline=        39,319  Δ=++0.000%
  ...
  FAIL aead_verify_tag                  cur=           321  baseline=           313  Δ=++2.556%
  ...
bench-check: FAIL (1 row(s) outside ±1.00%):
  - aead_verify_tag: baseline 313 -> current 321 (Δ=+2.556%)
```

## Sample-count guidance

VICE is *almost* deterministic but the chained-CIA wrapper exhibits a
~43-cycle jitter floor on the smallest measurements (sub-1k cycles).
For routines flagged `small_routine` in `BENCH_TARGETS`
(`chacha20_quarter_round`, `poly1305_reduce`, `aead_verify_tag`), the
bench automatically multiplies the user-requested sample count by 10×
so min-of-N converges to the true minimum. Without that, a min-of-3
measurement of `aead_verify_tag` can show 313 or 356 depending on CIA
timer phase at JSR (`313 + 43 = 356`); samples=30 reliably lands on
313.

## Reachability check (cross-referenced against the project memory)

Per project memory, dead-code macros exist in `src/lib/` that look
like opt targets but aren't on any public call path. The granular
bench rows here have been cross-referenced against `chacha20_block` /
`chacha20_encrypt` / `aead_encrypt` / `aead_decrypt` paths via
`grep -n "jsr <symbol>"` in `src/lib/*.s`:

| Row | Reached from |
|-----|--------------|
| `chacha20_quarter_round` | test-only (`tools/test_chacha20_poly1305.py`'s test_chacha20_quarter_round vector); NOT called from `chacha20_block` (inlined). Listed here because consumers see the `.export` and may bench it directly. |
| `chacha20_block` | `chacha20_encrypt`, `aead_derive_otk` (both AEAD paths) |
| `chacha20_encrypt` | `aead_encrypt`, `aead_decrypt` |
| `poly1305_multiply` | `poly1305_block` (and fall-through `poly1305_reduce`) |
| `poly1305_reduce` | fall-through from `poly1305_multiply` (used internally; benched here in isolation by writing the product buffer directly) |
| `poly1305_block` | `aead_process_padded` → `aead_compute_tag` (both AEAD paths) |
| `aead_compute_tag` | `aead_encrypt`, `aead_decrypt` |
| `aead_verify_tag` | `aead_decrypt` only |
| `sqtab_init` | `poly1305_init` (auto-rebuilt if `sqtab_ready=0`); `poly1305_lib_init` |
| `ct_mul_8x8` | Profile B only: `poly1305_multiply`'s `poly_pp_ct_mul` macro (272 calls per `poly1305_block`). Listed as the inner-loop hotspot. Profile A skips this row (uses Shoup tables). |

## Files

- `tools/bench_granular.py` — the bench driver. Re-uses
  `benchmark_chacha20_poly1305.py`'s wrapper bytes, calibration, and
  verify helpers.
- `Makefile` — `bench` and `bench-check` targets, `BENCH_*` variables.
- `docs/BENCH_REPORT.md` + `docs/BENCH_REPORT.md.json` — output of the
  latest `make bench` run. (Re-generated on every run; not the
  baseline.)
- `docs/BENCH_REPORT.baseline.json` — committed baseline JSON. Refresh
  via `make bench && cp docs/BENCH_REPORT.md.json
  docs/BENCH_REPORT.baseline.json`.
