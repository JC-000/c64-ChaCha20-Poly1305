# Turbo-scaling sweep (issue #44)

Wall-clock benchmark of the AEAD hot paths at multiple CPU turbo
speeds on Ultimate hardware, confirming that no wall-clock-anchored
work (REU DMA or other ~1 MHz-bus-rate-anchored component) sits on
any hot path. Context: `c64-nist-curves` issues #69/#71 found REU DMA
transfers at the stock ~1 MHz bus rate regardless of CPU turbo, so
per-operation DMA becomes a clock-invariant wall-time floor on
accelerated hosts. This library removed its last (init-time-only) REU
path in the issue #34 F1 slimming (PR #38); this sweep verifies the
resulting clean scaling empirically.

## Method

- `tools/bench_turbo_sweep.py`, Profile A build, run in a single
  power-on session (the per-run jiffy/CIA-rate drift nist-curves
  observed at 48 MHz makes cross-run comparisons slightly noisy;
  within-run ratios are clean).
- The CIA #1 chained Timer A+B wrapper from
  `tools/benchmark_chacha20_poly1305.py` counts CIA ticks. On
  Ultimate hardware the CIA keeps ticking at the stock PAL φ2 rate
  (~985 kHz) regardless of CPU turbo, so ticks ≈ wall-clock
  microseconds. Clean scaling therefore shows as ticks(N MHz) ≈
  ticks(1 MHz) / N; any speed-invariant component shows as a floor
  that does not divide.
- Wrapper overhead is re-calibrated per speed against an RTS stub
  (the CIA-arming I/O stores do not scale with CPU clock).
- Min of 3 samples per cell (×5 for the sub-ms routines). Turbo is
  restored to 1 MHz on exit (shared device).

## Results (2026-07-26, Ultimate 64 Elite)

| routine | 1 MHz wall | 16 MHz wall | 48 MHz wall | speedup @ 48 MHz | ideal |
|---------|-----------:|------------:|------------:|-----------------:|------:|
| `aead_encrypt` n=1024 | 1 647.4 ms | 102.9 ms | 35.0 ms | **47.0×** | 48× |
| `chacha20_block`      | 39.9 ms | 2.35 ms | 0.80 ms | ~48× (in jitter) | 48× |
| `poly1305_block`      | 12.1 ms | 0.72 ms | 0.24 ms | ~48× (in jitter) | 48× |

Raw ticks: `aead_encrypt n=1024` 1 623 065 / 101 397 / 34 524
(ratios 16.01× and 47.01×); `chacha20_block` 39 330 / 2 318 / 789;
`poly1305_block` 11 951 / 706 / 241. Sample spread at 48 MHz is
~60–90 ticks, which dominates the sub-1000-tick routines — their
min-of-N ratios land within jitter of ideal and slightly across it
(the raw table renders 49.8×/49.6× for the two block routines, which
is sampling noise, not super-linear scaling); the n=1024 AEAD row
(spread ≤ 0.25% of reading) is the load-bearing measurement.

## Interpretation

- **16.0× at 16 MHz and 47.0× at 48 MHz on the full AEAD path** —
  98% of the ideal clock ratio, i.e. no measurable speed-invariant
  floor. Consistent with the static audit: zero REU DMA and zero I/O
  register access anywhere in the library.
- 64 MHz was firmware-rejected on the Elite-generation test device
  (HTTP 400; that enum value exists only on the C64 Ultimate
  generation). The scaling conclusion does not depend on it; anyone
  with a C64U can extend the sweep with `--speeds 1,16,48,64`.
- Practical numbers for consumers: a 1024-byte AEAD encrypt costs
  ~1.65 s on a stock C64 (Profile A) and ~35 ms at 48 MHz.

## Reproduction

```
make profile-a
U64_HOST=<addr> python3 tools/bench_turbo_sweep.py --speeds 1,16,48 --samples 3
```

(`--md <path>` writes the results table only; this file adds the
surrounding methodology by hand — write the table elsewhere and
merge rather than clobbering this doc.)
