# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Portability + tooling + correctness sprint. Adds a runtime REU
layout API for downstream coexistence, an n-sweep benchmark mode
for packet-size sensitivity work, and corrects a planning-doc claim
about REU/Shoup caching that doesn't survive the per-packet `r`
dependency. Minor `poly1305_final` loop fuse contributes a
consistent ~200 cy / packet on both profiles (below per-measurement
noise but signal across the 20-point sweep).

### Added
- **Granular per-symbol benchmark** (`tools/bench_granular.py`, `make
  bench`, `make bench-check`). Adds 14 per-routine cycle-count rows
  (chacha20_quarter_round, chacha20_block, chacha20_encrypt n=64/1024,
  poly1305_multiply, poly1305_reduce, poly1305_block,
  aead_compute_tag, aead_verify_tag, sqtab_init, ct_mul_8x8, plus
  aead_encrypt n=0/64/1024) so perf regressions can be attributed to
  a specific symbol. Reuses the existing CIA #1 Timer A+B 32-bit
  wrapper at `$C080` from `tools/benchmark_chacha20_poly1305.py`;
  `set_turbo_mhz(client, 1)` after reset on the U64 path. `make
  bench-check` diffs against a committed baseline JSON
  (`docs/BENCH_REPORT.baseline.json`) and exits non-zero on >1%
  drift. See `docs/BENCH_GRANULAR.md` for the methodology and
  reachability matrix.
- **Turbo-hygiene fix** in `tools/audit_cross_check.py`,
  `tools/ct_mul_brute_check.py`, `tools/test_chacha20_poly1305.py`:
  one-line `set_turbo_mhz(client, 1)` after `client.reset()` on the
  U64 path so a sibling agent's bench (at e.g. 48 MHz) cannot leak
  CIA-rate mismeasurement into these (non-timing-sensitive but
  device-sharing) tools, and vice versa.

### Added
- **Runtime-configurable REU layout** (PR — sprint). Two new
  exported public RAM-backed symbols, both 8-bit cells in DATA:
  - `poly1305_reu_sqtab_bank` — REU bank for sqtab backup
  - `poly1305_reu_sqtab_offset` — 2-byte LE REU offset (lo, hi)
  Consumers may write to these cells *before* calling
  `poly1305_lib_init` to relocate the 1 KB sqtab backup region (e.g.,
  to coexist with c64-x25519 banks 0-1). Defaults remain `bank=0,
  offset=$0000`, baked at link time from the existing assemble-time
  defines (`POLY1305_REU_BANK` / `POLY1305_REU_OFFSET`), so existing
  consumers that never touch the cells get identical behavior to
  v0.5.0. See `docs/API.md` §"REU layout configuration" for the
  protocol and overhead notes (+6 cy on the cold REU-DMA-setup path,
  invisible against the ~5 k cy DMA cost).
- **`--sweep` benchmark mode** in `tools/benchmark_chacha20_poly1305.py`
  (additive flag, doesn't break n=0/n=1024 single-shot mode). Sweeps
  `aead_encrypt` across n=[16, 32, 64, 128, 192, 256, 384, 512, 1024,
  1500] per profile, emits a markdown comparison table with the new
  `--sweep-md <path>` flag. Used to capture v0.5.0 baseline at
  `docs/BENCH_NSWEEP_v0.5.0.md` and resolve the previously-unmeasured
  short-packet regime.
- **`docs/BENCH_NSWEEP_v0.5.0.md`** — packet-size sweep baseline for
  v0.5.0 (commit `5bdf535`). Documents the Profile A / Profile B
  crossover point at **n ≈ 64** (Profile B wins at n=16-32, ties at
  n=64, loses badly beyond) — this replaces the README's previously
  documented "n ≥ 256" crossover claim, which the data does not
  support.

### Changed
- **`poly1305_final` (in `src/lib/poly1305_lib.s`) fuses the trailing
  `h += s` and tag-output loops** into a single 16-iteration loop
  (commit `fb314a9`). Eliminates one full loop's overhead plus a
  redundant `lda poly_h,x`. Measured `aead_encrypt` Profile A n=0
  −221 cy; n=1024 −167 cy. Profile B n=0 −227 cy; n=1024 −65 cy
  (in-noise). Constant-time preserved (straight-line, no
  data-dependent branches).
- **`chacha20_encrypt` register handling** (commit `f9f9c00`):
  drops the redundant `sta cc20_buf_pos` ahead of the XOR loop and
  drives the data-pointer ADC off `tya` from the in-flight loop
  counter. Cumulative ≈ −10 cy at n=1024 (below per-measurement
  noise; clean-up only).
- **PRG fingerprints update.** Reference builds at sprint HEAD:
  - profile-a: `b1c2a68f3a39593231a5d3bd1c0f15db`
  - profile-b: `4afe54d466ad92ca38b91c94a2ea2b36`

### Fixed
- **`ct_mul_8x8` SMC target-site operand is now derived from
  `sqtab_lo` / `sqtab_hi` equates** instead of literal `$8000` /
  `$8200` immediates (`src/lib/poly1305_lib.s`). The SMC *dispatch*
  (the hi-byte patch math driving `SMC_StoreHighByte smc_{lo,hi}_addr`)
  was already equate-driven via `lda #>sqtab_lo` /
  `adc #(>sqtab_hi - >sqtab_lo)`; only the *target site* (the
  `lda abs,x` placeholder bytes) still embedded the default base.
  Behavior is unchanged under documented use — `ct_mul_8x8` always
  patches the hi byte before the indexed load executes — but the
  static image was out of sync with a consumer override
  (`-DLIB_SHARED_SQTAB_BASE=$<addr>`) until the patch ran.
  Defense in depth: assembled bytes are now `BD 00 <hi(sqtab_lo)>` /
  `BD 00 <hi(sqtab_hi)>` from the start. Default standalone build is
  byte-identical to v0.5.0 on both profiles
  (profile-a md5 `79deb98c…`, profile-b md5 `4afe54d4…`). 214/214
  tests pass on default profile-a, default profile-b, and an
  `LIB_SHARED_SQTAB_BASE=$7800` override build. Issue #40 audit
  follow-up; semver PATCH (v0.5.1).
- **`docs/OPTIMIZATION_PLAN.md` retracts the "Optional Step 10 REU
  Shoup-table preload" claim** (commit `b3eac9b`). The original
  proposal conflated the r-independent quarter-square table (sqtab —
  legitimately REU-cacheable, already shipped via
  `poly1305_reu_restore`) with the r-dependent Shoup per-r tables
  (which must rebuild every packet because `poly_r` is derived per-
  packet from the ChaCha20 OTK keystream). RETRACTED blockquotes
  added inline at the three affected passages; original text kept
  visible behind strike-through for traceability. New "Lessons"
  subsection in §8 codifies the r-independent vs r-dependent rule
  for future REU work.

### Sprint findings (not code changes, but worth recording)
- **ChaCha20 perf ceiling effectively reached.** Two proposed
  optimizations — C9 rotl32_8 offset-rename and the
  rotl32_8 + rotr32_1 fusion at the rotl-7 site — targeted dead-code
  macros. `rotl32_8_zp` and several sibling macros are defined in
  `chacha20_lib.s` but never called from production; rot-8 / rot-16
  were absorbed into compile-time operand renames in commit
  `71fabf3` (C3, v0.3.0). Future analyses of ChaCha20 should
  verify call-site reachability before estimating cycle wins.
- **BSS is not zero-cleared in this project.** The c64.cfg layout
  declares `BSS` as `type=bss` without `fill`, so BSS values are
  load-image undefined. New state cells must live in `.segment
  "DATA"` with explicit `.byte` initializers; this is now the
  pattern for the new REU layout cells. Documented in `data_lib.s`
  header comments since at least v0.4.0.
- **A/B crossover at n ≈ 64**, not n=256 as previously documented.
  At n=16 Profile B is ~32% faster than Profile A (159 k vs 235 k
  cy); they're within 1% at n=64; Profile A pulls ahead by 49% at
  n=1024. For short-packet workloads (handshake, alerts, DTLS
  control), Profile B remains the better choice.

## [0.5.0] — 2026-05-15

Performance release: lands **C4 (branchless rotl-4 LUT)** on the
ChaCha20 quarter-round. Measured −8.8% on `chacha20_block`, flowing
through to −3.8% / −1.9% on `aead_encrypt n=1024` for Profile A /
B vs v0.4.0. Library PRGs change on both profiles — consumers
integrating PRG binaries directly should re-integrate; consumers
linking from source see the change automatically.

### Added
- **Two page-aligned 256-byte LUTs in `src/lib/data_lib.s`**
  (PR #24): `chacha_nibswap_hi_tab[V] = (V << 4) & $FF` and
  `chacha_nibswap_lo_tab[V] = V >> 4`. Both `.align 256` in a new
  `.segment "CODE"` block in `data_lib.s`. Used by the rewritten
  `rotl32_4_zp` macro to stitch the four-byte nibble rotate in
  straight-line code: `new_b_i = hi_tab[b_i] | lo_tab[b_{(i-1) mod 4}]`.

### Changed
- **`rotl32_4_zp` macro in `src/lib/chacha20_lib.s` rewritten as
  the C4 branchless LUT form** (PR #24). Replaces the prior
  asl/lsr/ora chain (~124 cy) with a straight-line stitch across
  the two new LUTs (~80 cy). Saves ~44 cy per call × 8 inlined
  sites in `chacha20_block`'s looped double-round body =
  −3 804 cy / `chacha20_block` (matches PR #22's predicted
  ~−3 520 cy; small overshoot from tighter register choice).
  Constant-time posture preserved: no data-dependent branches,
  `lda abs,x` against page-aligned tables eliminates the page-cross
  timing dependency on the secret index. The macro now also
  clobbers X (in addition to A and `zp_tmp1`); verified safe
  against all call sites in `cc20_qr_body_rest`.
- **Library PRG fingerprints updated.** v0.5.0 reference builds:
  - profile-a: `4da465a262d966059acc2038710fde87` (16 424 B,
    top CODE label `$4827`)
  - profile-b: `fbcc2d509335ff8a40b8607c7fd74837` (17 448 B,
    top CODE label `$4C27`)
  Both profiles remain under the `$5000` benchmark-plaintext-buffer
  floor. Size delta vs v0.4.0 is +685 B on both profiles: −128 B
  from the smaller `chacha20_block` body, +173 B of `.align 256`
  padding between `chacha20poly1305_lib.o` end and the new
  `data_lib.o` CODE additions, +512 B of LUT data.

### Performance

v0.5.0 cycle counts (CIA timer, 3 samples min per routine, identical
on VICE and Ultimate 64 within ±0.2%):

| routine                | v0.4.0   | v0.5.0   | Δ |
|------------------------|---------:|---------:|---:|
| `chacha20_block` (A/B) |   43 135 |   39 331 | **−8.8%** |
| `poly1305_block` (A)   |   11 948 |   11 951 | noise |
| `poly1305_block` (B)   |   37 844 |   37 950 | noise |
| `aead_encrypt n=0` (A) |  186 182 |  182 345 | −2.1% |
| `aead_encrypt n=0` (B) |   84 560 |   80 749 | −4.5% |
| `aead_encrypt n=1024` (A) | 1 686 764 | 1 623 299 | **−3.8%** |
| `aead_encrypt n=1024` (B) | 3 259 490 | 3 196 264 | **−1.9%** |

### Validation
- **214 / 214** RFC 7539 fixed-vector test suite passes on Ultimate
  64 (`C64_BACKEND=u64 python tools/test_chacha20_poly1305.py`).
  The rotation sub-group is **70 / 70** — load-bearing correctness
  check for the C4 macro (covers all 80 logical
  `rotl32_4_zp` invocations per `chacha20_block` via the dynamic
  `chacha20_quarter_round` test entry).
- Profile A and Profile B PRG fingerprints reproducible from clean
  checkout.

### Security
- **No CT posture regression.** The new macro has zero data-dependent
  branches; both LUTs are `.align 256` so `lda abs,x` against them
  is strictly constant-time. v0.4.0's GREEN audit verdict
  (F1/F2/F3 resolved) carries forward unchanged — C4 modifies only
  the ChaCha20 rotation primitive, which was already CT-clean in
  v0.4.0 via the asl/lsr/ora chain; the LUT form preserves that
  property by construction.

### Re-implementation history
- This release re-implements [PR #22](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/22),
  which had originally landed C4 but was closed unmerged with its
  head branch unrecoverable. The current implementation follows
  the spec from the closed PR (macro identity, LUT shapes,
  page-alignment rationale) but is byte-different from the lost
  binary — PR #22's predicted md5 fingerprints
  (`418ce549…` / `27a71517…`) reflected that PR's specific
  register/sequencing choices, not the spec itself. The 214-test
  suite is the load-bearing correctness check, and it passes
  cleanly on both profiles.

## [0.4.0] — 2026-05-10

First release with **Ultimate 64 (U64) hardware backend support** for
the validation tooling. The four tooling scripts under `tools/`
(`test_chacha20_poly1305.py`, `audit_cross_check.py`,
`ct_mul_brute_check.py`, `benchmark_chacha20_poly1305.py`) now route
all 6502 `jsr` calls through a backend-agnostic shim, so the same
test/audit/bench flows that ran on VICE in v0.3.x now also run on a
real Ultimate 64 over the network at full silicon speed. Library
PRGs (`build/c64_chacha20_poly1305.prg`) are unchanged on both
profiles — the changes are entirely in the Python tooling and in two
ca65 source equates that make the Profile A REU stash destination
configurable.

### Added
- **U64 backend across the four tooling scripts.** All four
  `tools/*.py` scripts now select VICE or Ultimate 64 at runtime via
  `C64_BACKEND={vice|u64}` (and `U64_HOST=<ip-or-hostname>` for U64).
  VICE remains the default; existing flows are unaffected. Tested on
  Ultimate 64 Elite firmware 3.14d at `10.43.23.81`.
- **Backend-agnostic shim at `tools/_u64_helpers.py`.** New
  `run_subroutine(manager, addr)` and `measure_cycles(manager, addr)`
  helpers that dispatch on the underlying transport: on VICE they
  call `c64_test_harness.execute.jsr` directly; on U64 they drive a
  small trampoline at `$0360..$0377` that wraps `jsr <target>` with
  a sentinel-write + status flag + re-arm flag, polled by the host
  over the U64 control socket. `measure_cycles` returns true cycle
  counts on both backends via the existing CIA-timer wrapper.
- **`audit_cross_check.py --vectors N` CLI flag** for runtime
  budgeting. Defaults to the v0.3.x value of 15 000 vectors per
  profile. The U64 acceptance gate runs at `--vectors 1000` to fit a
  ~20 min walltime; see harness issue
  [#82](https://github.com/JC-000/c64-test-harness/issues/82).
- **`benchmark_chacha20_poly1305.py --backend` CLI flag.** Was
  previously hardcoded to `vice`; now accepts `vice` or `u64` and
  defaults to whatever `C64_BACKEND` selects (VICE if unset).
- **Configurable REU destination for Profile A sqtab backup**
  (issue #19). Two new `.ifndef`-guarded equates in
  `src/lib/constants_lib.s` — `POLY1305_REU_BANK` (default `0`) and
  `POLY1305_REU_OFFSET` (default `$0000`) — let downstream projects
  relocate the 1 KB quarter-square table that `poly1305_lib_init`
  stashes to REU under `POLY1305_REU=1`. Motivating use case:
  co-installing this library with `c64-x25519`, which already
  occupies REU banks 0-1. Override at assemble time via
  `ca65 --asm-define POLY1305_REU_BANK=3
  --asm-define POLY1305_REU_OFFSET=$1000`, or by `.include`'ing a
  project-wide layout header that defines them before
  `constants_lib.s` is included. The equates are gated on
  `POLY1305_PROFILE_LONG` + `POLY1305_REU`, so Profile B and non-REU
  Profile A builds are unaffected.

### Changed
- **`test_chacha20_poly1305`, `audit_cross_check`, `ct_mul_brute_check`,
  `benchmark_chacha20_poly1305` route their JSRs through the
  backend-agnostic shim** instead of calling
  `c64_test_harness.execute.jsr` directly. The `tools/` flows pick
  up VICE or U64 transparently from `C64_BACKEND` / `U64_HOST` with
  no per-test code changes.
- **Bench cycle measurement reworked.** VICE keeps the existing
  CIA-timer wrapper unchanged; U64 reuses the same wrapper via the
  shim, with a tolerance-window wrapper-verify (`501 ± jitter` on
  VICE, `501 ± max(spread, 50)` on U64) sourced from the bench's own
  calibration data. This absorbs the few-cycle silicon jitter
  observed on real U64 hardware without weakening the VICE gate.
- **Profile A + `POLY1305_REU=1` PRG grows by 8 bytes** at default
  equates (issue #19). The compact 11-byte `lda #$00 / sta $DF04 /
  sta $DF05 / sta $DF06` sequence inside `poly1305_lib_init`'s
  stash block and `poly1305_reu_restore` is now a 15-byte
  override-aware form (`lda #<POLY1305_REU_OFFSET` / `sta $DF04` /
  `lda #>POLY1305_REU_OFFSET` / `sta $DF05` /
  `lda #POLY1305_REU_BANK` / `sta $DF06`) because the three DMA
  register destinations no longer share a value. +4 bytes per block
  × 2 blocks = 8 bytes total. The shift propagates through labels
  in `shoup_init`, `poly1305_clamp`, `sqtab_init`, and `mul_8x8`
  until the `.align 256` boundary at `poly_reduce_shl6_tab` ($1D00)
  absorbs it. Runtime semantics with default equates are unchanged.
- **Non-REU Profile A PRG is bit-identical to v0.3.1** (md5
  `313300ff4d86cefc6d3b195563c1383d` preserved). The new code lives
  entirely inside `.ifdef POLY1305_REU`, so the default `make
  profile-a` build does not touch it.

### Fixed
- **VICE 3.10 + macOS-26 autostart hang.** The default
  `-autostart` VirtualFS mode hangs in an IEC busy-wait on
  macOS-26 builds of VICE 3.10 when the harness pre-loads a PRG.
  All four `tools/*.py` scripts now pass `-autostartprgmode 1`
  (RAM-injection autostart), which sidesteps the IEC path entirely.
  No effect on Linux VICE flows.

### Validation
- **Acceptance gate on Ultimate 64 Elite (firmware 3.14d):**
  Profile A and Profile B fully GREEN under the standard
  `C64_BACKEND=u64 AUDIT_VECTORS=1000` baseline — 142/142 RFC 7539
  fixed vectors per profile; 1 000/1 000 random AEAD vectors per
  profile cross-checked against `pyca/cryptography`; 65 536/65 536
  exhaustive `(a, b)` pairs for `ct_mul_8x8`; bench cycle counts
  within ±0.2% of the v0.3.0 VICE baselines on every routine.
- **VICE 3.10 + macOS-26 quick-verification:** probe 4/4,
  `ct_mul_brute_check` 65 536/65 536, `test_chacha20_poly1305`
  Profile A + Profile B 142/142 each. (Test-runner exit codes are
  non-zero due to a harness teardown bug surfaced by this work,
  tracked at harness issue
  [#79](https://github.com/JC-000/c64-test-harness/issues/79); all
  crypto assertions pass before the teardown `AttributeError`.)

### Known limitations
- **Audit reduced from 15 000 → 1 000 vectors per profile** in the
  U64 acceptance gate, to fit a ~20 min walltime. VICE still runs
  the full 15 000. Rationale and follow-on harness work tracked at
  [#82](https://github.com/JC-000/c64-test-harness/issues/82).
- **VICE gate exit-code hygiene blocked on harness
  [#79](https://github.com/JC-000/c64-test-harness/issues/79).**
  Test-runner returns non-zero on Profile A/B suites due to an
  `AttributeError` in the harness teardown path, but every crypto
  assertion passes before the failure. Crypto correctness is
  verified; the exit-code cleanup is a downstream harness fix.

### Follow-on harness work
This release surfaced a portability backlog in the
`JC-000/c64-test-harness` package, filed as
[issues #76–#85](https://github.com/JC-000/c64-test-harness/issues?q=is%3Aissue+76..85).
Resolving these will let v0.5.x simplify the
`tools/_u64_helpers.py` shim and remove the harness-side
workarounds.

## [0.3.1] — 2026-04-14

A patch release on top of v0.3.0 covering two post-release polish
PRs plus a small set of distribution and documentation cleanups.
The shipped library binaries are **bit-identical to v0.3.0** on
both profiles; consumers who already integrate v0.3.0 PRGs need
not re-integrate for v0.3.1.

### Added
- **`LICENSE` at repo root — MIT** (Copyright © 2026 JC-000).
  Vendored third-party code under `src/include/` retains upstream
  licenses: `ca65hl/` MIT (Julian Terrell), `smc.inc` zlib license
  (Christian Krüger). README gains a short License section.

### Changed
- **SMC sites now use `src/include/smc.inc` macros** (PR #17).
  Five hand-rolled self-modifying-code sites have been converted to
  the matching `smc.inc` `SMC` / `SMC_StoreLowByte` /
  `SMC_StoreHighByte` / `SMC_StoreValue` macros: the two AEAD
  partial-block dispatch sites in `chacha20poly1305_lib.s`
  (`@partial_smc`, `@zfill_smc`); the Profile A `shoup_init`
  incremental Shoup-table build in `poly1305_lib.s` (six page-byte
  patches plus one immediate); and the two Profile B `ct_mul_8x8`
  primitive sites in `poly1305_lib.s` (the self-patched abs,x
  hi-byte patches inside the primitive and the J-outer immediate
  patches in `poly1305_multiply`). Placeholder bytes inside each
  `SMC label, { statement }` block are preserved literally
  (`#$00`, `lda $8000,x`, etc.), so the generated PRG is
  bit-identical to v0.3.0 on both profiles. The cosmetic benefit
  is removal of the `+1` / `+2` off-by-one footgun: future SMC
  edits select the operand byte by name instead of by hand-counted
  offset.

### Fixed
- **`tools/test_chacha20_poly1305.py` no longer destructively
  auto-rebuilds** (PR #16). The test harness previously ran
  `make clean && make` unconditionally at startup, which defaulted
  to Profile A regardless of which profile had been pre-built.
  This caused sequential in-session Profile A → Profile B
  test-then-bench flows to silently return wrong-profile numbers
  (a Profile B bench against a freshly-clobbered Profile A PRG).
  The harness now expects the caller to pre-build via
  `make profile-a` or `make profile-b` and fails loudly if
  `build/c64_chacha20_poly1305.prg` is missing. The
  `C64_SKIP_BUILD=1` environment variable is retained as a no-op
  for backward compatibility with consumer scripts that set it.
  Aligns the harness with the bench harness and `examples/smoke_test/`
  pre-build conventions.

### Docs
- `docs/INTEGRATION.md` (PR #16): added a "Testing from a
  consumer project" subsection documenting the pre-build
  convention shared by `tools/test_chacha20_poly1305.py`,
  `tools/benchmark_chacha20_poly1305.py`, and
  `examples/smoke_test/run_smoke_test.py`.
- `docs/OPTIMIZATION_PLAN.md` (PR #17): added a Task #9 row to
  the progression table and a note explaining the cosmetic
  refactor.

### Security
- **No security-relevant changes.** v0.3.0's constant-time posture
  (F1/F2/F3 resolved, GREEN audit verdict in `docs/AUDIT.md`) is
  unchanged. PRG binaries are bit-identical to v0.3.0; consumers
  that ship v0.3.0 binaries need not re-integrate for v0.3.1.

## [0.3.0] — 2026-04-13

First release of the library as an external-consumer target. Two
performance sprints (S1–S10, S11–S13) are now folded in, the build
system has moved from ACME to ca65, and the full audit documentation
set ships with the repository.

### Added
- ca65 + ld65 toolchain with per-module `.o` builds, replacing the
  monolithic ACME build. Both Profile A and Profile B link from the
  same object set via `src/c64.cfg`.
- `src/include/ca65hl/` (Movax12's ca65hl macro pack) and
  `src/include/smc.inc` (cc65's self-modifying-code helper) vendored
  onto the include path for downstream consumers.
- `examples/smoke_test/` — minimal external-consumer template showing
  the expected include order, ZP layout, and call sequence.
- `docs/AUDIT.md`, `docs/API.md`, `docs/MEMORY_MAP.md`,
  `docs/INTEGRATION.md` — consumer-facing documentation covering the
  per-branch constant-time audit, the public API, the fixed memory
  map, and the integration contract.
- `tools/audit_cross_check.py` — 30 000 random AEAD vectors
  (15 000 per profile) checked against
  `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
- `tools/ct_mul_brute_check.py` — exhaustive 65 536-pair
  brute-force correctness gate for the new `ct_mul_8x8` primitive
  introduced by the v0.3.0 CT fix.
- `docs/CT_ANALYSIS.md`, `docs/REPRO_CHECK.md`, and
  `docs/design/ct_mul_8x8.md` — per-branch CT audit, reproducibility
  record, and the design memo for the Profile B branchless multiply.
- Sprint-2 structural addition: `poly1305_lib_init` public one-time
  setup entry point (carried over from S10).

### Changed
- Profile A `shoup_init` — the 16 Shoup per-r tables are now built by
  a straight-line ripple-add (`T_j[k] = T_j[k-1] + r[j]`) instead of
  4 096 `mul_8x8` calls. This is the S11 change and collapses the
  per-packet `poly1305_init` fixed cost from ~438 k cy to ~118 k cy.
- Profile B `poly1305_multiply` — the schoolbook multiply primitive
  has been replaced by a new branchless constant-time 8×8 multiply
  `ct_mul_8x8` (v0.3.0 CT fix, commit `dc4c575`). The Step-12
  `mult66` primitive and its `sqtab2_lo/hi` companion tables at
  `$8400..$87FF` have been **removed**; Profile B now reuses the
  same 1 KB `sqtab_lo`/`sqtab_hi` that Profile A uses, driven via
  SMC-patched `abs,x` loads. The J-outer / I-inner loop reversal
  and 16-byte straight-line block-add (P7) from S12 are retained.
  See `docs/design/ct_mul_8x8.md` for the design memo.
- ChaCha20 `chacha20_block` — the 64-byte `state → work` copy prelude
  is now fully unrolled straight-line code (C8, S13), and the row-0
  words of the expand-32-byte-k constants are baked in as `lda #imm`
  / `adc #imm` in the prelude and the `work += state` tail (C5 sites
  1 + 3, S13). Site 2 (first column round a-operand bake) is deferred
  — see S13 notes in `docs/OPTIMIZATION_PLAN.md` for why.

### Performance (vs `v0.2-optimized`)

Measured on the merged v0.3.0 release-candidate commit `f4f049e`
via `tools/benchmark_chacha20_poly1305.py --seed 7539`, 3 samples,
min per routine. These numbers supersede every pre-CT-fix draft
figure: the CT fix reshaped the Profile B hot path (F3 resolution)
and contributed a small Profile A win (F2 resolution). See
`docs/REPRO_CHECK.md` §4 for the full post-CT-fix bench table.

| routine                            |   v0.2-optimized |           v0.3.0 |       Δ |
|------------------------------------|-----------------:|-----------------:|--------:|
| Profile A `chacha20_block`         |           44 920 |           43 135 | −4.0%   |
| Profile A `poly1305_block`         |           12 122 |           11 948 | −1.4%   |
| Profile A `aead_encrypt` n=0       |          579 280 |          186 182 | −67.9%  |
| Profile A `aead_encrypt` n=1024    |        2 197 974 |        1 686 764 | −23.3%  |
| Profile B `chacha20_block`         |           44 920 |           43 135 | −4.0%   |
| Profile B `poly1305_block`         |           38 760 |           37 844 | −2.4%   |
| Profile B `aead_encrypt` n=0       |           74 844 |           84 560 | +13.0%  |
| Profile B `aead_encrypt` n=1024    |        3 415 291 |        3 259 490 | −4.6%   |

Additional notes:
- The Profile A n=0 collapse is the S11 incremental Shoup build
  (~438 k → ~118 k cy per `poly1305_init`) plus the S10 sqtab
  one-time preload; the CT fix contributes only the `−877 cy`
  rot1 branchless win on top.
- Profile B `aead_encrypt` n=0 regresses **+13.0%** versus
  `v0.2-optimized`. Root cause: the F3 CT fix replaces the fast
  but CT-unsafe `mult66` primitive with the branchless
  `ct_mul_8x8` (see Security section below). This is a deliberate
  correctness-over-performance trade-off — Profile B still
  delivers **−45.4%** on `aead_encrypt` n=1024 versus the
  sprint-0 baseline (5 974 048 cy → 3 259 490 cy).
- Cumulative vs the S0 baseline (`923d34d`, pre-sprint),
  Profile A `aead_encrypt` n=1024 moved 5 974 048 → 1 686 764 cy,
  **−71.8%** over two sprints plus the CT fix.

### Security

The v0.3.0 release is the first with a completed per-branch
internal constant-time audit. See `docs/AUDIT.md` for the
top-level GREEN verdict and `docs/CT_ANALYSIS.md` for the full
per-branch analysis plus post-fix Resolution section.

Three pre-existing constant-time findings were discovered by the
audit and **resolved in this release** (PR #14, commit `dc4c575`):

- **F1 — `poly1305_final` h ≥ p branch.** The final reduction
  selected between `h` and `h − p` via a `bcs` branch on secret
  state. Fixed by replacing the branch with a branchless
  mask-blend: compute both candidates, derive a sign-mask from
  the borrow-out, and merge byte-by-byte. Affects both profiles.
- **F2 — `rotl32_1_zp` / `rotr32_1_zp` wrap branch.** The 32-bit
  single-bit rotates used a `bcc no_wrap` carry-propagation
  branch that took a data-dependent path on every word whose top
  bit was set. Fixed by rewriting as a branchless ASL/ROL chain.
  The two public labels were rewritten in place (not deleted)
  because `rotr32_7` falls through to `rotl32_1` and `rotl32_7`
  tail-calls `rotr32_1` via `jmp`. Affects both profiles. Bonus:
  the branchless rewrite is **faster** than the original
  (`chacha20_block` −1 346 cy per block).
- **F3 — Profile B `mult66` `(zp),y` secret-pointer load.** The
  Step-12 inner multiply loaded `r[j]+h[i]` through a
  `(zp),y`-style pointer whose effective address varied with
  secret data, producing address-dependent page-cross timing on
  certain operand combinations. Fixed by **structurally removing**
  `mult66` and its Step-12 `sqtab2` companion tables at
  `$8400..$87FF`, replacing them with a new branchless
  constant-time 8×8 multiply primitive `ct_mul_8x8` that uses
  the quarter-square identity with a sign-mask absolute-value
  step. All table loads are `abs,x` on page-aligned bases, so
  no secret-dependent addressing-mode timing remains. Profile B
  only. See `docs/design/ct_mul_8x8.md` for the design memo and
  the quantified perf/RAM trade-off.

### Validation

- **30 000 / 30 000** random AEAD vectors (15 000 per profile)
  cross-checked against `pyca/cryptography`'s reference
  `ChaCha20Poly1305` — all byte-identical
  (`tools/audit_cross_check.py`).
- **65 536 / 65 536** `(a, b)` pairs in `[0,255]²` brute-forced
  against Python's arbitrary-precision reference for the new
  `ct_mul_8x8` primitive — exhaustive correctness gate
  (`tools/ct_mul_brute_check.py`).
- **214 / 214** RFC 7539 fixed-vector test suite passes on both
  profiles at seed 7539.
- **Bit-for-bit reproducible PRG builds** across clean rebuild
  cycles (see `docs/REPRO_CHECK.md` §2).

This remains an internal audit rather than a third-party
security review. The library is still intended for hobbyist /
research use.

### API stability
- v0.3.x carries a backward-compatibility promise within the series:
  the public entry points (`aead_encrypt`, `aead_decrypt`,
  `poly1305_lib_init`) and the memory map documented in
  `docs/MEMORY_MAP.md` are fixed for the lifetime of v0.3.x.
- **v0.4.0 is a planned breaking release.** It will make the ZP
  slots and the table base addresses configurable via ca65 `-D`
  defines so that consumers can co-locate the library alongside
  their own code. Consumers that need address flexibility should
  expect to re-integrate at v0.4.0.

## [0.2-optimized] — 2026-04-11

Tagged from the commit that closes sprint 1 (steps S1–S8 plus the
S9 profile-documentation tag; S10 and the ca65 port landed after the
tag as pre-sprint-2 work).

### Added
- Dual build profiles. `make profile-a` targets Shoup per-r tables
  for long messages (WireGuard, TLS 1.3 records, >= 256 B amortized);
  `make profile-b` is the stock-C64 portable baseline that wins on
  short messages and zero-length AEAD.
- Profile A: 8 KB Shoup per-r table at `$6000..$7FFF`
  (16 × 2 × 256 B, page-aligned per limb).
- Profile A: REU-assisted sqtab backup (`POLY1305_REU=1`, S10).
- Per-packet AEAD glue fast paths: S8 A5 folds the OTK derivation
  into the encrypt/decrypt counter prime; A3 unrolls the zero-length
  branch; A4 adds an SMC dispatch for partial Poly1305 blocks; A6
  skips redundant re-init on decrypt.

### Changed
- ChaCha20 hot path: `cc20_work` moved to ZP (C1); all eight
  quarter-rounds of `chacha20_quarter_round` inlined into
  `chacha20_block` (C2); rot-8 and rot-16 reworked as offset renames
  (C3). `chacha20_block`: 149 987 → 44 920 cy, **−70.0%**.
- Poly1305 multiply: `poly1305_multiply` fully unrolled from its
  previous schoolbook loop (P1). Profile A: replaced with 272-entry
  Shoup per-r table lookup (P3). Both profiles: reduction rewritten
  as a single fused Donna-style wrap pass with a 256 B
  `poly_reduce_shl6_tab` (P4, the form that is realisable in
  byte-layout Poly1305).
- AEAD: `cc20_keystream = cc20_work` alias (C7), eliminating the
  64 B keystream copy per block.
- Sprint-1 sqtab-build move (S10): the quarter-square table is now
  built once at `poly1305_lib_init` time instead of per-packet,
  saving ~89 k cy per `aead_encrypt` call on both profiles.

### Performance (vs S0 baseline `923d34d`)
- Profile A `chacha20_block`: 149 987 → 44 920 cy (**−70.0%**).
- Profile A `poly1305_block`: 53 270 → 12 122 cy (**−77.2%**).
- Profile A `aead_encrypt` n=1024: 5 974 048 → 2 197 974 cy (**−63.2%**).
- Profile B `chacha20_block`: 149 987 → 44 920 cy (**−70.0%**).
- Profile B `poly1305_block`: 53 270 → 38 760 cy (**−27.2%**).
- Profile B `aead_encrypt` n=1024: 5 974 048 → 3 415 291 cy (**−42.8%**).

See `docs/OPTIMIZATION_PLAN.md` Section 8 for the full per-step
measurement table and the plan-vs-measured retrospective.

## [0.1] — 2026-04-11

### Added
- Initial release. Baseline scaffold, cycle-accurate benchmark harness,
  and independent pyca cross-check. (No tagged git release; date is
  taken from the first scaffold commit `602012e`.)
