# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
