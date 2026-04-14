# Audit Report — c64-ChaCha20-Poly1305 v0.3.0

## Scope

This audit covers commit `f4f049e` on `main` (the merge commit of
PR #14, "CT fix: F1 poly_final mask-blend + F2 chacha20 rot1
branchless + F3 ct_mul_8x8 Profile B"). The CT-fix source commit
is `dc4c575`. This is an **internal audit** performed by the
project maintainer team. It is not an external security review
and must not be relied upon for threat models where "audited"
carries legal or compliance weight.

## Methodology

- **Reproducibility check**: `make clean && make profile-a
  profile-b` executed from a clean tree; PRG md5s verified stable
  across multiple independent rebuild cycles on the merged-main
  state. See [REPRO_CHECK.md](REPRO_CHECK.md) §2.
- **Fixed-vector test suite**: 214 / 214 RFC 7539 library tests
  pass on both profiles at seed 7539
  (`tools/test_chacha20_poly1305.py`).
- **Random cross-check**: 30 000 random AEAD vectors
  (15 000 per profile) generated and checked against
  `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`
  via `tools/audit_cross_check.py`. Vectors span ChaCha20
  keystream, Poly1305 tag, AEAD encrypt, AEAD decrypt, and AEAD
  tamper-reject categories with boundary-mix and uniform-random
  length distributions up to 1024 B plaintext / 255 B AAD.
  **All 30 000 / 30 000 pass, bit-identical to pyca.**
- **`ct_mul_8x8` exhaustive brute-force**: 65 536 / 65 536
  `(a, b)` pairs in `[0,255]²` brute-forced against Python's
  arbitrary-precision `a * b` reference via
  `tools/ct_mul_brute_check.py` (2.7 s). This is the cheapest
  possible full-coverage test for an 8×8 primitive and closes
  the correctness gap for the new Profile B CT multiply.
- **Per-branch constant-time classification**: every branch in
  every `.s` file under `src/lib/` and `src/main.s` was
  classified as CT-safe, flag-derived-but-not-secret, or secret
  dependent. Three findings (F1, F2, F3) were flagged; all three
  are resolved as of this release. See
  [CT_ANALYSIS.md](CT_ANALYSIS.md) for the full per-branch table
  plus the post-fix Resolution section.
- **Public API documented**: see [API.md](API.md) for the public
  symbol list, calling conventions, clobbered registers, and
  per-routine cycle counts.
- **Memory map documented**: see [MEMORY_MAP.md](MEMORY_MAP.md)
  for the ZP claims, fixed-address tables, and consumer
  collision-risk summary.

## Verdict

**GREEN.**

Three pre-existing constant-time findings (F1, F2, F3) flagged
by the per-branch CT analysis were resolved in PR #14
(commit `dc4c575`). On both profiles, there are no known
remaining secret-dependent branches in the production AEAD hot
path and no known secret-dependent addressing-mode timing
(table loads use `abs,x` / `abs,y` on page-aligned bases
throughout the hot path; no `(zp),y` on secret-indexed pointers).
The carry-chain `bcc` branches in `add32` / `adc`-style
multi-precision arithmetic remain classified as YELLOW by plan
acceptance (terminating ripple, sign-inferred from flag state
rather than from value inspection — see
[CT_ANALYSIS.md](CT_ANALYSIS.md) §6) and are the intended
post-fix steady state for v0.3.x.

## Findings and resolutions

### F1 — `poly1305_final` h ≥ p branch (RESOLVED)

- **Origin**: pre-existing, inherited from the upstream
  `c64-wireguard` family of Poly1305 implementations.
- **Severity**: leaked bit 130 of the reduced accumulator via a
  `bcs` branch in the final-emit step of `poly1305_final`. The
  branch spread was roughly 100 cy per tag emission.
- **Scope**: both profiles (the reduction step is shared).
- **Fix**: replaced with a branchless mask-blend. The routine
  now computes both candidate outputs (`h` and `h − p`) in a
  single fixed-length sequence, derives a byte-wide sign-mask
  from the borrow-out of the subtraction, and selects between
  the two candidates via `and` / `ora` on every output byte.
  The final copy cost is ~280 cy constant per tag.
- **Resolved in**: PR #14, commit `dc4c575`.

### F2 — `rotl32_1_zp` / `rotr32_1_zp` wrap branch (RESOLVED)

- **Origin**: pre-existing, inherited from the `c64-wireguard`
  family of ChaCha20 implementations.
- **Severity**: the 32-bit single-bit rotate primitives used a
  `bcc no_wrap` / `inc` carry-propagation idiom that took a
  data-dependent path on every word whose top bit was set. The
  cumulative branch spread was roughly 960 cy per
  `chacha20_block` across all rotate call sites.
- **Scope**: both profiles (ChaCha20 is shared).
- **Fix**: rewritten as a branchless `asl` / `rol` chain that
  performs the 32-bit rotate as four chained shift/rotate
  operations with the top bit recycled into the bottom via a
  fixed-length `rol`, so the instruction stream taken is
  independent of the rotated word's top bit value.
- **Rewrite-not-delete deviation**: the `rotl32_1` /
  `rotr32_1` subroutines in `word32_lib.s` are **not** dead
  code — `rotr32_7` falls through to `rotl32_1` and `rotl32_7`
  tail-calls `rotr32_1` via `jmp`. Both labels also appear in
  the test harness required-label list at
  `tools/test_chacha20_poly1305.py:1018`. They were therefore
  rewritten branchless **in place** rather than deleted, which
  preserves all call-site and fall-through behavior unchanged.
- **Net perf impact**: the branchless rewrite is actually
  **faster** than the original because the common-case `bcc`
  penalty is gone. `chacha20_block` 44 481 → 43 135 cy
  (**−1 346 cy**, ~3% speedup) on both profiles.
- **Resolved in**: PR #14, commit `dc4c575`.

### F3 — Profile B `mult66` `(zp),y` page-cross (RESOLVED)

- **Origin**: introduced in sprint-2 Step 12 (the `mult66`
  Profile B schoolbook-multiply primitive).
- **Severity**: `mult66`'s inner loop loaded `r[j] + h[i]`
  through a `(zp),y`-style indirect-indexed pointer whose
  effective address varied with secret data. On 6502, an
  effective-address page crossing in `(zp),y` incurs an extra
  cycle, producing an address-dependent timing spread
  proportional to how often `r[j] + h[i] ≥ 256`. Max spread
  ≈ 272 cy per Profile B `poly1305_block`.
- **Scope**: Profile B only. Profile A's hot path uses the
  Shoup per-r tables and is unaffected.
- **Fix**: **structural revert** of `mult66` and its Step-12
  scaffolding. The `lmul0` / `lmul1` ZP pointer pair and the
  `sqtab2_lo` / `sqtab2_hi` companion tables at `$8400..$87FF`
  have been removed entirely. Profile B now uses a new
  branchless constant-time 8×8 multiply primitive `ct_mul_8x8`
  that computes `a * b` via the quarter-square identity
  `a*b = ((a+b)² − (a−b)²) / 4` with a branchless sign-mask
  absolute-value step for `a−b`. All table loads are `abs,x`
  on page-aligned `$8000` / `$8200` bases, so no
  secret-dependent addressing-mode timing remains.
- **Performance cost**: Profile B `poly1305_block` 27 195 →
  37 844 cy (**+10 649 cy**, +39%); `aead_encrypt n=1024`
  2 590 638 → 3 259 490 cy (**+668 852 cy**, +25.8%). Profile
  B still delivers −45.4% on n=1024 versus the sprint-0
  baseline (5 974 048 cy). This is a deliberate
  correctness-over-performance trade-off — the v0.3.0 release
  directive is correctness first.
- **Runtime RAM delta**: **−512 B** net (sqtab2 removed, no
  new tables). Profile B runtime RAM is back to ~1 KB
  (sqtab only, reused from Profile A's existing allocation).
- **Correctness**:
  - 65 536 / 65 536 exhaustive `(a, b)` brute-force pass via
    `tools/ct_mul_brute_check.py` (2.7 s Profile B).
  - 15 000 / 15 000 random AEAD cross-check vectors pass via
    `tools/audit_cross_check.py --profile b`, byte-identical
    to pyca.
  - 214 / 214 RFC 7539 fixed-vector suite on Profile B.
- **Design rationale**: see
  [design/ct_mul_8x8.md](design/ct_mul_8x8.md).
- **Resolved in**: PR #14, commit `dc4c575`.

## Sub-reports

- [Reproducibility check](REPRO_CHECK.md) — bit-for-bit PRG
  rebuild stability, bench numbers, cross-check vector results.
- [Constant-time analysis](CT_ANALYSIS.md) — per-branch CT
  classification for every `.s` file; the historical RED
  findings are preserved unchanged with a post-fix Resolution
  section appended at the bottom.
- [Memory map](MEMORY_MAP.md) — ZP claims, fixed-address
  tables, consumer collision-risk summary, and v0.4.0
  configurability plan.
- [Public API](API.md) — exported symbols, calling conventions,
  clobbered registers, per-routine cycle counts.
- [Integration guide](INTEGRATION.md) — consumer import
  mechanisms (release-tarball vendoring primary, git submodule
  secondary), wiring recipe, and smoke-test reference.
- [`ct_mul_8x8` design memo](design/ct_mul_8x8.md) — full
  rationale for the F3 fix, cycle/RAM analysis, and
  cross-project applicability notes.

## Cross-project note

Per the F3 research memo
([design/ct_mul_8x8.md](design/ct_mul_8x8.md)), four sibling
C64 cryptography projects ship the same CT bug family or a
close relative:

- `c64-x25519`
- `c64-nist-curves`
- `c64-wireguard`
- `c64-aes256-ecdsa`

The `ct_mul_8x8` primitive is portable back to them as
follow-up remediation work, not gating the v0.3.0 release of
this library. The F2 fix (`rotl32_1` / `rotr32_1` branchless
rewrite) is likewise potentially portable to any sibling that
shares the upstream ChaCha20 word-32 codepaths.

## Known limitations

- This is an **internal audit**, not an external security
  review. Do not rely on it for threat models where "audited"
  carries legal or compliance weight.
- Side-channel resistance covers **timing only**. Power
  analysis and EM analysis are out of scope (and largely
  meaningless on a typical C64 deployment).
- The memory map is **fixed in v0.3.x**. Consumers whose own
  address claims conflict with the library's `$6000..$7FFF`
  (Profile A Shoup) or `$8000..$83FF` (both profiles, sqtab)
  allocations must either (a) patch the library source, or
  (b) wait for v0.4.0, which is planned to make those addresses
  configurable via ca65 `-D` defines (see
  [MEMORY_MAP.md](MEMORY_MAP.md) "v0.4.0 plans").
- The test harness `tools/test_chacha20_poly1305.py` has a
  destructive auto-rebuild bug tracked as task #18. Workaround:
  export `C64_SKIP_BUILD=1` before invoking the harness on
  Profile B. See [REPRO_CHECK.md](REPRO_CHECK.md) §4.

## Release fingerprints

These are the v0.3.0 reference-build PRG fingerprints. They are
bit-for-bit reproducible from a clean `make clean && make
profile-a profile-b` on the merged CT-fix commit `f4f049e`.

- **Profile A** PRG: md5 `313300ff4d86cefc6d3b195563c1383d`,
  15 739 bytes, load address `$0801`
- **Profile B** PRG: md5 `a0e4b682fa454c6b8e2d8a04297333ab`,
  16 777 bytes, load address `$0801`

See [REPRO_CHECK.md](REPRO_CHECK.md) §2 for the md5 stability
table across multiple independent rebuild cycles.

## Review

- **Internal review**: project maintainer team (this session).
- **External review**: none. v0.3.0 ships as an internally
  reviewed hobbyist / research library.
