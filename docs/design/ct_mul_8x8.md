# F3 Fix Design Memo

**Task**: #19 — research-only design memo for the F3 CT fix (Profile B `poly1305_lib.s` `mult66` `(zp),y` page-cross timing channel).
**Author**: f3-researcher
**Date**: 2026-04-12
**User directive (load-bearing)**: correctness over performance. Reliable polished library first, iterate on perf later. Profile B cycle regressions are acceptable.

---

## 1. Problem Statement

`mult66` is the Profile B 8×8→16 multiply primitive introduced in S12
(commit `291925a`). It implements the quarter-square identity
`a*b = sqtab[a+b] - sqtab[|a-b|]` but eliminates the software "sum-page"
branch of the classical `mul_8x8` by caching one operand `a` into the
low byte of a ZP pointer (`lmul0`, `lmul1`) pre-biased to
`sqtab_lo`/`sqtab_hi` and then loading `sqtab[a+b]` via
`lda (lmul0),y` with `y = b`. The 9-bit sum is "auto-decoded" by 6502
indirect-indexed addressing when `lmul0.lo + y >= 256`.

That auto-decode is precisely the problem. On 6502, `(zp),y` pays
**+1 cycle** when `zp_lo + y >= 256`, i.e. when `a + b >= 256`, i.e.
when `r[j] + h[i] >= 256`. Both `r[j]` and `h[i]` are secret. The
primitive has three such loads per call (`poly1305_lib.s:565, 570, 578`)
and is called 272 times per Poly1305 block, giving a worst-case spread
of ~272 cycles per block on a predicate that is a function of the
product of two secrets. This is **F3** in `CT_ANALYSIS.md §2`.

`ct-fixer` (task #17) paper-checked four variants (X/Y/Z/α) that tried
to patch mult66 in place while staying under a +3.5% Profile B
`poly1305_block` performance budget. All four blew the budget by an
order of magnitude in paper accounting. This memo re-examines the
fix space under the relaxed "correctness over performance" directive,
starting with the user's own hypothesis that a revert to pre-S12 code
may be cheaper than a rebuild.

**Scope**: F3 only. F1 (`poly1305_final` h≥p branch) and F2
(ChaCha20 `rotl32_1_zp`/`rotr32_1_zp` wrap branch) are straightforward
branchless rewrites per the task #17 brief and should ride in the same
PR as F3 but are out of scope for *this* memo.

---

## 2. Pre-S12 Revert Analysis

### 2.1 Historical source recovered

Pre-S12 state of `src/lib/poly1305_lib.s` = **commit `7752545`**
(merge of PR #11, "Step 11: incremental Shoup build"). This is the
immediate parent of S12 (`291925a`).

Recovered via `git show 7752545:src/lib/poly1305_lib.s`. The file is
875 lines, 46 lines of diff added by S12. The pre-S12 8×8 primitive
is `mul_8x8` at lines 398–444 of the historical file.

### 2.2 Pre-S12 `mul_8x8` classification

Copy of the primitive (from the historical dump):

```
mul_8x8:
        sta mul_a
        stx mul_b
        clc
        adc mul_b               ; A = a+b (low), C = sum-page bit
        tax
        lda #0
        adc #0
        sta mul_s_pg

        lda mul_a               ; |a-b| branch:
        sec
        sbc mul_b
        bcs :+                  ; <-- secret-dep branch on (a>=b)
        eor #$ff
        adc #1
:       tay

        lda mul_s_pg
        beq @s0                 ; <-- secret-dep branch on sum-page bit
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
@s0:
        lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
```

**Two secret-dep branches**:

1. **`bcs :+` at the |a-b| computation**. Branches on the borrow from
   `sbc mul_b`, equivalent to `(a >= b)`. Both `a` and `b` are secret.
   Taken branch = 3 cy, not-taken = 2 cy. Same cycle-spread class as
   F3 but via branch-timing rather than page-cross. **SECRET, RED.**

2. **`beq @s0` at the sum-page selection**. Branches on
   `mul_s_pg = ((a+b) >> 8) & 1`, i.e. whether the sum fell into
   page 0 or page 1 of `sqtab`. Taken = 3 cy, not-taken = 2 cy.
   Same leak class. **SECRET, RED.**

Both branches have both arms as straight-line code that access
page-aligned `sqtab_{lo,hi}` via `abs,x` and `abs,y`, so no
page-cross channels in either arm. The *only* CT issues are the two
branches themselves.

### 2.3 Comparison with other c64-*-crypto projects

Cross-checked against the rest of the c64-crypto family in
`/home/someone/`:

| Project                                  | File                    | `mul_8x8` status |
|------------------------------------------|-------------------------|------------------|
| `c64-x25519`                             | `src/mul_8x8.s`         | **Identical** CT bug: same `bcs :+` and `beq @s0`. |
| `c64-nist-curves`                        | `src/mul_8x8.s`         | **Identical** CT bug. |
| `c64-wireguard`                          | `src/poly1305.asm`      | **Identical** CT bug. |
| `c64-aes256-ecdsa`                       | (`fp_init_sqtab` parent) | Presumed identical (not re-read — pre-S12 comment cites it as origin). |
| `c64-x25519`                             | `src/fe25519.s:832–915` | `mult66` variant with the **same F3 page-cross bug** as our S12 code PLUS an additional `beq @sqr_nonzero_j` early-exit branch that our S4 already removed from our copy. |

**Finding**: the entire `c64-*-crypto` family shares the same CT-broken
`mul_8x8` ancestor. None of these sibling projects has solved CT for
8×8 multiply. The F3 fix for this project is essentially new prior-art
territory for the 6502 C64 crypto family. Whatever we land here
should be portable back to the other projects as a follow-up.

### 2.4 Revert verdict

**REVERT-NOT-VIABLE (as literal revert).** Pre-S12 `mul_8x8` is not
CT-clean; it trades one leak family (F3 `(zp),y` page-cross, 272-way
per block) for another (two secret-dep branches per call, also
272-way per block). Net CT posture: equivalent, both are RED.

**However** the pre-S12 *structural* shape is the right starting
point for the fix, because it:

- Uses `abs,x` / `abs,y` exclusively for the table loads (page-aligned,
  never page-cross — the addressing mode is intrinsically immune to
  F3's leak class).
- Needs only the existing 1 KB `sqtab_lo`/`sqtab_hi`. The
  `sqtab2_lo`/`sqtab2_hi` helper table introduced by S12 (512 B at
  `$8400..$87FF`) and its `sqtab2_init` builder become dead code and
  can be deleted — **saving 512 B of runtime RAM**.
- Needs no ZP pointer pair (`lmul0`/`lmul1`). Two zero-page slots
  free up.
- Is already the primitive used by all the sibling `c64-*-crypto`
  projects, so a CT-fix to this shape is portable back to them.

The two branches in the pre-S12 shape can be rewritten branchlessly
(detailed in §3.1 below) for roughly the same cost as any CT
rebuild-from-scratch — the branchless form is ~78 cy per 8×8 call
either way because both paths have to do the same table lookups.

**Verdict**: reject literal revert. Recommend "structural revert"
(drop S12's `sqtab2` + `lmul0`/`lmul1` + `mult66` primitive) followed
by a branchless rewrite of the pre-S12 `mul_8x8` as a new
`ct_mul_8x8` primitive. This is effectively §3.1 below.

---

## 3. Alternative CT-Clean Multiply Designs

All cycle counts re-derived from scratch against the current code
shape per `project_plan_estimate_translation.md`. Baseline: current
`mult66` = **~46–50 cy per call** including `jsr`/`rts`
(tya/sec/sbc/tax/lda(z),y/bcs/sbc abs,x/sta/lda(z),y/sbc abs,x/sta/rts
+ the `jsr` at call site). 272 calls per poly1305_block. Current
Profile B `poly1305_block` ≈ **27 032 cy** (per `docs/OPTIMIZATION_PLAN.md`
S12 row).

### 3.1 CT-Quarter-Square — branchless pre-S12 rewrite  (RECOMMENDED)

**Mechanism**. Same quarter-square identity as pre-S12
`mul_8x8`, but with both secret-dep branches replaced by branchless
sequences:

1. **Sum-page branch** (`beq @s0`) → **SMC-patched hi-byte of an
   `abs,x` load**. Compute sum + carry; add carry to `#>sqtab_lo`;
   store the result as the hi-byte of the `lda abs,x` operand
   (via `sta smc_lo_addr+2`). Same trick `poly_reduce_shl6_tab`
   already uses (`poly1305_lib.s:694` is explicitly `.align 256`
   for this exact reason — the authors were CT-aware of page-cross
   channels). Both sqtab pages are handled by the same straight-line
   code after the SMC patch.

2. **|a-b| branch** (`bcs :+`) → **sign-mask trick**. Compute
   `raw = a - b`; capture the sign via `sbc #0` into a mask byte
   (`$00` if `a >= b`, `$FF` if `a < b`); `eor` raw with mask;
   `sbc` the mask (subtracting `$FF` adds 1 with carry set,
   subtracting `$00` is a no-op). Result: `|a-b|` in Y.

**Primitive (draft, ca65 syntax)**:

```asm
; Pre-baked (once per outer-j iteration in poly1305_multiply):
;   smc_sum_a_imm + 1 = r[j]    ; via sta at outer-j entry
;   smc_diff_a_imm + 1 = r[j]   ; via sta at outer-j entry
; Entry: Y = h[i]
; Exit:  poly_prod_lo/hi = r[j] * h[i]

ct_mul_8x8:
        ; === Sum and SMC-patch of the two abs,x load hi-bytes ===
        tya                             ; 2    A = b
        clc                             ; 2
smc_sum_a_imm:
        adc #$00                        ; 2    SMC = a; A = a+b, C = sum page
        tax                             ; 2    X = (a+b).lo
        lda #>sqtab_lo                  ; 2    A = $80
        adc #0                          ; 2    A = $80 or $81
        sta smc_lo_addr+2               ; 4    patch abs,x hi byte
        adc #$02                        ; 2    A += (sqtab_hi - sqtab_lo).hi
        sta smc_hi_addr+2               ; 4    patch second abs,x hi byte

        ; === Branchless |a-b| → Y ===
        tya                             ; 2    A = b again
        sec                             ; 2
smc_diff_a_imm:
        sbc #$00                        ; 2    SMC = a; A = b-a, C = (b>=a)
        sta diff_raw                    ; 3
        lda #0                          ; 2
        sbc #0                          ; 2    A = $00 if b>=a else $FF
        sta sign_mask                   ; 3
        eor diff_raw                    ; 3    (raw XOR sign)
        sec                             ; 2
        sbc sign_mask                   ; 3    -sign: +0 if b>=a, +1 if b<a
        tay                             ; 2    Y = |a-b|

        ; === Table loads (both arms now straight-line, abs,x / abs,y,
        ;     all page-aligned, never page-cross) ===
smc_lo_addr:
        lda $8000,x                     ; 4    SMC = sqtab_{lo,lo+1}
        sec                             ; 2
        sbc sqtab_lo,y                  ; 4
        sta poly_prod_lo                ; 3
smc_hi_addr:
        lda $8200,x                     ; 4    SMC = sqtab_{hi,hi+1}
        sbc sqtab_hi,y                  ; 4
        sta poly_prod_hi                ; 3
        rts                             ; 6
```

**Cycle count**: 22 (sum/SMC) + 26 (abs block) + 30 (loads + rts)
= **78 cy per call**, + `jsr` 6 cy = **84 cy per call at caller site**.

Vs current `mult66` ~50 cy: **+34 cy per call**.

**Per-block regression**: +34 × 272 = **+9 248 cy**.

**Profile B `poly1305_block`**: 27 032 → ~36 280 cy ≈ **+34%**.

**Profile B `aead_encrypt n=1024`** (scales ~linearly with block count,
64 full blocks + glue): ~+630 k cy from 2 598 896 → ~3 229 k cy
≈ **+24%**. Still **~36% improvement over the sprint-0 baseline**
(2 598 896 was already −65% from sprint-0's ~7.4 M cy per
`docs/OPTIMIZATION_PLAN.md`). Profile B remains a meaningful
optimization over the baseline even with this regression.

**Profile B `aead_encrypt n=0`** (mostly AAD + length block, 2
poly1305_block calls): +18 496 cy on top of a ~50 k baseline
≈ **+37%** on n=0. This is the profile intended for short packets
(TLS handshake, WireGuard short messages) — the regression hurts
more here in relative terms but the absolute cycle count stays
well under 100 k cy per short packet.

**RAM cost**: **−512 B** net.
- Remove `sqtab2_lo` ($8400..$84FF) — 256 B
- Remove `sqtab2_hi` ($8600..$86FF) — 256 B
- Remove `sqtab2_init` builder code (~30 B) — code shrinks
- Remove `lmul0` / `lmul1` ZP pointer pair (2 ZP slots freed)
- Retain `sqtab_lo` / `sqtab_hi` at $8000..$83FF (1 KB) — already built
  at init by `sqtab_init` and REU-preloaded on Profile A per S10

**Implementation effort**: ~100 lines of new asm (the `ct_mul_8x8`
primitive above plus a small sum/diff ZP scratch block), ~50 lines of
deletion (mult66, sqtab2 table, sqtab2_init), ~10 lines of caller
adaptation in the `.repeat 16, J` outer loop of `poly1305_multiply`
(the SMC pre-bake block stores r[j] to both `smc_sum_a_imm+1` and
`smc_diff_a_imm+1`, replacing the `sta lmul0` / `sta lmul1` /
`sta mult66_sbc_a+1` triplet). Difficulty: **low-medium**. ~4 hours
of focused work including test bring-up. No cross-file layout moves.

**CT proof sketch**:
1. **No branches on secret data**. All branches in `ct_mul_8x8`:
   - `jsr` call/return (public).
   - No explicit conditional branches (zero `bcc`/`bcs`/`beq`/`bne`/`bmi`/`bpl`).
2. **All table loads use page-aligned bases**. `sqtab_lo` is
   `$8000`, `sqtab_hi` is `$8200`. Both are `.align 256` (by the
   $00-low-byte alignment). X ranges over 0..255 and Y ranges over
   0..255 (the abs/sum are pre-clamped to 8 bits before the tax/tay).
   Therefore `sqtab_lo + X`, `sqtab_hi + X`, `sqtab_lo + Y`,
   `sqtab_hi + Y` never cross a page → always 4 cy for
   `lda abs,x` / `lda abs,y`.
3. **SMC'd `lda $XX00,x` loads don't page-cross**. The SMC store
   patches the hi byte only; the lo byte is `$00` (page-aligned),
   and X ≤ 255, so effective addresses are always within the
   patched page. Always 4 cy.
4. **SMC store costs are constant**. `sta abs` is 4 cy regardless
   of the stored value.
5. **Sign-mask branchless abs**. `sbc #0` with C=1 → A=0;
   with C=0 → A=$FF. Both 2 cy. The subsequent `eor`, `sec`,
   `sbc`, `tay` are all constant-cy.
6. **Sum-page dispatch**. Both page-0 and page-1 cases execute the
   *same* straight-line code; only the SMC'd hi byte differs.
   Identical cycle count in both cases.
7. **No variable-cycle branches remain**. The total cycle cost of
   `ct_mul_8x8` is a fixed constant (~78 cy) independent of a and b.

**Portability back to sibling projects**: the `ct_mul_8x8` primitive
is plug-in compatible with the pre-S12 `mul_8x8` interface
(sta A / stx X → poly_prod_lo/hi), except for the additional SMC
pre-bake step at the caller. It can be dropped into `c64-x25519`,
`c64-wireguard`, `c64-nist-curves`, and `c64-aes256-ecdsa` with
minor adaptation. Follow-up work, not gating v0.3.0.

**Caveats**:
- SMC patching in the hot loop requires the patched code to live
  in RAM (already true — CODE segment is in RAM on C64). No issue.
- ca65 macros for SMC labels already present in the codebase
  (`mult66_sbc_a`, `smc_*` labels in chacha20_lib.s per S13). Style
  consistent.
- The 78 cy primitive is ~1.7× the cost of `mult66` but ~0.9×
  the cost of pre-S12 branching `mul_8x8`. We land **between** the
  two historical primitives in cycle cost but strictly above both
  in CT posture.

---

### 3.2 Shoup-lite per-j row table (REJECTED for Profile B)

**Mechanism**: at `poly1305_init`, build 16 rows × 256 bytes of
`rj_row_lo/hi[y] = (r[j] * y).lo/hi`. Inner multiply becomes:
```
ldy poly_h + I
lda rj_row_lo + J*256, y        ; 4 cy, page-aligned
sta poly_prod_lo
lda rj_row_hi + J*256, y        ; 4 cy
sta poly_prod_hi
```
~14 cy per multiply including the ldy.

**Cycle cost**: 14 cy × 272 = 3 808 cy/block on the multiplies alone,
vs current ~13 600 cy on the mult66 path — ~−10 k cy/block
(~**−36% speedup**). Per-packet table-build cost: 16 × 256 × ~12 cy
= ~50 000 cy amortized over the packet.

**RAM cost**: **+8 KB** (16 × 512 B). This blows Profile B's
"stock C64 minimal-RAM" design intent. Profile B currently uses
~1 KB runtime RAM for sqtab; Shoup-lite takes us to ~9 KB, which is
in the same neighborhood as Profile A's full Shoup (4–8 KB depending
on S11 incremental-build state). Profile B would effectively collapse
into Profile A modulo the REU-preload difference.

**Workload fit** (per
`/home/someone/.claude/projects/-home-someone-c64-ChaCha20-Poly1305/memory/project_target_workloads.md`):
Profile B "owns short packets (n=0 −65.3%)". Shoup-lite's 50 k cy
per-packet precompute would **reverse that win** — on n=0 (2 blocks)
the amortized build cost is 25 k cy per block, which dominates the
multiply cost. **Shoup-lite is structurally incompatible with
Profile B's target workload.**

**Verdict**: **REJECTED.** Contradicts Profile B design intent; worse
on Profile B's target workload; not a valid fix path under any
reasonable interpretation of the ship goals.

**(Alternative framing for completeness)**: if we were willing to
have only one profile (Profile A collapsed with Profile B, REU
optional), Shoup-lite would be the right answer. But that's a
sprint-level architectural decision, not a CT fix, and it's out of
scope for v0.3.0 unbreak.

---

### 3.3 Full-precompute partial-products (REJECTED — recursive)

**Mechanism**: per poly1305_block, compute all 272 products
`h[i] * r[j]` into a scratch buffer before the accumulate phase, then
schoolbook-add the buffer branch-free.

**Problem**: the precompute phase still needs a CT multiply primitive.
This moves the problem rather than solving it. If the primitive is
`ct_mul_8x8` (§3.1), total cost is identical to §3.1 plus the
scratch buffer shuffle overhead. If the primitive is branchy, nothing
is fixed.

**RAM cost**: +544 B scratch (272 × 2).

**Verdict**: **REJECTED.** Strictly dominated by §3.1.

---

### 3.4 Software shift-and-add multiply (REJECTED — catastrophic cost)

**Mechanism**: classical branchless 8-iteration shift-and-add with
`sbc #0` sign-mask conditional add.

**Cycle cost**: ~44 cy per inner iter × 8 iters + setup/teardown ≈
**370 cy per 8×8 multiply**. × 272 = 100 640 cy/block.

**Profile B regression**: 27 032 → ~114 000 cy/block ≈ **+320%**.
`aead_encrypt n=1024` would balloon from 2.6 M to ~8.1 M cy.
Sprint-0 baseline is recovered and then some.

**RAM cost**: −1 KB (can drop sqtab entirely).

**Verdict**: **REJECTED** as the primary fix. Keep in reserve as a
sanity-baseline cross-check only: if 214/214 pass with this
primitive, we know the rest of the multiply surface is correct.
Useful as a validation tool, not a ship target.

---

### 3.5 Dual-load equalize for mult66 (REJECTED — unachievable)

**Mechanism** (as described in `CT_ANALYSIS.md §2.F3` Option A):
force `(lmul0),y` to always page-cross via a clever table layout.

**Analysis**: for `(zp),y` to always page-cross, we need
`zp_lo + y >= 256` for **all** valid y. Since `y_min = 0`, this
requires `zp_lo >= 256`, which is impossible on an 8-bit
architecture. There is no placement of `lmul0.lo` and no offset of
`y` that forces unconditional page-cross while preserving the
correct effective address `sqtab[a+b]`.

**Follow-on attempts**: pre-biasing y by a constant shifts the valid
range but does not eliminate the y=0 case. Adding a nop on the
no-cross path is impossible because the CPU does not expose "did
this load cross" to software. Adding a second dummy load that
always-crosses has the same 8-bit impossibility.

**Verdict**: **REJECTED.** `CT_ANALYSIS.md §2.F3 Option A` was a
well-intentioned suggestion but is not achievable with `(zp),y`
addressing on 6502. The only way to eliminate F3 is to eliminate
the `(zp),y` load entirely, which is what §3.1 does.

---

### 3.6 SMC'd `abs,y` with per-j page patch (REJECTED — wrong index)

**Mechanism** (as described in `CT_ANALYSIS.md §2.F3` Option B):
replace `(lmul0),y` with `abs,y` whose hi byte is SMC-patched at the
start of each outer-j iteration based on some deterministic function
of `r[j]`.

**Analysis**: the page the sum `a + b` falls into is a function of
**both** a=r[j] and b=h[i]. For fixed a, the predicate
`a + b >= 256` cuts the valid-b range into two pieces at
`b_threshold = 256 - a`. Different h[i] values per inner iteration
will fall on different sides of the threshold. There is no per-j
SMC patch that captures this; the patch would need to happen per-i
(per inner iteration), which is exactly what §3.1 does (the patch
IS per-mul, just folded into the primitive).

**Verdict**: **REJECTED** as a distinct option. Collapses into §3.1
when unfolded correctly.

---

### 3.7 Summary table

| # | Candidate | cy/mul | Δ block | Δ n=1024 | RAM Δ | Effort | CT? |
|---|---|---:|---:|---:|---:|---:|:---:|
| 3.1 | **CT-quarter-square (branchless pre-S12)** | ~84 | +34% | +24% | **−512 B** | ~4 h | ✓ |
| 3.2 | Shoup-lite per-j rows | ~14 | −36% | −40%† | **+8 KB** | ~6 h | ✓ |
| 3.3 | Full-precompute products | ~84+† | +34%+overhead | same | +544 B | ~6 h | ✓ |
| 3.4 | Software shift-and-add | ~370 | +320% | +210% | −1 KB | ~3 h | ✓ |
| 3.5 | Dual-load equalize | — | — | — | — | — | ✗ (impossible) |
| 3.6 | SMC'd abs,y per-j | — | — | — | — | — | ✗ (wrong granularity) |

† Shoup-lite's speedup on aead_encrypt collapses on short packets:
  n=0 pays the 50 k cy per-packet build with only ~2 blocks to
  amortize over, **reversing** the win.

---

## 4. Recommendation

**Adopt §3.1: CT-Quarter-Square (branchless rewrite of pre-S12
`mul_8x8`).**

**Reasoning**:

1. **Structurally correct under CT**. Zero conditional branches on
   secret data. All table loads use page-aligned `abs,x` / `abs,y`,
   which are cycle-invariant. SMC stores are unconditional-cost.
   The primitive is straight-line except for the `jsr`/`rts`
   bracketing, which is public.

2. **Preserves Profile B design intent**. Net −512 B RAM (sqtab2
   and its init go away), same 1 KB `sqtab_lo`/`sqtab_hi` as today,
   no new 8 KB Shoup table. Profile B remains the "stock C64
   portable baseline" per `docs/OPTIMIZATION_PLAN.md §5`. Profile A
   is untouched (the `.ifdef POLY1305_PROFILE_LONG` Shoup path is
   unaffected).

3. **Profile B workload fit preserved**. Profile B still wins on
   short packets (n=0) in absolute cycle terms — the regression is
   ~+37% on n=0 but the absolute number stays well under 100 k cy,
   acceptable for short-message use cases. Profile B's structural
   advantage on low-precompute workloads is preserved.

4. **Cost is honest and expected**. ~+34% Profile B `poly1305_block`
   and ~+24% `aead_encrypt n=1024` is the real price of CT on 6502
   without hardware MUL. Web research (see §5 below) confirms
   there is no known cheaper CT 8×8 multiply primitive for 6502:
   all sibling c64-crypto projects have the same CT bug, and
   BearSSL explicitly notes that "software fallbacks guaranteed
   constant-time for architectures fundamentally lacking appropriate
   multiply support" are not in the field. We would be the first.

5. **Portable back to the c64-crypto family**. The same primitive
   fixes the same bug in `c64-x25519`, `c64-nist-curves`,
   `c64-wireguard`, and `c64-aes256-ecdsa`. Significant value beyond
   this project alone — one audit, many fixes.

6. **Small implementation surface**. ~100 lines new code in one
   file, ~60 lines deleted, ~10 lines caller change. No cross-file
   layout moves. Low risk of regressing Profile A or the AEAD glue.
   Achievable in a single focused session.

7. **Correctness-friendly**. The primitive is small enough to
   unit-test against a brute-force `a*b` reference for all 65 536
   (a,b) pairs in a few seconds. High-coverage CT fuzz via the
   existing cross-check harness is straightforward.

**Expected final cycle shape**:
- Profile B `poly1305_block`: ~36 280 cy (from 27 032, +34%).
- Profile B `aead_encrypt n=0`: ~69 000 cy (from ~50 000, +37%).
- Profile B `aead_encrypt n=1024`: ~3 229 000 cy (from 2 598 896, +24%).
- Profile A: **unchanged** (all numbers identical pre/post).

**RAM budget**: Profile B total runtime RAM drops from ~1.5 KB
(sqtab + sqtab2) to **1 KB** (sqtab only). Code size shrinks by
~50 lines.

**CT contract update**: after §3.1 lands, `docs/OPTIMIZATION_PLAN.md
§4` CT-contract language should be tightened from "no data-dependent
branches" to "no data-dependent branches **and no data-dependent
addressing-mode timing (page-cross, etc.)**". This is a docs-only
follow-up and is not on the critical path for v0.3.0.

**F1 and F2 fit**: F1 (`poly1305_final` h≥p branch) and F2
(`rotl32_1_zp`/`rotr32_1_zp` wrap) are independent sites and can be
fixed in the **same PR** as F3 per the task #17 cadence. Their fixes
are small (branchless mask-blend and branchless ASL/ROL chain
respectively), well-understood, and validated against the existing
audit. Bundle all three for v0.3.0.

---

## 5. Web Research Summary

### 5.1 Searches run

1. **"6502 constant-time multiply Poly1305 branchless quarter-square"** —
   thin. Quarter-square theory is well-known
   ([retrocomputingforum](https://retrocomputingforum.com/t/quarter-square-multiplication-analog-computing-and-6502-mos/2180),
   [lysator](https://www.lysator.liu.se/~nisse/misc/6502-mul.html)) but no
   CT-aware variants in the public 6502 literature.

2. **"Poly1305 8-bit microcontroller constant-time AVR implementation"** —
   produced the Hutter/Schwabe NaCl-on-AVR 2013 paper
   ([cryptojedi.org/papers/avrnacl-20130220.pdf](https://cryptojedi.org/papers/avrnacl-20130220.pdf),
   [Springer](https://link.springer.com/chapter/10.1007/978-3-642-38553-7_9)).
   Fetched and PDF-extracted.

3. **"poly1305-donna-8 8-bit fallback multiply implementation"** —
   located the reference code
   ([floodyberry/poly1305-donna](https://github.com/floodyberry/poly1305-donna),
   [poly1305-donna-8.h](https://github.com/floodyberry/poly1305-donna/blob/master/poly1305-donna-8.h)).

4. **"BearSSL constant-time multiplication software fallback"** — fetched
   [BearSSL's ConstantTime Crypto page](https://www.bearssl.org/constanttime.html).

5. **"6502 branchless abs subtract eor sign mask constant time"** —
   general 6502 instruction references only
   ([masswerk](https://www.masswerk.at/6502/6502_instruction_set.html),
   [6502.org tutorials](https://6502.org/tutorials/compare_beyond.html),
   [nesdev](https://www.nesdev.org/wiki/6502_assembly_optimisations)).
   No published CT-aware `mul_8x8` variant.

### 5.2 Key findings

- **Hutter/Schwabe (NaCl-on-AVR, 2013)**: their Poly1305 runs at
  195–211 cy/byte in constant time **because AVR has a 2-cycle
  hardware `MUL` instruction**, which is inherently constant-time.
  "We followed a similar approach by breaking the 136-bit
  multiplication into 8×8-byte, 9×9-byte, and 9×8-byte multiplications
  ... 17×17-byte multiplication takes 1 967 cycles." None of their CT
  techniques transfer to a platform without hardware MUL. Confirmed
  from PDF §5, extracted text lines 302–340.

- **poly1305-donna-8.h**: uses C's `*` operator directly for 8×8×16,
  trusting the compiler/target platform to provide a CT multiply.
  No software-fallback CT multiply in the public codebase. No 6502
  variant exists in the donna family.

- **BearSSL**: explicitly acknowledges the problem on platforms
  without constant-time hardware multiply ("a dedicated page lists
  architectures with variable-time multiplications and possible
  workarounds"). For Poly1305 on ARM Cortex-M0 (where 32-bit MUL
  is still hardware and CT but 64-bit is not), they use a 13-bit
  limb layout to stay within 32-bit multiplies. **The documentation
  explicitly states they do not provide software fallbacks
  guaranteed constant-time for architectures fundamentally lacking
  appropriate multiply support.** This is our situation on 6502.

- **6502 CT prior art**: essentially none. The 6502 retro-crypto
  community uses quarter-square multiplies with the standard
  branching pattern because CT was not a goal. We appear to be the
  first to tackle CT 8×8 multiply on 6502 for production crypto use.

- **c64-*-crypto family**: all four sibling projects
  (`c64-x25519`, `c64-nist-curves`, `c64-wireguard`,
  `c64-aes256-ecdsa`) use the same CT-broken `mul_8x8`. See §2.3.

### 5.3 Known-bad patterns to flag

None discovered in the web search. No published timing attacks
specifically against Poly1305 that would require a different fix
class than F3.

### 5.4 Research verdict

The web does not surface a cheaper CT 8×8 multiply for 6502. §3.1
(CT-quarter-square) is essentially novel work. The cost estimates in
§4 are the honest lower bound on CT cost on this platform given
the current state of public 6502 crypto literature.

---

## 6. Implementation Plan Outline

Target branch: continue on `ct-fix-v0.3.0` (the worktree at
`.claude/worktrees/ct-fix-v030` already exists from ct-fixer's first
attempt — the coding agent should resume there, either as a new
`ct-fixer-v2` spawn or by re-briefing ct-fixer with this memo).

### 6.1 Files to edit

- `src/lib/poly1305_lib.s` — delete `mult66`, `sqtab2_init`,
  `sqtab2_lo`/`sqtab2_hi` equates, `lmul0`/`lmul1` ZP equates and
  init-time stores; add `ct_mul_8x8` primitive; rewrite the
  `poly_pp_mult66` macro as `poly_pp_ct_mul` with the new caller
  preamble (two SMC stores instead of three).
- `src/lib/constants_lib.s` — add ZP slots for `diff_raw`, `sign_mask`
  (two new bytes). Remove `lmul0`/`lmul1`. Net ZP usage: −0 bytes
  (2 added, 2 removed).
- `src/lib/poly1305_lib.s` (same file) — also apply F1 (poly1305_final
  branchless mask-blend h≥p reduction) per `CT_ANALYSIS.md §2.F1`.
- `src/lib/chacha20_lib.s` — apply F2 (rotl32_1_zp / rotr32_1_zp
  branchless ASL+ROL chain) per `CT_ANALYSIS.md §2.F2`.
- `src/lib/word32_lib.s` — delete dead test-only `rotl32_1` /
  `rotr32_1` subroutines (F2 follow-up per task #17 brief).
- `docs/OPTIMIZATION_PLAN.md` — add CT-fix progression row, note
  the +34% Profile B regression honestly.

### 6.2 Functions to replace / add

- **Delete**: `mult66`, `mult66_sbc_a`, `sqtab2_init`, macro
  `poly_pp_mult66`.
- **Add**: `ct_mul_8x8` (the primitive in §3.1), macro `poly_pp_ct_mul`
  (rewraps the `jsr ct_mul_8x8` + accumulate/ripple epilogue, identical
  to `poly_pp_mult66`'s epilogue).
- **Modify**: `poly1305_multiply` Profile B `.repeat 16, J` outer loop
  — replace the three-store SMC bake
  (`sta lmul0` / `sta lmul1` / `sta mult66_sbc_a+1`) with the
  two-store bake
  (`sta smc_sum_a_imm+1` / `sta smc_diff_a_imm+1`).
- **Modify**: `poly1305_init` — remove the `jsr sqtab2_init` and
  the `sta lmul0+1` / `sta lmul1+1` cached-hi-byte stores (both
  become dead code once `lmul0`/`lmul1` are deleted).

### 6.3 Tests

- **214/214 unit tests** both profiles (seed 7539), same harness as
  S12. Must pass byte-identical.
- **10 000 cross-check** against pyca/cryptography Poly1305
  (`tools/step12_cross_check.py` or equivalent), both profiles.
  New primitive → required per sprint rules.
- **Exhaustive 8×8 primitive test** (new, ~50 lines): brute-force
  all 65 536 (a,b) pairs, compare `ct_mul_8x8(a,b)` against `a*b`.
  Runs in ~10 s under VICE. This is cheap correctness insurance
  for a new primitive and catches any sign-mask / SMC / edge-case
  bug early.
- **AEAD 10 000 cross-check** via `tools/audit_cross_check.py`
  both profiles (from task #12). Full ChaCha20-Poly1305 AEAD,
  random vectors vs pyca reference.

### 6.4 Cross-check vectors

Run existing AEAD cross-check harness at seed 20260412 (the S12
cross-check seed) to confirm byte-identical AEAD output for the
same (k, n, aad, pt) inputs across the CT-fix PR. Profile A must
be byte-identical to pre-fix. Profile B will be byte-identical too
(the primitive output is the same; only timing changes).

### 6.5 Performance budget to accept

**No budget gate**. User directive is correctness over performance.
Expected deltas to state honestly in the progression table:

- Profile B `poly1305_block`: **+34%** (27 032 → ~36 280 cy)
- Profile B `aead_encrypt n=0`: **+37%** (~50 000 → ~69 000 cy)
- Profile B `aead_encrypt n=1024`: **+24%** (2 598 896 → ~3 229 000 cy)
- Profile A: **unchanged**
- Profile B RAM: **−512 B**
- Both profiles ChaCha20 `rotl32_1` F2 fix: **~−240 cy/block net win**
- Both profiles `poly1305_final` F1 fix: **~+200 cy/packet one-shot**

Write these numbers into the `docs/OPTIMIZATION_PLAN.md` CT-fix row
verbatim after benching. Call out the Profile B regression as an
explicit trade: "correctness over performance per user directive;
Profile B's S12 mult66 win was incompatible with CT and has been
replaced with a CT-clean primitive at a 34% per-block cost. Profile
B still delivers ~36% improvement over the sprint-0 baseline and
remains the portable stock-C64 configuration."

### 6.6 Cadence

Two commits (same cadence as S10–S13):
1. `CT fix: F1 poly_final masked-blend + F2 rot1 branchless + F3 ct_mul_8x8 — +<delta> Profile B poly1305_block`
2. `docs: fill in CT-fix commit hash in progression table`

PR title: `CT fix: F1 poly_final + F2 rot1 + F3 ct_mul_8x8 (Profile B)`.
PR body: full summary per task #17 cadence step 11, plus a pointer
to this memo at `.claude/tasks/c64-chacha20poly1305-port-sprint/audit_drafts/F3_FIX_DESIGN.md`.

### 6.7 Post-merge follow-ups (not blocking v0.3.0)

- Port `ct_mul_8x8` back to the sibling c64-crypto projects as
  follow-up PRs (separate from v0.3.0).
- Tighten CT contract language in `docs/OPTIMIZATION_PLAN.md §4`
  to explicitly cover non-branch timing channels (addressing-mode
  page-cross, etc.).
- Consider a future optimization sprint targeted specifically at
  *CT-aware* Profile B optimization (e.g., SMC-optimized primitive
  variants, partial inlining of the 32 lowest-cost mul calls per
  block). Out of scope for v0.3.0.

---

## 7. Showstoppers discovered

**None.** The fix is implementable, bounded in scope, does not
require cross-file layout changes, does not require new third-party
dependencies, and does not require abandoning any design invariant.
The ~+34% Profile B regression is painful but consistent with the
user's explicit directive ("correctness over performance; iterate
on perf later").

Trivial CT fix that everyone missed? **No.** The fundamental issue
is that 6502 lacks hardware MUL and requires a lookup-table based
primitive, and ANY 9-bit-indexed lookup on 6502 either (a) uses
`(zp),y` with secret-dep page-cross timing (F3) or (b) uses `abs,x`
with a software sum-page dispatch. Option (b)'s dispatch used to
be a branch (pre-S12) and now needs to be SMC-based. §3.1 is the
minimum-cost SMC-based dispatch I can construct; I don't see a
cheaper path.

---

## 8. Post-merge hardening: SMC target-site operand derived from equate (v0.5.1)

**Context**. After PR #39 adopted `LIB_SHARED_SQTAB_BASE` as the
canonical sqtab base equate (per `c64-lib-contract` SPEC §8.1), the
issue #40 audit observed that the `ct_mul_8x8` SMC *target site*
placeholders still embedded literal `$8000` / `$8200` in their
initial assembled bytes:

```asm
smc_lo_addr:  lda $8000,x   ; assembled as BD 00 80
smc_hi_addr:  lda $8200,x   ; assembled as BD 00 82
```

The SMC *dispatch* — the code that computes the hi-byte patch via
`lda #>sqtab_lo` + `adc #(>sqtab_hi - >sqtab_lo)` — was already
equate-driven. But the target-site operand (the bytes ld65 emits at
the `lda abs,x` placeholder) was a separate concern: a literal
immediate in the SMC macro's `statement` argument compiles to those
exact bytes regardless of the equate.

**Behavior under documented use was correct.** `ct_mul_8x8`
deterministically patches the hi byte of `smc_lo_addr+2` and
`smc_hi_addr+2` before any code path can reach the indexed load
(the patch sequence is the first six instructions of the routine,
and the indexed load comes ~18 instructions later — no jumps in
between). Under default standalone build (`LIB_SHARED_SQTAB_BASE =
$8000`), the literal bytes also happen to match the equate, so even
a hypothetical cold-jump consumer that skipped the patch would read
from the correct page.

**Bytes were out of sync under a consumer override.** Multi-lib
PRGs may set `-DLIB_SHARED_SQTAB_BASE=$<addr>` (e.g. `$7800`) to
share one sqtab across c64-x25519 / c64-chacha20-poly1305 / a
host-app primitives table. The equate then resolves to `$7800`, the
dispatch correctly patches `$78` / `$7A` into the hi byte at
runtime, and execution is correct. But the *static image* still
showed `BD 00 80` / `BD 00 82` at the SMC target sites — a
cold-jump consumer that skipped the patch sequence would read from
the wrong page (`$8000` instead of `$7800`).

**Hardening**. Replace the literal immediates with symbol
references:

```asm
SMC smc_lo_addr, { lda sqtab_lo,x }   ; was: lda $8000,x
SMC smc_hi_addr, { lda sqtab_hi,x }   ; was: lda $8200,x
```

The ca65 assembler emits `BD <lo(sqtab_lo)> <hi(sqtab_lo)>` for the
first instruction and `BD <lo(sqtab_hi)> <hi(sqtab_hi)>` for the
second. Both equates are page-aligned (`.assert` enforced in
`poly1305_lib.s`), so the lo byte is `$00` regardless of override
target — the SMC patch sequence still touches `+2` only, and the
runtime cycle accounting is unchanged.

**Verification matrix**:

| Build | Bytes at `smc_lo_addr` | Bytes at `smc_hi_addr` | Tests |
|---|---|---|---|
| default profile-a (sqtab gated out under F1) | n/a | n/a | 214/214 |
| default profile-b (LIB_SHARED_SQTAB_BASE = $8000) | `BD 00 80` | `BD 00 82` | 214/214 |
| override profile-b (LIB_SHARED_SQTAB_BASE = $7800) | `BD 00 78` | `BD 00 7A` | 214/214 |

The default-build PRGs are byte-identical to the pre-hardening
output (md5 unchanged on both profiles) — the same ca65 input
`lda <equate>,x` emits the same `BD 00 80` bytes as the previous
literal `lda $8000,x`. The hardening payoff is visible only on
override builds, where the static image now tracks the equate.

**Scope discipline**. This pass touches only the two `SMC` macro
invocations at the table-lookup site (line ~570 / line ~574 of
`src/lib/poly1305_lib.s`). The SMC dispatch math, the equate
definitions, and all non-sqtab SMC sites (`shoup_*`, `mult66_*`,
`smc_sum_a_imm`, `smc_diff_a_imm`) are unchanged. SPEC §8.1 is
unchanged — this is a lib-internal correctness pass, not an ABI
or layout change.

**Refs**: issue #40 audit, `c64-lib-contract` PR #5 / #6 / #9
(originating SPEC §8.1 and the canonical `LIB_SHARED_*` equate
pattern). Semver: PATCH bump (defense in depth, byte-identical
default output, 214/214 on every verified profile).

---

**End of memo.**
