# CT_ANALYSIS — Constant-Time Audit (v0.3.0)

Static audit of the merged-main library tree. Auditor: task #11
(audit-reader, original static sweep). Follow-up fix: task #17
(ct-fixer). Scope: every conditional branch in `src/main.s`,
`src/lib/word32_lib.s`, `src/lib/chacha20_lib.s`,
`src/lib/poly1305_lib.s`, `src/lib/chacha20poly1305_lib.s`,
`src/lib/data_lib.s`, `src/lib/constants_lib.s`. Non-branch
timing channels (page-cross on indexed/indirect loads, secret-dep
addressing) are also classified.

---

## VERDICT: GREEN (post-fix, v0.3.0)

All three constant-time findings originally flagged by this audit
(F1, F2, F3) were resolved in PR #14 / commit `dc4c575`, merged
into main as `f4f049e`. The library's v0.3.0 production hot path
has no known secret-dependent branches and no known secret-dependent
addressing-mode timing on hot-path loads.

See the **Resolution** section at the bottom of this document for
per-finding fix summaries. The historical RED content below is
preserved unchanged for audit-trail completeness — it was the
state of the library **pre-CT-fix** and should be read as a
point-in-time snapshot of what was found, not as a description of
the shipping v0.3.0 code.

---

## HISTORICAL (PRE-FIX) VERDICT: RED

The library v0.3.0 (current main) **DOES NOT** satisfy its own CT
contract (`docs/OPTIMIZATION_PLAN.md` §4: *"no data-dependent branch
on secret data"*). Three independent timing channels leak secret
state on the production hot path:

- **F1** — `poly1305_final` branches on bit 130 of `(h + 5)`, a
  direct function of the secret accumulator `h`.
- **F2** — `rotl32_1_zp` / `rotr32_1_zp` in `chacha20_lib.s` branch
  on the carry wrap (the MSB / LSB of a ChaCha20 state word), on
  the inner quarter-round path, 80× per `chacha20_block`. Every
  emitted keystream byte's timing depends on the ChaCha20 state
  — which mixes the secret key with the nonce and counter.
- **F3** — `mult66`'s `(lmul0),y` / `(lmul1),y` indirect-indexed
  loads page-cross iff `r[j] + h[i] >= 256`, adding 1 cycle on a
  secret-dependent condition (Profile B only). The `bcs @pos`
  branch on `b - a` is previously disclosed as "same class" as
  mul_8x8's existing branch in the plan, but the `(lmul0),y`
  channel is additive and NOT disclosed.

All three findings have straightforward fixes (Section 2).

The previously-validated canonical-CT primitives remain intact:
`aead_verify_tag` OR-accumulator, `poly1305_multiply` straight-line
schoolbook (post-P1 cleanup, both profiles), `poly_reduce_shl6_tab`
page-aligned LUT, and `shoup_init`'s public-counter-only loops.
These are classified YELLOW-acceptable and listed in Section 4.

---

## 1. Verification Answers (team-lead's six questions)

### Q1. Are `word32_lib.s::rotl32_1` / `rotr32_1` (the SUBROUTINES) dead code?

**YES** — the subroutine versions at `word32_lib.s:286` and
`word32_lib.s:447` are dead in the production build. Call-graph
trace:

- `rotl32_1` (subroutine) is called only via the `chacha20_quarter_round`
  test-only entry (the non-ZP path of chacha20_lib.s's early API).
- `rotr32_1` (subroutine) is similarly reachable only via
  `rotr32_7` → `rotr32_1` tail fall-through, which is only called
  from the same test-only entry.
- **Production path**: `chacha20_block` uses the ZP-resident macro
  variants `rotl32_1_zp` / `rotr32_1_zp` in `chacha20_lib.s`
  (lines 199, 222). The subroutines are NEVER reached by the hot
  path from `aead_encrypt` / `aead_decrypt` / `chacha20_encrypt`.
- However, since `chacha20_quarter_round` is currently `.export`ed
  from `chacha20_lib.s` (test entry), the word32 subroutines are
  linked in the PRG even though no production code uses them. They
  are "exported-reachable but production-unused."

**Conclusion**: F2 (the macro bug) is in `chacha20_lib.s`, NOT in
`word32_lib.s`. The word32 subroutines DO contain the same bug
pattern (`bcc @done` at `word32_lib.s:306` and `word32_lib.s:466`)
but are test-only. **F2 is a production CT bug regardless**; the
word32 subroutine variants are merely a secondary instance that
future fixes should also patch for completeness.

### Q2. Does `poly1305_multiply`'s unrolled schoolbook (post-S4 P1 cleanup) have ZERO secret-dependent branches?

**YES, for both profiles.** Verified by exhaustive inspection of
`poly_pp_shoup` (Profile A, `poly1305_lib.s:665–678`) and
`poly_pp_mult66` (Profile B, `poly1305_lib.s:634–648`):

- Neither macro contains any branch on `h[i]`, `r[j]`, or their
  product directly.
- The only branches are `bcc :+` on carry-out of the accumulator
  add — that's the canonical carry-chain pattern (Section 4,
  plan-accepted YELLOW).
- The outer schoolbook expansion is a `.repeat` macro over fixed
  (i, j) indices; no runtime counter with secret-dep exit.
- S4's P1 cleanup (removing early-exit `beq` on `h[i]`/`r[j]`) is
  INTACT and still applied.

The `bcc :+` in both macros leads to `poly_ripple` which has its
own branches on carry propagation — those are also canonical
(Section 4).

### Q3. Does the S12 mult66 primitive (cleared-carry SBC convention) introduce any secret-dependent branches?

**PARTIALLY — F3 finding.** The plan already discloses that mult66
has one secret-dep branch `bcs @pos` at `poly1305_lib.s:566` on
`b - a` sign, and argues this is "same class" as mul_8x8's existing
sum-page branch. That disclosure is accepted YELLOW (Section 4).

**HOWEVER**, the routine also has three `(lmul0),y` / `(lmul1),y`
loads at lines 565, 570, 578 that page-cross iff `a + b >= 256`
(6502 adds 1 cy when the indirect-indexed effective address
crosses a page boundary). Since `a = r[j]` and `b = h[i]`, the
cycle-count difference is a direct function of `(r[j] + h[i]) mod
512 >= 256` — a product-of-secrets predicate. This channel is
NOT disclosed in `docs/OPTIMIZATION_PLAN.md` or in the mult66
header comment at `poly1305_lib.s:550–558` (the header claims
"neither `,x` load crosses a page boundary", but that only covers
the `sqtab_lo,x` / `sqtab2_lo,x` loads on the diff path, NOT the
`(lmul0),y` sum-path load).

**Impact**: ~1 cycle per 8x8 depending on `(r[j] + h[i]) >= 256`,
17*16 = 272 iterations per Poly1305 block. Net spread up to ~272
cycles per block, data-dependent on the secret product rows.

**This is F3 in this report.**

### Q4. Does the S11 incremental Shoup build have any secret-dependent branches?

**NO.** `shoup_init` at `poly1305_lib.s:288–302`:

- Inner k-loop `bne shoup_k_loop` (line 296) branches on `y++`,
  Y is a public counter 1..255 → 0 (255 iterations), exit when
  Y wraps to zero. PUBLIC.
- Outer j-loop `bne shoup_j_loop` (line 301) branches on
  `poly_j` compared to 16. PUBLIC.
- The SMC site `shoup_rj_val: adc #$00` patches in `r[j]` as the
  loop's adc immediate. The patch itself is a straight-line
  `sta shoup_rj_val+1`; no branches.
- All table writes are via SMC'd store instructions
  (`sta r_tab_lo,y` with the high-byte of the target patched per
  outer-j iteration). No branches on table addresses.
- Every `adc #r[j]` inside the loop uses the `adc imm` addressing
  mode (2 cy fixed), NOT indexed — immune to page cross.
- Every `lda r_tab_lo-1,y` / `sta r_tab_lo,y` uses `abs,y` but
  the r_tab_lo base is page-aligned (`= $6000 + j*256`, patched),
  and Y stays in 0..255 — no page cross is possible on these
  loads because the effective address stays on the single patched
  page.

**Verdict**: Shoup build is public-counter only, no secret-dep
timing. S11 is clean.

### Q5. Does the ChaCha20 C7 keystream alias (S8) introduce timing variance via page-cross on `(zp),y` reads of secret data?

**NO.** `cc20_keystream` is an alias for `cc20_work = $40`
(`constants_lib.s:69–70`). Both symbols name the SAME ZP-resident
64-byte buffer at `$40..$7F`. The XOR loop at `chacha20_lib.s:798–804`
reads the keystream via:

```
lda (cc20_data_ptr),y      ; plaintext — (zp),y — page-cross possible
eor cc20_keystream,y       ; $40,y     — zp,y  — 4 cy FIXED
sta (cc20_data_ptr),y      ; ciphertext — (zp),y — page-cross possible
```

- `eor cc20_keystream,y` is `zp,y` addressing (opcode $59 is
  `eor abs,y` for 16-bit base — HOWEVER since `cc20_keystream = $40`
  fits in 8 bits and ca65 emits `eor $40,y`, the assembler selects
  the `zp,y`-style encoding where available). In strict 6502 ISA
  terms `eor zp,y` doesn't exist (only `zp,x`); ca65 therefore emits
  `eor abs,y` with a 2-byte operand. `eor abs,y` costs 4 cy, +1 cy
  on page-cross. BUT — since the base `$0040` is on page 0 and
  `y < 64`, the effective address is `$0040..$007F`, which cannot
  cross a page. Timing is fixed 4 cy regardless of y.
- The plaintext pointer `(cc20_data_ptr),y` page-crosses depending
  on the caller-supplied plaintext address — but that address is
  PUBLIC (caller chooses where to store plaintext). The branch
  `bne @xor_loop` on `x--` exits at `x==0`, where `x` is
  `min(cc20_remain, 64)` — the LENGTH, which is public.

**Verdict**: C7 keystream alias (S8) has no secret-dep page-cross.
The ZP placement was specifically chosen (per plan) to KILL the
`abs,y` page-cross channel that would exist if keystream lived in
main RAM and happened to straddle a page boundary.

### Q6. Verify `aead_verify_tag`'s OR-accumulator CT tag-compare is intact.

**YES — INTACT and canonical-OK.** At `chacha20poly1305_lib.s:453–465`:

```
aead_verify_tag:
        lda #0
        sta poly_carry          ; zero accumulator
        ldx #15
@cmp_loop:
        lda poly1305_tag,x      ; 4 cy (+0 pg-cross: poly1305_tag base fixed)
        eor aead_tag,x          ; 4 cy
        ora poly_carry          ; 3 cy (zp)
        sta poly_carry          ; 3 cy (zp)
        dex                     ; 2 cy
        bpl @cmp_loop           ; branch on X sign — PUBLIC counter (15..-1)
        lda poly_carry          ; 3 cy
        rts
```

- `bpl @cmp_loop` branches on `x == -1` after 16 iterations. X is
  a hardcoded 15-down-to-0-to-minus-one counter; not data-dep.
- The OR-accumulator in `poly_carry` aggregates all 16 XOR
  differences. On exit, A = 0 iff every byte of `poly1305_tag`
  equals `aead_tag`. The caller's subsequent `bne @auth_fail`
  branch at `chacha20poly1305_lib.s:100` THEN branches on the
  single boolean result — but this is the API-mandated success/fail
  signal (canonical-OK).
- Base addresses `poly1305_tag` and `aead_tag` are fixed in the
  DATA segment (`data_lib.s`), so `abs,x` loads don't cross pages
  within the 16-byte walk.
- No indexed load on secret data uses an index derived from
  secret bytes.

**Verdict**: CT tag-compare is the canonical RFC-safe pattern.
GREEN.

---

## 2. Findings (Secret-dependent branches requiring fix)

### F1 — `poly1305_final` branches on bit 130 of (h+5) — RED

**Location**: `poly1305_lib.s:1021` (the `beq @no_reduce` branch),
and the taken-path loop `bcc @use_reduced` at line 1030.

**Data flow**:

```
1000    ; Compute h + 5, store in poly_product as temp
1004    clc
1005    lda poly_h
1006    adc #5
1007    sta poly_product
1010 @add5:
1011    lda poly_h,x
1012    adc #0
1013    sta poly_product,x
...
1019    lda poly_product+16      ; top limb of (h+5)
1020    and #$04                 ; bit 130 (bit 2 of byte 16)
1021    beq @no_reduce           ; <-- SECRET BRANCH on h
```

`poly_h` IS the secret Poly1305 accumulator. The branch `beq`
tests whether `(h + 5) >= 2^130`, i.e., whether the final reduction
`h >= p = 2^130 - 5` applies. Both arms have DIFFERENT cycle
counts: the reduced path takes 16 iterations of a `bcc
@use_reduced` copy loop plus an AND+STA, the non-reduced path
skips all of it. Net difference: ~100 cy per `poly1305_final`
depending on whether `h >= p`.

**Effectively this leaks**: whether the Poly1305 accumulator is
within 5 of the prime boundary at finalization. In practice, this
reveals roughly 1 bit of secret per invocation (`h mod p >= p-5`).
Over many AEAD operations with the same key, bias leaks might be
combinable into key material — though a clean CT fix is cheaper
than arguing exploitability.

**Suggested fix** (constant-time conditional move):

```
; After computing h+5 into poly_product:
;   - bit 130 of (h+5) gives the select mask (1 = use reduced, 0 = keep h)
lda poly_product+16
and #$04
; A = $04 if reduce, $00 if not. Build 0xFF / 0x00 mask:
cmp #$04
lda #0
sbc #0                   ; A = $FF if reduce, $00 otherwise
tax                      ; X = mask (clobber OK; tmp spare)
sta poly_tmp             ; stash mask
; Now UNCONDITIONALLY copy over all 17 bytes with mask blend:
ldy #16
@blend:
lda poly_h,y             ; original
eor poly_product,y       ; delta = h ^ reduced
and poly_tmp             ; mask: keep delta iff reduce
eor poly_h,y             ; apply: = h if mask=0, = reduced if mask=$FF
sta poly_h,y
dey
bpl @blend               ; public counter
; Mask top bits of poly_h+16 to 2 bits regardless (harmless if not reducing)
lda poly_h+16
and #$03
sta poly_h+16
```

Cost: ~200 cy extra per finalize (17 iter × ~10 cy), acceptable
for CT at finalization (poly1305_final runs once per AEAD op).

**Impact to ship**: MUST fix for v0.3.0 CT claim, or restrict
CT claim language in README / release notes to "timing-safe
except for one bit leaked at finalization."

### F2 — `rotl32_1_zp` / `rotr32_1_zp` MSB/LSB wrap branch — RED

**Location**:
- `chacha20_lib.s:213` — `bcc :+` in `rotl32_1_zp` macro
- `chacha20_lib.s:236` — `bcc :+` in `rotr32_1_zp` macro

**Data flow**: `rotl32_1_zp dst` 4×ROLs the 4 bytes of the state
word at `dst`, then branches on the final carry-out (which equals
the ORIGINAL MSB of the word). If MSB was 0, skip the wrap; if
MSB was 1, write-back the LSB OR'd with #$01. The skipped arm is
~12 cy shorter than the taken arm.

`rotl32_7_zp` expands to `rotl32_8_zp + rotr32_1_zp`, called by
`cc20_qr_body_rest` at `chacha20_lib.s:394`. Each chacha20_block
invokes 8 QRs × 10 double-rounds = 80 quarter-rounds. Each QR
does one `rotl32_7` (= `rotr32_1_zp`) → **80 branches per
chacha20_block on the MSB of state words derived from key +
nonce + counter + plaintext-ish data**.

ChaCha20's state after each round is a (complex but deterministic)
function of the original key, nonce, counter, and round constants.
Every branch on the MSB of a state word is thus a branch on a
secret-derived bit. Over 80 branches per block, the cumulative
timing spread can reach ~960 cy per block (80 × 12 cy) — a
substantial, linearly-accumulating secret-dep leak.

**Suggested fix** (branchless wrap via ADC):

```
.macro rotl32_1_zp dst
        lda dst+3
        asl                 ; A = old MSB in carry; A's bit 0 = 0
        lda dst
        rol                 ; rotate byte 0, carry = old msb from dst+3
        sta dst
        lda dst+1
        rol
        sta dst+1
        lda dst+2
        rol
        sta dst+2
        lda dst+3
        rol                 ; now carry = bit 7 of dst+3 (discarded), result in A
        sta dst+3
        ; The low bit has been lost in the process; recover it:
        ; wait — better approach: use ADC #0 to conditionally add the msb to byte 0
.endmacro
```

Actually the cleanest CT fix is:

```
.macro rotl32_1_zp dst
        ; Capture old MSB into bit 0 of byte 0, then rotate.
        lda dst+3
        asl                 ; carry = old msb
        lda dst
        adc #0              ; add old msb into LSB (no branch!)
        sta tmp_lsb_slot
        lda dst
        asl                 ; carry = old bit 6 of byte 0, A = byte 0 << 1
        ... [full branchless rol]
.endmacro
```

A simpler formulation: compute `new_byte0_lsb = old_byte3_msb`
directly via ASL+ADC with no intermediate branch:

```
.macro rotl32_1_zp dst
        lda dst+3
        asl                 ; C = bit 7 of dst+3 (the one that wraps)
        lda dst
        rol
        sta dst
        lda dst+1
        rol
        sta dst+1
        lda dst+2
        rol
        sta dst+2
        lda dst+3
        rol                 ; C = old bit 7 of dst+3 ignored (goes to carry out)
        sta dst+3
        ; Wait — this doesn't wrap the MSB correctly. The issue is
        ; that rol 4 bytes produces a 33-bit value; we need the
        ; top bit of the input put into bit 0 of the output.
.endmacro
```

The correct branchless form requires one extra step: shift the
original MSB into carry BEFORE the rol chain, and use a trailing
`adc #0` on byte 0 instead of a branch:

```
.macro rotl32_1_zp dst
        lda dst+3       ; top byte
        asl             ; C = top bit
        lda dst         ; low byte
        rol             ; bit 0 of new byte 0 = old top bit; C = old bit 7 of byte 0
        sta dst
        lda dst+1
        rol
        sta dst+1
        lda dst+2
        rol
        sta dst+2
        lda dst+3
        rol             ; C discarded; result in A
        sta dst+3
.endmacro
```

Cost: ~2 cy added (the leading `asl` is 2 cy; the removed `bcc`
and branch body are ~5–9 cy depending on arm). **NET SAVINGS**
~3 cy per macro invocation × 80 per block = **~240 cy saved per
chacha20_block** on top of the CT fix. This is a straight win.

Analogous fix for `rotr32_1_zp`: lead with `lda dst / lsr` to
capture the LSB into carry, then `ror` chain the 4 bytes
top-down. Same pattern, same savings.

**Impact to ship**: MUST fix for v0.3.0 CT claim. Also applies
to the dead-code subroutine variants in `word32_lib.s` at lines
286 and 447 for consistency.

### F3 — `mult66` `(lmul0),y` / `(lmul1),y` page-cross on r+h — RED

**Location**: `poly1305_lib.s:565, 570, 578` — three
`lda (lmul0/lmul1),y` loads in `mult66`.

**Data flow**: `mult66` caches `a = r[j]` as the low byte of
`lmul0` / `lmul1` ZP pointers (high bytes = `>sqtab_lo`,
`>sqtab_hi`). Caller passes `b = h[i]` in Y. The effective
address for `lda (lmul0),y` is computed as `(lmul0) + y`, and the
6502 adds 1 cycle if that computation crosses a page boundary,
i.e., if `lmul0.lo + y >= 256`, i.e., if `a + b >= 256`, i.e.,
if `r[j] + h[i] >= 256`.

Both `r` and `h` are secret. The cycle count of `mult66` therefore
depends on the secret sum `r[j] + h[i]`.

Number of mult66 calls per Poly1305 block: 17*16 = 272 (unrolled
via `poly_pp_mult66`). Number of *distinct* page-cross predicates:
272. Net worst-case timing spread per block: ~272 cy (about
0.04% of the ~11k–27k cy poly1305_block cost, but still a
structural CT leak).

**Is this disclosed?** The header comment at
`poly1305_lib.s:550–558` says:

> *"Timing: this routine has one secret-dependent branch (`bcc`
> on the sign of a - b). Both arms are straight-line and access
> fixed tables only (sqtab_lo/hi and sqtab2_lo/hi, each on their
> own 256-byte page), **so neither `,x` load crosses a page
> boundary**."*

This ONLY covers the `sqtab_lo,x` / `sqtab2_lo,x` abs-indexed
loads on the diff path. The `(lmul0),y` / `(lmul1),y` indirect-
indexed loads on the sum path are a DIFFERENT addressing mode
(6502 `(zp),y` — zero-page indirect Y-indexed) and they DO
page-cross when `zp_lo + y >= 256`. The comment's claim is
narrowly true for what it actually says, but does not cover all
the loads in the routine.

**Is it documented in the plan?** Checked
`docs/OPTIMIZATION_PLAN.md` §4 and the S12 plan entry — neither
mentions this channel. The `bcs @pos` branch is disclosed; the
`(zp),y` page-cross is not.

**Suggested fix**: Three options, all force the `(lmul0),y` load
to be non-page-crossing.

1. **Page-pad**: Ensure `sqtab_lo` and `sqtab_hi` are page-aligned
   (they already are: `$8000`, `$8200`) AND that `lmul0.lo +
   y` never wraps into a new page that would add a cycle. The
   issue is the *wrap itself*, not the destination. Option 1
   does not help.

2. **Swap to abs,x indexing**: Rewrite `mult66` to compute
   `sum = a + b` in X directly (with a sum-page branch like
   `mul_8x8` — but this is what S12 replaced!), then use
   `lda sqtab_lo,x` for low-page and `lda sqtab_lo+256,x` for
   high-page. Re-introduces the sum-page software branch.
   Cost: loses the S12 P7 savings.

3. **Burn the page cross unconditionally** via a dummy load that
   always incurs 1 cy, OR rewrite the addressing so both arms
   take the same cycle count. Simplest: add a `nop` on the non-
   crossing path. Not clean but works:

   ```
   mult66:
       tya
       sec
   mult66_sbc_a:
       sbc #$00
       tax
       lda (lmul0),y       ; may page-cross (secret-dep)
       nop                 ; burn 2 cy to equalize with +1 crossing
       nop
       ...
   ```

   A cleaner variant is to force page-cross unconditionally:

   ```
   mult66:
       tya
       sec
   mult66_sbc_a:
       sbc #$00
       tax
       ; Force a known page cross by adding 256 to base before indexing.
       ; Set lmul0 low byte to $FF and adjust high byte down by 1:
       ; ... <requires init-time rework>
   ```

4. **Switch to `abs,y` indexing with a second SMC'd base**: Replace
   `(lmul0),y` with `sqtab_lo,y` + an SMC'd high-byte ripple
   (similar to shoup_k_loop's SMC of the high byte). This requires
   per-outer-j re-patching the SMC site. Potentially zero-cost if
   the high byte is patched once per outer j in the caller
   (`poly1305_multiply` J-loop).

**Recommended**: Option 4 for cleanest fix — remove the indirect-
indexed addressing entirely from the mult66 inner, replace with
SMC'd `abs,y` reading a per-j page of sqtab. Requires restructuring
the mult66 call site and possibly the sqtab layout.

**Impact to ship**: Should fix for v0.3.0. If not fixable in time,
must be explicitly disclosed in the CT contract section of README.

---

## 3. Full per-file branch classification

Every `bcc/bcs/beq/bne/bmi/bpl/bvc/bvs` in the 6 source files is
classified as PUBLIC (safe, no CT implication), YELLOW (secret-
derived but canonical CT pattern, accepted per plan), or RED
(secret-dep and leaks, F1/F2/F3).

### `src/main.s`

No branches. Trampoline / lib_entry RTS stub only.

### `src/lib/constants_lib.s`

No branches. Equates only, no code emitted.

### `src/lib/data_lib.s`

No branches. Segment reservations only.

### `src/lib/word32_lib.s`

| line | branch       | context                 | class  | notes |
|------|--------------|-------------------------|--------|-------|
| 306  | `bcc @done`  | `rotl32_1` subroutine   | RED-dead | Secret-dep MSB wrap (same pattern as F2). **Dead code** — not reached by production. Should be fixed for consistency. |
| 466  | `bcc @done`  | `rotr32_1` subroutine   | RED-dead | Secret-dep LSB wrap. **Dead code**. Same as above. |

Other branches in word32_lib.s: none (only straight-line primitive
code).

### `src/lib/chacha20_lib.s`

| line | branch              | context                    | class  | notes |
|------|---------------------|----------------------------|--------|-------|
| 213  | `bcc :+`            | `rotl32_1_zp` macro        | **RED / F2** | MSB-wrap branch; 80×/block on hot path via `cc20_qr_body_rest`. See F2. |
| 236  | `bcc :+`            | `rotr32_1_zp` macro        | **RED / F2** | LSB-wrap branch; same channel. |
| 555  | `bpl @copy_const`   | chacha20_init const copy   | PUBLIC | X-counter, 16 iters, no secret. |
| 563  | `bpl @copy_key`     | chacha20_init key copy     | PUBLIC | X-counter loop bound is public (32). Key bytes are loaded/stored but the *branch* is on the counter, not key content. |
| 571  | `bpl @copy_ctr`     | chacha20_init counter copy | PUBLIC | X-counter. |
| 579  | `bpl @copy_nonce`   | chacha20_init nonce copy   | PUBLIC | X-counter. Nonce is public anyway. |
| 674  | `beq @rounds_done`  | chacha20_block round loop  | PUBLIC | Branches on `cc20_round` (public 0..10 counter). |
| 756  | `bne @ctr_done`     | counter++ ripple           | PUBLIC-YELLOW | Branches on `inc cc20_counter` = 0 detect, i.e., on whether the block counter (public) overflows. Counter is a public 32-bit field. |
| 758  | `bne @ctr_done`     | counter++ ripple           | PUBLIC | Same. |
| 760  | `bne @ctr_done`     | counter++ ripple           | PUBLIC | Same. |
| 778  | `beq @enc_done`     | chacha20_encrypt len check | PUBLIC | Branches on `cc20_remain \| cc20_remain_hi == 0` — length is public API input. |
| 786  | `bne @full`         | chacha20_encrypt size pick | PUBLIC | `cc20_remain_hi != 0`. Length, public. |
| 789  | `bcc @partial`      | chacha20_encrypt size pick | PUBLIC | `cc20_remain < 64`. Length, public. |
| 804  | `bne @xor_loop`     | XOR loop exit              | PUBLIC | X = min(remain, 64), public length. |
| 826  | `bne @next_block`   | main loop exit             | PUBLIC | Decremented length counter. |

**chacha20_lib.s has 2 RED branches (F2 x2), 14 PUBLIC. All other
branches are on public counters.**

Non-branch channel check:
- `lda cc20_state,x` / `sta cc20_state,x` loads and stores in the
  init and round body use `abs,x` with a fixed base; page-cross
  depends on X (public round / word counter). No secret-dep page
  cross.
- `(cc20_data_ptr),y` in the XOR loop page-crosses on the
  plaintext buffer address (caller-chosen, public).
- `cc20_keystream,y` / `$40,y` is 4-cy fixed (ZP placement). Q5.

### `src/lib/poly1305_lib.s`

| line | branch              | context                    | class  | notes |
|------|---------------------|----------------------------|--------|-------|
| 85   | `bne @already_done` | `poly1305_lib_init` gate   | PUBLIC | Branches on `sqtab_ready` (public init flag). |
| 182  | `bpl @zero_h`       | `poly1305_init` h zero loop| PUBLIC | X-counter 16..0. |
| 186  | `bne @sqtab_done`   | `poly1305_init` gate       | PUBLIC | `sqtab_ready`. |
| 296  | `bne shoup_k_loop`  | Shoup inner k-loop         | PUBLIC | Y = 1..255 wrap, public. Q4. |
| 301  | `bne shoup_j_loop`  | Shoup outer j-loop         | PUBLIC | `poly_j` vs 16, public counter. |
| 372  | `beq @pg0`          | sqtab_init page select     | PUBLIC | Branches on `sq_i+1` (public loop index 0..511). |
| 394  | `bne :+`            | sqtab_init `inc sq_ad`     | PUBLIC | Carry ripple on public index arithmetic. |
| 409  | `bne :+`            | sqtab_init `inc sq_i`      | PUBLIC | Carry ripple on public counter. |
| 413  | `beq @done`         | sqtab_init exit            | PUBLIC | `sq_i+1 == 2` (i.e., i==512). Public bound. |
| 457  | `bne @loop`         | sqtab2_init loop           | PUBLIC | X wrap 1..255→0 (Profile B). Public. |
| 489  | `bcs :+`            | `mul_8x8` sign of a-b      | YELLOW | Plan-accepted: `mul_8x8` existed pre-optimization and its secret-dep branch is the S12 plan's quoted baseline ("same class"). |
| 496  | `beq @s0`           | `mul_8x8` sum-page branch  | YELLOW | Same family: pre-existing, plan-accepted as the baseline. Replaced by mult66 in Profile B's hot path. |
| 566  | `bcs @pos`          | `mult66` sign of a-b       | YELLOW | Plan-disclosed (poly1305_lib.s:550–558). Accepted. |
| 603  | `bcs @done`         | `poly_ripple` X vs 33      | PUBLIC | X is a public ripple index bounded by poly_product size. |
| 605  | `bne @done`         | `poly_ripple` INC wrap     | YELLOW | Canonical carry-chain: branches on whether an INC wrapped a byte to zero. Plan §4 explicitly documents this as CT-safe ("The early-exits removed from poly1305_multiply (beq on h[i] / r[j]) were such violations; carry-out branches are not."). |
| 607  | `bne @loop`         | `poly_ripple` X overflow   | PUBLIC | X++ wraparound check, bounded by poly_product size (33). |
| 644  | `bcc :+`            | `poly_pp_mult66` carry     | YELLOW | Canonical carry-chain on accumulator add. |
| 673  | `bcc :+`            | `poly_pp_shoup` carry      | YELLOW | Canonical carry-chain. |
| 869  | `bne @add_block`    | poly1305_block 16-byte add | PUBLIC | X counter 16..0. |
| 919  | `beq @upd_done`     | poly1305_update length 0   | PUBLIC | `cc20_remain` is public length. |
| 924  | `bcc @last_block`   | poly1305_update final gate | PUBLIC | `cc20_remain < 16`, public. |
| 943  | `bne @next_block`   | poly1305_update main loop  | PUBLIC | `cc20_remain` decrement, public. |
| 954  | `bpl @zero_scratch` | poly1305_update zero pad   | PUBLIC | X counter 15..0. |
| 959  | `beq @pad_done`     | poly1305_update partial 0  | PUBLIC | Remaining bytes count, public. |
| 965  | `bne @copy_partial` | poly1305_update copy loop  | PUBLIC | X counter, public length. |
| 1016 | `bne @add5`         | poly1305_final h+5 loop    | PUBLIC | Y counter 16..0, public. Note: the ADDS themselves ripple through carry on secret data, but the BRANCH is on the counter. |
| **1021** | `beq @no_reduce`| **F1 — bit 130 of (h+5)** | **RED / F1** | Secret-dep; see F1. |
| 1030 | `bcc @use_reduced`  | reduced-path copy loop     | PUBLIC-in-path | X counter 0..16, public. BUT this branch is only reached on the F1 RED arm, so its EXISTENCE vs NON-EXISTENCE is secret-dep (that's exactly F1's leak). The branch *itself* is on a public counter, but executing it or not is the leak. |
| 1046 | `bne @add_s`        | poly1305_final add s loop  | PUBLIC | Y counter. |
| 1055 | `bcc @output`       | poly1305_final tag output  | PUBLIC | X counter. |

**poly1305_lib.s**: 1 RED (F1), plus F3 non-branch channel
(`(lmul0),y` page-cross) which also lives here. 6 YELLOW-canonical,
22 PUBLIC.

### `src/lib/chacha20poly1305_lib.s`

| line | branch              | context                    | class  | notes |
|------|---------------------|----------------------------|--------|-------|
| 100  | `bne @auth_fail`    | `aead_decrypt` verify      | YELLOW | Canonical: branches on the OR-accumulator result of `aead_verify_tag`. This IS the API success/fail signal (CT-correct per RFC). |
| 154  | `bpl @copy_r`       | aead_init r copy           | PUBLIC | X counter. |
| 162  | `bpl @copy_s`       | aead_init s copy           | PUBLIC | X counter. |
| 180  | `bpl @copy_key`     | aead_init key copy         | PUBLIC | X counter 31..0. Key bytes move through A but branch is on counter. |
| 187  | `bpl @copy_nonce`   | aead_init nonce copy       | PUBLIC | X counter. |
| 204  | `beq @skip_aad`     | aead_process AAD gate      | PUBLIC | `aead_aad_len == 0`, public. |
| 218  | `beq @skip_ct`      | aead_process CT gate       | PUBLIC | `aead_data_len == 0`, public. |
| 283  | `bne @have_data`    | aead_process_padded gate   | PUBLIC | Length check, public. |
| 289  | `bne @full_block`   | aead_process_padded size   | PUBLIC | Length check, public. |
| 292  | `bcc @partial`      | aead_process_padded size   | PUBLIC | `len < 16`, public. |
| 463  | `bpl @cmp_loop`     | `aead_verify_tag` OR-acc   | YELLOW | Canonical CT tag compare. Q6. |

**chacha20poly1305_lib.s**: 2 YELLOW-canonical, 9 PUBLIC, 0 RED.

---

## 4. Canonical-OK patterns (YELLOW-acceptable)

These patterns are secret-derived in flag state but are plan-accepted
or RFC-canonical constant-time idioms.

### 4.1 Carry-chain ripple branches (plan §4)

The `bcc :+` at end of every multi-precision `adc` chain, and the
`bne @done` / `bne @loop` inside `poly_ripple`, all branch on
hardware carry flags that are derivatives of secret-operand
additions. **OPTIMIZATION_PLAN.md §4 explicitly documents these as
CT-safe** on 6502 because:
- They branch on flag state of an ADD, not on an operand byte
  value directly.
- The early-exits REMOVED in S4 P1 cleanup were `beq` on `h[i]`
  or `r[j]` directly; those were the violations.
- `poly_ripple:604–607` header comment at lines 591–596
  elaborates.

Instances: `poly1305_lib.s:603–607, 644, 673`, `poly1305_lib.s:394,
409, 756, 758, 760`.

**Caveat**: This classification assumes the plan's 6502-specific
argument holds. A stricter reviewer could argue that a branch on
post-ADD carry still leaks 1 bit per add; however, the alternative
(branchless multi-precision ADC chains) costs a lot on 6502, and
the plan makes a conscious tradeoff here. If the v0.4.0 CT claim
is tightened, these would need to revisit.

### 4.2 `aead_verify_tag` OR-accumulator fold → branch

`chacha20poly1305_lib.s:100 bne @auth_fail` branches on the single
boolean output of the OR-accumulator at
`chacha20poly1305_lib.s:453–465`. The OR-accumulator itself is
branchless over all 16 tag bytes; the final branch reveals only
the RFC-mandated success/fail bit. This is the canonical CT tag
compare pattern and is accepted GREEN-as-YELLOW (the branch
exists, but it only reveals what the caller will learn from the
return value anyway).

### 4.3 `mult66 bcs @pos` (sign of a-b)

`poly1305_lib.s:566`. Plan-disclosed, accepted as "same class" as
the pre-existing `mul_8x8` baseline. The diff-path loads both
access per-page-aligned tables (`sqtab_lo`, `sqtab2_lo`), so no
secondary page-cross channel via those loads. **The secondary
channel on `(lmul0),y` is F3, not this one.**

### 4.4 `mul_8x8` sum-page branch

`poly1305_lib.s:489, 496`. Pre-existing pre-optimization code.
Used only for the Shoup init (test code path in Profile A) and
Profile B's non-hot-path `mul_8x8` routine — not on the
poly1305_multiply inner for Profile B (that goes through mult66).
In Profile A it may be reachable from `sqtab_init` utilities only,
no secret operands.

**Verify**: grep for `mul_8x8` callers — used by `sqtab_init`? No,
`sqtab_init` computes squares via recurrence, not `mul_8x8`. The
`mul_8x8` routine is present for API completeness but not in
either profile's hot path. PUBLIC from actual-reachability
perspective.

---

## 5. Non-branch timing channels

### 5.1 Indexed addressing mode page-cross

6502 `abs,x` / `abs,y` / `(zp),y` add 1 cycle when the effective
address crosses a page boundary. Any such load indexed by a
secret-derived value leaks whether `base.lo + index >= 256`.

**Secret-dep page-cross channels found**:

- **F3**: `poly1305_lib.s:565, 570, 578` — `(lmul0),y` and
  `(lmul1),y` where `y = h[i]`, `lmul0.lo = r[j]`. See F3.

**Verified clean** (static analysis):

- `poly_reduce_shl6_tab,y` at `poly1305_lib.s:694–698` is
  **explicitly `.align 256`**. Comment at lines 688–693 says:
  *"Page-aligned so that `lda poly_reduce_shl6_tab,y` never crosses
  a page boundary — `lda abs,y` adds a 1-cycle penalty on page
  cross, and Y here is derived from h*r (secret), so a
  cross-dependent timing would be a CT violation. Aligning the
  base low byte to $00 makes the access strictly constant-time."*
  — verified. GREEN.

- `sqtab_lo,y` / `sqtab_lo+256,x` / `sqtab_hi,y` / `sqtab_hi+256,x`
  in `mul_8x8`: base is `$8000`/`$8200`, X and Y are `sum.lo` and
  `|a-b|` respectively. Since `sqtab_lo = $8000` is page-aligned
  AND X/Y stay in 0..255, these never page-cross. GREEN.

- `sqtab_lo,x` / `sqtab2_lo,x` in `mult66`: base pages `$8000`,
  `$8400`, page-aligned; X is `b - a` or `256 - (a-b)` both in
  0..255; never page-cross. GREEN (this is what the mult66 header
  correctly claims).

- `r_tab_lo + (ja*256), x` in `poly_pp_shoup`: base is
  `$6000 + j*256`, page-aligned; X = `poly_h + i` (a ZP address,
  not content — wait, this is wrong — it's `ldx poly_h + ia`
  meaning X = h[i] the value). X in 0..255, base page-aligned,
  so never page-cross. GREEN.

- `poly_h,x` / `poly_h,y` loads where the index is a public row/col
  counter (unrolled `.repeat` with compile-time constant indices):
  no runtime index, no page-cross. GREEN.

- `cc20_keystream,y` at `chacha20_lib.s:800`: Q5 verified —
  base = $40 ZP, y < 64, never page-cross. GREEN.

- `(cc20_data_ptr),y` at `chacha20_lib.s:799, 801`: plaintext
  pointer and index; the pointer is caller-chosen (public) and Y
  is a block-offset counter 0..63 (public). The page-cross depends
  on the public plaintext address + public offset. PUBLIC.

- `(zp_ptr1),y` in `poly1305_block` add-block loop
  (`poly1305_lib.s:865, 893`): pointer is caller-chosen (public),
  Y is a byte index 0..15 (public). PUBLIC page-cross — depends
  on the AEAD data pointer the caller chose.

- `poly_product,x` / `poly_product,y` loads throughout the
  schoolbook unrolled macros: base is a public label, indices
  are compile-time constants from `.repeat`. GREEN.

- `poly_h,x` in `poly1305_final`'s `@add5` loop: X is a counter
  1..16 (public). GREEN.

- `poly_product,x` in the `@use_reduced` loop of `poly1305_final`:
  X is a public counter 0..16. GREEN (except the WHOLE LOOP is
  gated by F1's RED branch).

- `poly1305_tag,x` / `aead_tag,x` in `aead_verify_tag`: base is
  a fixed DATA label, X is a public 15..0 counter. GREEN.

### 5.2 Self-modifying code patch timing

SMC sites (all verified fixed-cycle writes to static patch
addresses):
- `shoup_ld_lo+2`, `shoup_sta_lo+2`, etc. in `shoup_init` —
  patches written before the inner loop begins. No branches on
  patch writes. PUBLIC (written from `poly_j`).
- `shoup_rj_val+1` in `shoup_init` — patches r[j] into an `adc #imm`
  site. The patch itself is `sta shoup_rj_val+1` (4 cy fixed). The
  subsequent `adc #imm` uses immediate addressing (2 cy fixed).
  **No timing variance from SMC**. GREEN.
- `mult66_sbc_a+1` — patched once per outer-j iteration in
  `poly1305_multiply`. Same analysis: 4 cy write, 2 cy immediate
  use. GREEN.
- `cc20_state_tail` SMC in `chacha20_lib.s` (S13 C8) — patches
  ChaCha20 state tails. The patches are with PUBLIC round-counter
  values, not secret bytes. GREEN.
- `aead_partial` SMC dispatch in `chacha20poly1305_lib.s` — the
  dispatch key is the partial-block length (public API input).
  GREEN.
- `smc_lo_addr` / `smc_hi_addr` in `ct_mul_8x8`
  (`src/lib/poly1305_lib.s`) — the SMC target sites for the
  quarter-square sum-page dispatch. The target-site `lda abs,x`
  placeholder operand is now derived from `sqtab_lo` / `sqtab_hi`
  equates (v0.5.1 hardening, issue #40 audit follow-up) so the
  static image stays consistent with `LIB_SHARED_SQTAB_BASE` under
  consumer overrides. CT properties unchanged: the hi-byte patch
  is a 4 cy `sta abs`, the subsequent indexed load is 4 cy on a
  page-aligned base (no page-cross), both fixed-cycle. GREEN.

### 5.3 Jump tables / indirect branches

None in the library. All control flow is direct branches, jsr,
or rts.

### 5.4 Interrupt timing

The library does not disable IRQs during its hot paths. A host
system that delivers IRQs during chacha20_block / poly1305_block
could cause timing variance, but this is a host concern, not a
library one. Consumers requiring strict CT should SEI around
library calls.

---

## 6. Dead-code report

**`word32_lib.s::rotl32_1` (line 286)** and **`word32_lib.s::rotr32_1`
(line 447)**, both as subroutines, are **NOT reachable from the
AEAD hot path** (`aead_encrypt`, `aead_decrypt`,
`chacha20_encrypt`, `poly1305_block`, etc.). They are reachable
ONLY via the `chacha20_quarter_round` test-only entry point
(`.export`ed from `chacha20_lib.s`).

Both subroutines contain the SAME F2 pattern (`bcc @done` on MSB/LSB
wrap). If the library drops the `chacha20_quarter_round` export
(it's a diagnostic/test entry, not needed for AEAD), both
subroutines become fully dead and can be deleted.

**Recommendation**: For v0.3.0, patch F2 in BOTH the macros
(chacha20_lib.s:213, 236) AND the subroutine variants
(word32_lib.s:306, 466) for consistency, even though only the
macros are reached by production code. The fix is the same
~2–3 cy branchless rewrite in both.

---

## 7. Anomalies and surprises

- **F3 was not in my initial escalation.** I found F1 and F2 in
  the first pass and escalated with just those two. During the
  full branch classification I discovered the `(lmul0),y`
  page-cross channel, which is a SEPARATE leak from the
  already-disclosed `bcs @pos` branch. The mult66 header comment
  correctly claims "`,x` loads don't page-cross" — but that
  carves out a narrower guarantee than the comment's tone
  implies, and the `(zp),y` loads in the same routine DO
  page-cross on secret data.

- **Profile A and Profile B both have F1 and F2.** F3 is Profile B
  only (mult66 is `.ifndef POLY1305_PROFILE_LONG`).

- **The OPTIMIZATION_PLAN.md §4 language is narrow.** It says
  *"no data-dependent branch on secret data"* but also
  explicitly-permits carry-chain branches. F1 and F2 are NOT
  carry-chain branches — they're branches on MSB/LSB bit
  positions of secret data, which the plan's own language
  prohibits. F3 is not a branch at all; it's a timing channel
  via page-cross on indirect-indexed addressing, a kind of leak
  the plan doesn't mention at all.

- **`poly_reduce_shl6_tab` is explicitly aligned to avoid a
  page-cross leak**, showing the authors are aware of `abs,y`
  page-cross as a CT channel. This makes the F3 `(zp),y`
  oversight a more surprising miss — the same class of concern
  was addressed elsewhere but not here.

- **F1 is architecturally the cheapest fix.** It runs once per
  AEAD op (finalization), and a branchless mask-blend adds
  ~200 cy to a 1.7M cy op (0.01% overhead). F2 actually SAVES
  cycles after the fix (branchless rewrite is faster than the
  branchy original). F3 is the trickiest — options 2 and 4
  require restructuring; option 3 is an inelegant equalization
  nop.

- **No `poly1305_tag_finalize` symbol exists**; the actual
  exported name is `poly1305_final`. Noted in API.md as a
  documentation discrepancy vs. the task brief's phrasing.

---

## 8. Summary counts

| file                          | RED | YELLOW | PUBLIC |
|-------------------------------|-----|--------|--------|
| main.s                        |  0  |   0    |   0    |
| constants_lib.s               |  0  |   0    |   0    |
| data_lib.s                    |  0  |   0    |   0    |
| word32_lib.s                  |  2 (dead) | 0 | ~dozens |
| chacha20_lib.s                |  2 (F2 × 2) | 0 | 14 |
| poly1305_lib.s                |  1 (F1) + 1 (F3 non-branch) | 6 | 22 |
| chacha20poly1305_lib.s        |  0  |   2    |   9    |
| **TOTAL (production-reachable)** | **3 (F1, F2, F3)** | **8** | **~45** |

**OVERALL VERDICT: RED.**

The library cannot ship v0.3.0 under its current CT contract
language without at least F1 and F2 being fixed (both live in the
production AEAD hot path on both profiles). F3 is Profile-B-only
and has a smaller per-call leak but should also be fixed or
disclosed.

After F1, F2, F3 are fixed, the overall verdict will be GREEN
pending re-audit of the patched code (carry-chain branches
remain YELLOW by plan acceptance, which is the intended post-fix
steady state).

---

## Resolution (v0.3.0, post-fix)

All three findings flagged above were resolved in PR #14 /
commit `dc4c575` (merged to `main` as `f4f049e`). The library's
production hot path on both profiles is now free of the known
secret-dependent branches and addressing-mode timing issues
identified by this audit.

### F1 — `poly1305_final` h ≥ p branch: **RESOLVED**

- **Fix commit**: `dc4c575` (PR #14, "CT fix: F1 poly_final
  mask-blend + F2 chacha20 rot1 branchless + F3 ct_mul_8x8
  Profile B").
- **Fix summary**: the `bcs final_emit_h` / `final_emit_h_plus_p`
  branch was replaced with a branchless mask-blend. The final
  reduction now computes `h - p` and `h` in parallel, derives a
  single sign-bit mask from the borrow-out, and uses that mask
  to blend the two candidate outputs byte-by-byte into the tag
  buffer. Control flow is identical for all secret inputs; no
  data-dependent branch remains in `poly1305_final`.
- **Validation**: 214/214 RFC 7539 library vectors on both
  profiles. 30 000 / 30 000 `audit_cross_check.py` vectors
  against `pyca/cryptography` (tag bytes bit-identical). Bench
  delta on Profile A `aead_encrypt n=0`: −877 cy
  (one-time per-packet, rounds out with F2).

### F2 — `rotl32_1_zp` / `rotr32_1_zp` wrap branch: **RESOLVED**

- **Fix commit**: `dc4c575` (same PR).
- **Fix summary**: the `bcc no_wrap` / `inc` carry-propagation
  idiom in both single-bit rotate primitives was replaced with a
  branchless ASL/ROL chain. The new sequence performs the 32-bit
  rotate as four chained `asl`/`rol` operations with the top bit
  recycled into the bottom via a fixed-length `rol`, so the
  instruction stream taken is independent of the rotated word's
  top-bit value.
- **Deviation from original plan**: the plan anticipated deleting
  `rotl32_1`/`rotr32_1` as dead code. They are not dead —
  `rotr32_7` **falls through** to `rotl32_1`, and `rotl32_7`
  **tail-calls** `rotr32_1` via `jmp`. Both labels also appear in
  the test harness required-label list at
  `tools/test_chacha20_poly1305.py:1018`. They were therefore
  **rewritten branchless in place** rather than deleted, which
  preserves all call-site and fall-through behavior unchanged.
- **Validation**: 214/214 RFC 7539 library vectors on both
  profiles (ChaCha20 keystream bit-identical pre/post fix).
  30 000 / 30 000 `audit_cross_check.py` vectors. Bench delta:
  Profile A `chacha20_block` 44 481 → 43 135 cy (**−1 346 cy**,
  3.0% speedup — the branchless rewrite is *faster* than the
  conditional original because the common-case `bcc` penalty
  is gone).

### F3 — Profile B `mult66` `(zp),y` secret-pointer load: **RESOLVED**

- **Fix commit**: `dc4c575` (same PR).
- **Fix summary**: the Profile B `mult66` inline multiply and
  its Step-12 pointer-table scaffolding (`lmul0`/`lmul1` ZP
  slots, `sqtab2_lo`/`sqtab2_hi` companion tables at
  `$8400..$87FF`) were **structurally removed**. Profile B now
  uses a new branchless constant-time 8×8 multiply primitive
  `ct_mul_8x8` that computes `a*b` via the quarter-square
  identity `a*b = ((a+b)² − (a−b)²) / 4` with a branchless
  sign-mask absolute-value step for `a−b`. All table loads are
  `abs,x` (page-aligned on `$8000`/`$8200`), so no
  secret-dependent addressing-mode timing remains. The design
  memo is in `docs/design/ct_mul_8x8.md`.
- **Validation**:
  - **Exhaustive brute-force**: `tools/ct_mul_brute_check.py`
    iterates all 65 536 `(a, b)` pairs in `[0,255]²` and asserts
    `ct_mul_8x8(a, b) == a * b` against Python's
    arbitrary-precision reference. **65 536 / 65 536 pass**
    (2.7 s Profile B). This is the cheapest full-coverage test
    possible for an 8×8 primitive and is the correctness gate
    for the new multiply.
  - **AEAD cross-check**: 15 000 Profile B vectors via
    `tools/audit_cross_check.py` against `pyca/cryptography`,
    all byte-identical.
  - **RFC 7539 vectors**: 214/214 on Profile B.
- **Performance cost**: Profile B `poly1305_block` 27 195 →
  37 844 cy (**+10 649 cy**, +39%); `aead_encrypt n=1024`
  2 590 638 → 3 259 490 cy (**+668 852 cy**, +25.8%). Profile B
  still delivers **−45.4%** versus the sprint-0 baseline
  (5 974 048 cy at n=1024) and remains the correct choice for
  short-packet workloads. Profile A is unaffected by F3 (Shoup
  per-r tables own the multiply hot path at runtime).

### Overall post-fix verdict: **GREEN**

No known secret-dependent branches or secret-dependent
addressing-mode timing remain in the production hot path on
either profile. The carry-chain YELLOW items called out in §6
above remain classified as YELLOW by plan acceptance
(terminating ripple, sign-inferred rather than value-inferred)
and are the intended post-fix steady state.

`docs/AUDIT.md` is the top-level human-facing audit summary
that tracks this verdict; `docs/REPRO_CHECK.md` records the
bit-for-bit reproducibility gate on the merged-main CT-fix
commit.
