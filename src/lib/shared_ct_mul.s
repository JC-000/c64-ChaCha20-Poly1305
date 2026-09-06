; =============================================================================
; lib/shared_ct_mul.s - c64-lib-contract SPEC §8.3 constant-time 8x8 multiply
;
; ONE TRANSLATION UNIT, ONE DISPLACEABLE GROUP. Split out of poly1305_lib.s
; for SPEC §6.1 member isolation (v1.2.0; carve-out v1.2.1; both collision
; directions named at v1.2.2), issue #108 item 2. This file exports
; `ct_mul_8x8` and the two SMC operand-bake sites `smc_sum_a_imm` /
; `smc_diff_a_imm` — three of §8.3's five provider-surface names, all
; dropped by one switch, `-D SHARED_CT_MUL_8X8=1` — and NOTHING else a
; consumer may import. The other two (poly_prod_lo/hi) are in
; shared_prod_scratch.s and the reason is mechanical, not contractual: see
; that file's header. Everything else this TU defines (smc_lo_addr,
; smc_hi_addr and the SMC pack's `_SMC` designators) is internal to the body
; below.
;
; The two SMC sites CANNOT be isolated any further: they are labels on
; immediate operands INSIDE the ct_mul_8x8 body. That is the construction
; proof that §6.1's "other displaceable names included" cannot mean one
; name per TU — see shared_sqtab_init.s's header for the reading this
; library settled on.
;
; DO NOT REORDER: this TU sits between mul_8x8_legacy.o and poly1305_core.o
; on every link line. See poly1305_lib.s's header.
; =============================================================================

.setcpu "6502"
.include "constants_lib.s"      ; ct_diff_raw / ct_sign_mask ZP scratch
.include "smc.inc"

; Profile B reads sqtab via ct_mul_8x8 and emits the sqtab init.
; Profile A gates these out entirely — see issue #34 F1 and the
; "Profile A dead-code trim" comment block at sqtab_init / mul_8x8.
; c64-lib-contract SPEC §8.3 ct_mul_8x8 migration switch (issue #47).
;
; Owner mode (default): this library provides the canonical §8.3 body.
; SPEC §8.3 names `ct_mul_8x8` as the canonical entry, so it is exported
; here. Before issue #47 the manifest claimed the $0004 ownership bit
; while `ct_mul_8x8` stayed a local label with no `.export`, so no
; sibling could actually defer to this library as provider — the claim
; was unsatisfiable. `poly_prod_lo` / `poly_prod_hi` are the §8.3
; product scratch, and `smc_sum_a_imm` / `smc_diff_a_imm` are the
; operand-bake sites a caller patches with `a` before each call.
;
; Deferral mode (`-D SHARED_CT_MUL_8X8=1`): the body below is gated out
; and this whole TU becomes empty, so the member is never pulled and the
; designated owner's copy is the only one in the link, per §8.3 "Migration
; shape". The `.import`s that §8.3 requires a deferring build to leave
; behind live in the TU that actually references the names — that is
; src/lib/poly1305_core.s, which imports all five in EVERY build. Before
; issue #47 the switch flipped only the manifest bit while these exports
; stayed live, so the two-archive link against c64-x25519 v0.8.0 (which
; exports the same three names) died with
; `ld65: Error: Duplicate external identifier: 'poly_prod_hi'`.
;
; `poly_prod_lo` / `poly_prod_hi` are exported by src/lib/shared_prod_scratch.s
; and imported here — see that file's header for why the §8.3 product
; scratch is a separate member (emitted byte order, not contract).
.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_CT_MUL_8X8
.export ct_mul_8x8
.export smc_sum_a_imm, smc_diff_a_imm
.import poly_prod_lo, poly_prod_hi
.endif
.endif

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)

.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_CT_MUL_8X8
.include "sqtab_base.inc"
sqtab_lo        = LIB_SHARED_SQTAB_BASE
sqtab_hi        = LIB_SHARED_SQTAB_BASE + $0200
.assert sqtab_hi = sqtab_lo + $0200,        error, "sqtab_hi must follow sqtab_lo by $0200"
.endif
.endif

.ifndef POLY1305_PROFILE_LONG
; A deferral build (`-D SHARED_CT_MUL_8X8=1`) gates this body out and
; calls the owner's canonical `ct_mul_8x8` instead — SPEC §8.3
; "Migration shape" (issue #47). The callers are unaffected: they bake
; `a` into smc_sum_a_imm+1 / smc_diff_a_imm+1 and read the result from
; poly_prod_lo/hi, and all four names resolve to the owner's copy.
.ifndef SHARED_CT_MUL_8X8
; =============================================================================
; ct_mul_8x8 — Profile B constant-time 8×8 → 16-bit multiply (v0.3.0 CT fix)
;
; Structural replacement for the Step 12 `mult66` primitive. mult66 was
; fast (~22 cy body) but leaked the secret page-cross bit on its two
; `lda (lmul0),y` / `lda (lmul1),y` indirect-indexed loads: `(zp),y`
; takes 5 cy on same-page and 6 cy on page-cross, and the cross occurs
; iff a+b >= 256, which is a function of both secret operands. See
; CT_ANALYSIS.md §2.F3 and F3_FIX_DESIGN.md §3.1 for the data-flow trace.
;
; Identity (unchanged): a*b = floor((a+b)^2/4) - floor((a-b)^2/4)
;                            = sqtab[a+b] - sqtab[|a-b|]
;
; CT strategy (two branchless patches over pre-S12 `mul_8x8`):
;
;   Patch 1: SMC-patch the hi byte of two `lda abs,x` loads at each
;            call so they address sqtab_{lo,hi} or sqtab_{lo,hi}+256
;            depending on the sum-page bit. `abs,x` takes 4 cy with
;            no page-cross penalty regardless of the patched page:
;            the hi byte is encoded in the instruction, not formed
;            from base.lo + x. Timing is therefore independent of
;            whether a+b >= 256. Same trick poly_reduce_shl6_tab uses.
;
;   Patch 2: Branchless |a-b| via `raw = b - a`, capture sign with
;            `lda #0 / sbc #0` (→ $00 if b>=a, $FF if b<a), then
;            `eor raw / sec / sbc mask` flips-and-negates the raw
;            value without a `bcc` branch. Result Y = |a-b|.
;
; Entry: Y = b, smc_sum_a_imm+1 = smc_diff_a_imm+1 = a (SMC-baked by
;        the caller's outer-j loop in poly1305_multiply).
; Exit:  poly_prod_lo / poly_prod_hi = a * b (16-bit).
; Clobbers: A, X, Y, ct_diff_raw, ct_sign_mask, and the four SMC
;           patch sites below.
;
; Timing: ~82 cy body. No data-dependent branches. No indirect-indexed
; loads. No `abs,y` / `abs,x` page-cross (sqtab_lo/hi and sqtab_lo+256
; / sqtab_hi+256 are all page-aligned; the sbc-y reads sqtab_{lo,hi}
; at |a-b| in [0,255] so never cross either). CT-clean.
;
; See F3_FIX_DESIGN.md §3.1 for the full CT proof.
ct_mul_8x8:
        ; --- Compute sum = a + b and SMC-patch the two abs,x hi bytes ---
        tya                             ; A = b
        clc
        SMC smc_sum_a_imm, { adc #$00 } ; SMC imm = a; A = (a+b).lo, C = page
        tax                             ; X = (a+b) & $FF
        lda #>sqtab_lo
        adc #0                          ; $80 or $81 (C already folded in above)
        SMC_StoreHighByte smc_lo_addr   ; patch sqtab_lo abs,x hi byte
        adc #(>sqtab_hi - >sqtab_lo)    ; C=0 after prior adc #0, so += 2
        SMC_StoreHighByte smc_hi_addr   ; patch sqtab_hi abs,x hi byte

        ; --- Branchless |a-b| → Y (sign-mask flip-and-negate) ---
        tya                             ; A = b
        sec
        SMC smc_diff_a_imm, { sbc #$00 }; SMC imm = a; A = b-a, C=1 iff b>=a
        sta ct_diff_raw
        lda #$00
        sbc #$00                        ; C=1: 0; C=0: $FF (sign mask)
        sta ct_sign_mask
        eor ct_diff_raw                 ; raw XOR mask
        sec
        sbc ct_sign_mask                ; + (−mask): +0 if b>=a, +1 if b<a
        tay                             ; Y = |a-b| (in [0,255])

        ; --- Table-lookup subtract: sqtab[a+b] − sqtab[|a-b|] ---
        ; SMC target-site operands are derived from the sqtab_{lo,hi}
        ; equates (= LIB_SHARED_SQTAB_BASE +0/+$0200) so the static
        ; image stays consistent with the equate under consumer
        ; overrides. Behavior is unchanged: ct_mul_8x8 always patches
        ; the hi byte (via SMC_StoreHighByte smc_{lo,hi}_addr above)
        ; before the indexed load executes, so the runtime page is
        ; always equate-driven; this just keeps the as-assembled bytes
        ; in sync with the equate at the static-image level (defense
        ; in depth — issue #40 audit follow-up).
        SMC smc_lo_addr, { lda sqtab_lo,x } ; SMC base: sqtab_lo or sqtab_lo+256
        sec
        sbc sqtab_lo,y                  ; sqtab_lo[|a-b|]
        sta poly_prod_lo
        SMC smc_hi_addr, { lda sqtab_hi,x } ; SMC base: sqtab_hi or sqtab_hi+256
        sbc sqtab_hi,y                  ; sqtab_hi[|a-b|]
        sta poly_prod_hi
        rts

; Cross-library aliases for the two operand-bake sites (issue #47). The
; SMC macro pack spells the underlying labels with a `_SMC` suffix
; (`smc_sum_a_imm_SMC`), but SPEC §8.3 and c64-x25519 use the
; unsuffixed names, so a deferring sibling patching our body — or our
; callers patching a sibling's body — needs this spelling to exist.
; Same address, so the emitted bytes are unchanged.
smc_sum_a_imm  = smc_sum_a_imm_SMC
smc_diff_a_imm = smc_diff_a_imm_SMC

.endif  ; .ifndef SHARED_CT_MUL_8X8 (ct_mul_8x8 body)
.endif
