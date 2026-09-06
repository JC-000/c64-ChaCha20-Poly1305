; =============================================================================
; lib/poly1305_core.s - Poly1305 arithmetic half (RFC 7539)
;
; poly_reduce_shl6_tab, poly1305_multiply, poly1305_reduce, poly1305_block,
; poly1305_update, poly1305_final. Split out of poly1305_lib.s at issue #108
; item 2 — not because anything here is displaceable (nothing is), but
; because the four displaceable TUs it now sits behind were emitted BETWEEN
; this code and poly1305_lib.s's half. Keeping the arithmetic in its own TU,
; last on the link line, is what makes the whole split byte-neutral: the
; seven objects contribute to LIB_CHACHA20_POLY1305_CODE in exactly the
; order the single file did, and all four profile PRGs are byte-identical
; to v0.10.0.
;
; This TU carries `.align 256` (for poly_reduce_shl6_tab's CT invariant), so
; ld65 starts its section on a page boundary — $1D00 on Profile B, exactly
; where the table sat in v0.10.0. `poly_ripple`, which preceded the table
; inside the old single section at a NON-page address, therefore had to move
; to its own unaligned TU; see src/lib/poly1305_ripple.s.
;
; This TU imports the §8.3 surface it uses (ct_mul_8x8, poly_prod_lo/hi and
; the two SMC bake sites) in EVERY build, owner and deferral alike — they
; live in another TU now either way. That import is also what lets a
; consumer's own APP_OWNED definitions win: they are on the link command
; line before any archive is scanned, so ld65 resolves these imports against
; the consumer and never pulls the library's own member beside them. Before
; the split those definitions sat in the same member as poly1305_final, so
; the member arrived uninvited and ld65 reported
; `Duplicate external identifier: 'ct_mul_8x8'`.
;
; DO NOT REORDER: this TU is last of the seven on every link line. See
; poly1305_lib.s's header.
; =============================================================================

.include "constants_lib.s"
.include "smc.inc"

; Cross-module imports: data_lib state.
.import poly_h, poly_r, poly_s, poly_product, poly1305_tag
.import aead_scratch
.import poly_ripple

.export poly1305_multiply, poly1305_reduce
.export poly1305_block, poly1305_update, poly1305_final

; SPEC §8.3 surface, resolved from src/lib/shared_ct_mul.s +
; src/lib/shared_prod_scratch.s in an owner build, from the designated owner
; in a `-D SHARED_CT_MUL_8X8=1` build, or from the consumer's own object in
; an APP_OWNED link against the default archive. Either way it is an import
; here, which is what §8.3's "MUST .import where referenced" asks for.
.ifndef POLY1305_PROFILE_LONG
.import ct_mul_8x8
.import poly_prod_lo, poly_prod_hi
.import smc_sum_a_imm, smc_diff_a_imm
.endif

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)
; =============================================================================
; poly1305_multiply - Multiply h (17 bytes) by r (16 bytes), reduce mod 2^130-5
;
; Fully unrolled 17x16 schoolbook multiply (272 partial products) as a
; straight-line macro expansion. Eliminates the inner/outer loop overhead
; from the old loopy form (~12 k cy per block) and removes the two
; data-dependent early-exits (`beq @skip_h_zero`, `beq @skip_r_zero`)
; which were constant-time violations — every partial product is now
; computed unconditionally regardless of h[i] or r[j] being zero.
;
; Each partial product h[i]*r[j] is added to poly_product[i+j..i+j+1]
; via a 16-bit add; if that add leaves carry set, poly_ripple propagates
; it upward. Final reduction mod 2^130-5 is handled by poly1305_reduce.
;
; Clobbers: A, X, Y
; =============================================================================

.ifndef POLY1305_PROFILE_LONG
; Macro: emit one partial product h[i] * r[j] — Profile B CT path
; (v0.3.0 CT fix). Used inside a J-outer / I-inner double loop, with
; r[j] already SMC-baked into smc_sum_a_imm+1 and smc_diff_a_imm+1
; at outer-j entry. Calls `ct_mul_8x8` to compute h[i]*r[j] into
; poly_prod_lo/hi, then accumulates into poly_product[I+J..I+J+1].
; Entry Y = h[i] for ct_mul_8x8. Exit preserves poly_prod_{lo,hi}.
.macro poly_pp_ct_mul ia, ja
        ldy poly_h + ia
        jsr ct_mul_8x8
        clc
        lda poly_product + (ia + ja)
        adc poly_prod_lo
        sta poly_product + (ia + ja)
        lda poly_product + (ia + ja + 1)
        adc poly_prod_hi
        sta poly_product + (ia + ja + 1)
        bcc :+
        ldx #(ia + ja + 2)
        jsr poly_ripple
:
.endmacro
.endif

.ifdef POLY1305_PROFILE_LONG
; Macro: Shoup-table partial product h[i] * r[j] — Profile A.
;
; Precondition on entry: X = poly_h + i (loaded once per outer row).
; The Shoup table at r_tab_lo + j*256 holds T_j[x] = (x * r[j]) & $ff,
; and r_tab_hi + j*256 holds the high byte. Two page-indexed loads
; replace the sqtab-based 8x8 multiply entirely.
;
; Postcondition: X still equals poly_h + i (reloaded from RAM only
; on the rare ripple path).
;
; No branches depend on the *value* of h[i] or r[j]; the only branch
; (bcc) depends on carry-out from the addition, which is standard
; multi-precision arithmetic and CT-safe on 6502.
.macro poly_pp_shoup ia, ja
        clc
        lda r_tab_lo + (ja * 256), x
        adc poly_product + (ia + ja)
        sta poly_product + (ia + ja)
        lda r_tab_hi + (ja * 256), x
        adc poly_product + (ia + ja + 1)
        sta poly_product + (ia + ja + 1)
        bcc :+
        ldx #(ia + ja + 2)
        jsr poly_ripple
        ldx poly_h + ia         ; ripple clobbered X; restore row base
:
.endmacro
.endif

; =============================================================================
; poly_reduce_shl6_tab - 256-entry LUT: tab[y] = (y & 3) << 6
;
; Used by the unrolled fused poly1305_reduce to land the top 2 bits of
; product[17+k] at bit positions 6..7 of the overflow byte without six
; in-line `asl`s. Saves ~10 cy per inner iteration × 16 iterations.
;
; **Page-aligned** so that `lda poly_reduce_shl6_tab,y` never crosses a
; page boundary — `lda abs,y` adds a 1-cycle penalty on page cross, and
; Y here is derived from h*r (secret), so a cross-dependent timing
; would be a CT violation. Aligning the base low byte to $00 makes the
; access strictly constant-time.
;
; The `.align 256` above is not self-enforcing: it is honoured only if
; the consumer's cfg declares LIB_CHACHA20_POLY1305_CODE with
; `align = $100`, and ld65 merely WARNS when it does not — it links the
; table misaligned and exits 0. The deferred assert below is what turns
; that into a link error, on the same footing as the two nibswap LUTs in
; data_lib.s (issue #100). See the note at the head of that segment in
; data_lib.s for why the action is `lderror` and why the assert tests
; the resolved address rather than the directive.
; =============================================================================
        .align 256
poly_reduce_shl6_tab:
        .repeat 256, V
            .byte (V & 3) << 6
        .endrepeat

.assert (poly_reduce_shl6_tab & $00FF) = 0, lderror, "poly_reduce_shl6_tab must be page-aligned (CT invariant): Y derives from poly_product - consumer cfg must declare LIB_CHACHA20_POLY1305_CODE with align = $100, ld65 only WARNS otherwise"

poly1305_multiply:
        ; Zero the product buffer (33 bytes) — unrolled store chain.
        lda #0
        .repeat 33, Z
            sta poly_product + Z
        .endrepeat

.ifdef POLY1305_PROFILE_LONG
        ; Fully unrolled 17x16 schoolbook via Shoup per-r tables (P3).
        ; X is hoisted out of the j loop: h[i] is constant for all 16
        ; inner iterations of a given row.
        .repeat 17, I
            ldx poly_h + I
            .repeat 16, J
                poly_pp_shoup I, J
            .endrepeat
        .endrepeat
.else
  .ifdef POLY1305_MULTIPLY_ROLLED_OUTER
        ; --- Profile B + outer-only-rolled (midpoint on the size/cycles
        ;     curve for issue #34). Outer J=0..15 is a runtime loop, but
        ;     each iteration still inlines all 17 inner-I partial products
        ;     as a straight-line macro expansion. Pays one extra outer-loop
        ;     setup (load r[j] via abs,x; increment j; cmp; bne) per j —
        ;     a few hundred cycles — but avoids the 272 per-product
        ;     inc/cmp/bne overhead the fully-rolled variant adds.
        ;
        ;     Size is dominated by the 17 inlined partials: ~17*32 = ~544
        ;     bytes for the inner body, plus outer-loop scaffolding.
        ldx #0
        stx poly_j                      ; j = 0
@outer_jloop:
        ldx poly_j
        lda poly_r, x
        sta smc_sum_a_imm+1             ; bake `a` (see §8.3 block, issue #47)
        sta smc_diff_a_imm+1

        ; The poly_pp_ct_mul macro hardcodes the (i, j) pair into
        ; absolute addresses for poly_product[i+j..]. Since j is now a
        ; runtime value we can't bake j into the macro — fall back to an
        ; abs,x form inside the inner row. The compromise: inline 17
        ; instances of a "row" partial-product that uses X = j as the
        ; column offset for product addressing.
        ;
        ; For each i in 0..16 the inner body is:
        ;     ldy poly_h+i               ; constant offset, fine
        ;     jsr ct_mul_8x8             ; uses SMC'd r[j]
        ;     ldx poly_j                 ; column offset for product
        ;     clc
        ;     lda poly_product+i, x
        ;     adc poly_prod_lo
        ;     sta poly_product+i, x
        ;     lda poly_product+i+1, x
        ;     adc poly_prod_hi
        ;     sta poly_product+i+1, x
        ;     bcc :+
        ;     ; ripple from i+j+2; start X at j and add immediate i+2.
        ;     ; cheapest: txa / clc / adc #(i+2) / tax / jsr poly_ripple.
        ;     ; But this leaks no secret (i and 2 are constants, j is a
        ;     ; loop counter), so still CT-safe.
        ;     txa
        ;     clc
        ;     adc #(i + 2)
        ;     tax
        ;     jsr poly_ripple
        ;     :
        .repeat 17, I
            ldy poly_h + I
            jsr ct_mul_8x8
            ldx poly_j
            clc
            lda poly_product + I, x
            adc poly_prod_lo
            sta poly_product + I, x
            lda poly_product + I + 1, x
            adc poly_prod_hi
            sta poly_product + I + 1, x
            bcc :+
            txa
            clc
            adc #(I + 2)
            tax
            jsr poly_ripple
            :
        .endrepeat

        inc poly_j
        lda poly_j
        cmp #16
        beq @outer_done
        jmp @outer_jloop
@outer_done:
  .elseif .defined(POLY1305_MULTIPLY_ROLLED)
        ; --- Profile B + rolled-loop alternative 2 (issue #34) ----------
        ; Same J-outer / I-inner index pattern as the unrolled body, but
        ; expressed as runtime loops instead of a 17x16 macro expansion.
        ; CT contract preserved: only loop-control branches (on counter
        ; equality) and the carry-out ripple branch (a function of
        ; hardware flags, see poly_ripple header) appear in this loop.
        ; r[j] is still SMC-baked into ct_mul_8x8's immediate slots once
        ; per outer iteration. The inner loop maintains pp_idx (= i + j)
        ; as a running ZP byte so poly_product[i+j] / poly_product[i+j+1]
        ; reduce to `lda/sta poly_product,x` (single-page abs,x — no
        ; cross penalty: poly_product through poly_product+32 fits in
        ; one page).
        ;
        ; ZP reuse: poly_i holds the i counter, poly_j holds j and is
        ; also the running pp_idx (initialised to j and incremented
        ; per inner iteration). Both are otherwise unused in Profile B
        ; (poly_i / poly_j are only consumed by shoup_init, which is
        ; gated on POLY1305_PROFILE_LONG).
        lda #0
        sta poly_i                      ; i = 0 not used yet; init below
        sta poly_j                      ; j = 0
@rolled_jloop:
        ; --- Cache r[j] into ct_mul_8x8 immediates (one set per j) ----
        ldx poly_j
        lda poly_r, x
        sta smc_sum_a_imm+1             ; bake `a` (see §8.3 block, issue #47)
        sta smc_diff_a_imm+1

        ; --- Inner i loop: 17 iterations (i = 0..16) -------------------
        ; pp_idx = i + j starts at j; we keep it in poly_carry as a
        ; running byte since poly_carry is reset at every poly1305_block
        ; entry and is otherwise unused inside poly1305_multiply. (We
        ; cannot use poly_j itself for pp_idx because we also need the
        ; original j value to compare against #16 at the outer-loop
        ; bottom. We keep i in poly_i.)
        lda poly_j
        sta poly_carry                  ; pp_idx = j
        lda #0
        sta poly_i                      ; i = 0
@rolled_iloop:
        ldx poly_i
        ldy poly_h, x                   ; Y = h[i] → ct_mul_8x8 b operand
        jsr ct_mul_8x8                  ; clobbers A,X,Y; result in
                                        ; poly_prod_lo / poly_prod_hi

        ldx poly_carry                  ; X = pp_idx = i + j
        clc
        lda poly_product, x
        adc poly_prod_lo
        sta poly_product, x
        inx                             ; X = i + j + 1
        lda poly_product, x
        adc poly_prod_hi
        sta poly_product, x
        bcc @no_ripple
        inx                             ; X = i + j + 2 (ripple start)
        jsr poly_ripple                 ; clobbers A, X
@no_ripple:
        inc poly_carry                  ; pp_idx → i + 1 + j

        inc poly_i
        lda poly_i
        cmp #17
        bne @rolled_iloop

        inc poly_j
        lda poly_j
        cmp #16
        bne @rolled_jloop
  .else
        ; Profile B CT path (v0.3.0 CT fix). Loop order remains
        ; J-outer / I-inner (unchanged from Step 12) so each outer-j
        ; iteration can SMC-bake r[j] once into the ct_mul_8x8
        ; immediate slots and 17 inner iterations reuse that cached
        ; operand. Two SMC stores per j (vs three for the deleted
        ; mult66 path): no ZP pointer pair is needed.
        .repeat 16, J
            lda poly_r + J
            sta smc_sum_a_imm+1             ; bake `a` (see §8.3 block, issue #47)
            sta smc_diff_a_imm+1
            .repeat 17, I
                poly_pp_ct_mul I, J
            .endrepeat
        .endrepeat
  .endif
.endif

        ; Fall through to poly1305_reduce (fused Donna wrap).

; =============================================================================
; poly1305_reduce - Reduce poly_product (33 bytes) mod 2^130-5 into poly_h
;
; Step 7 (P4 Donna-style fused wrap): the schoolbook above still fills
; poly_product[0..32] as a 33-byte intermediate, but this reduction is
; rewritten as a single fused pass that merges the old two 1-bit right-
; shift passes and the 17-byte *5 running-carry loop into straight-line
; code that computes each overflow byte on the fly.
;
; Identity: product = L + 2^130 * H  where
;     L = product[0..15] + (product[16] & 3) << 128   (130 bits)
;     H = product[16..32] >> 2                        (124 bits, 17 bytes)
; and  product mod (2^130 - 5) = L + 5*H  (since 2^130 ≡ 5 mod p).
;
; overflow byte k = (product[16+k] >> 2) | ((product[17+k] & 3) << 6),
; with product[33] implicitly zero for k=16.
;
; Each overflow byte is multiplied by 5 via (x<<2)+x and added to h[k]
; with a running 16-bit carry.
;
; CT contract: the only branches are (a) ripple on adder carry, which is
; a function of hardware flags and independent of secret bytes beyond
; standard multi-precision arithmetic, and (b) loop control on a fixed
; 17-iteration unroll (fully straight-line here).
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_reduce:
        ; 1. Copy low 130 bits of product → h (straight-line).
        .repeat 16, K
            lda poly_product + K
            sta poly_h + K
        .endrepeat
        lda poly_product + 16
        and #$03
        sta poly_h + 16

        ; 2. Fused overflow-shift + *5 + add-to-h, fully unrolled for
        ;    k = 0..16. Running carry_in kept in poly_carry.
        ;
        ;    Per iteration:
        ;      ov    = (p[16+k] >> 2) | ((p[17+k] & 3) << 6)  ; k<16
        ;      ov    = (p[32] >> 2)                           ; k=16
        ;      prod5 = ov * 5                                 ; 16-bit (max 1275)
        ;      sum16 = prod5 + carry_in                       ; 16-bit
        ;      h[k] += sum16_lo; carry_out = sum16_hi + add_carry
        ;      carry_in := carry_out
        ;
        ;    All arithmetic is branch-free (no early-outs on secret ov),
        ;    matching the Step 4 CT cleanup.
        lda #0
        sta poly_carry

        .repeat 17, K
            ; --- form overflow byte K in A.
            lda poly_product + 16 + K
            lsr
            lsr                     ; A = p[16+K] >> 2 (bits 6..7 cleared)
            .if K < 16
                sta poly_tmp        ; stash low 6 bits of ov
                ldy poly_product + 17 + K
                lda poly_reduce_shl6_tab,y  ; A = (y & 3) << 6  (via 256-entry LUT)
                ora poly_tmp        ; A = overflow byte K
            .endif
            sta poly_tmp            ; poly_tmp = ov (stash for ov*5)

            ; --- compute ov*5 into (poly_i : A) branch-free.
            ;     poly_i is unused outside shoup_init, repurposed as the
            ;     running 8-bit hi scratch (max ov*5 = 1275, hi ≤ 4).
            lda #0
            sta poly_i
            lda poly_tmp            ; A = ov
            asl                     ; A = (ov<<1)&$ff, C = ov bit7
            rol poly_i              ; poly_i:A = ov*2
            asl
            rol poly_i              ; poly_i:A = ov*4
                                    ; rol leaves C = old poly_i bit7 = 0,
                                    ; so the following adc doesn't need clc.
            adc poly_tmp            ; A = (ov*4 + ov) lo = (ov*5) lo
            sta poly_tmp            ; poly_tmp = ov*5 lo (reuse)
            lda poly_i
            adc #0                  ; hi of ov*5
            sta poly_i              ; poly_i  = ov*5 hi

            ; --- add running carry_in to ov*5
            clc
            lda poly_tmp
            adc poly_carry
            sta poly_tmp
            lda poly_i
            adc #0
            sta poly_i              ; (poly_i : poly_tmp) = ov*5 + carry_in

            ; --- add to h[K], produce new carry_in for next k
            clc
            lda poly_h + K
            adc poly_tmp
            sta poly_h + K
            lda poly_i
            adc #0
            sta poly_carry          ; carry_in for iteration K+1
        .endrepeat

        rts

; =============================================================================
; poly1305_block - Process one 16-byte block
;
; Input: chacha20poly1305_zp_ptr1 points to 16-byte block
;        A = high bit to add (1 for normal blocks, 0 for final partial)
;
; Operations: h += block (with high bit), then h *= r mod p
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_block:
        sta poly_carry          ; save high bit value

.ifdef POLY1305_PROFILE_LONG
        ; h += block (16 bytes from (chacha20poly1305_zp_ptr1))
        ; IMPORTANT: Use DEX/BNE for loop control — CPY clobbers carry,
        ; which would break carry propagation in the multi-byte addition.
        clc
        ldx #16                ; byte counter
        ldy #0
@add_block:
        lda poly_h,y
        adc (chacha20poly1305_zp_ptr1),y
        sta poly_h,y
        iny
        dex
        bne @add_block

        ; h[16] += high bit + carry
        lda poly_h+16
        adc poly_carry
        sta poly_h+16
.else
        ; Profile B (Step 12 P7): straight-line block-add. Y walks the
        ; 16 byte indexes 0..15 so the `adc (chacha20poly1305_zp_ptr1),y` stays a single
        ; addressing mode, while `lda/sta poly_h,y` uses absolute,y.
        ; Compared to the Profile A DEX/BNE loop (~321 cy for 16 iters),
        ; the straight-line chain drops loop-control cycles (iny+dex+bne
        ; = 7 cy/iter × 16 = 112 cy) at a cost of only slightly more
        ; code bytes.
        ;
        ; The fully-unrolled fuse-with-multiply form of P7 isn't
        ; achievable in byte layout without stashing and restoring the
        ; inter-byte carry around each mult66 call (which costs more
        ; than it saves on a 17-byte ripple). The carry chain is kept
        ; linear here and handed off to the multiply in a single sweep.
        clc
        ldy #0
        .repeat 16, K
            lda poly_h + K
            adc (chacha20poly1305_zp_ptr1),y
            sta poly_h + K
            .if K < 15
                iny
            .endif
        .endrepeat
        ; h[16] += high bit + carry
        lda poly_h+16
        adc poly_carry
        sta poly_h+16
.endif

        ; h *= r mod p
        jsr poly1305_multiply
        rts

; =============================================================================
; poly1305_update - Process message data
;
; Input: chacha20poly1305_zp_ptr1 = pointer to data, cc20_remain = length
;        (Reuses cc20_remain as a general byte counter)
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_update:
        lda cc20_remain
        beq @upd_done

@next_block:
        lda cc20_remain
        cmp #16
        bcc @last_block         ; < 16 bytes remaining = partial final block

        ; Full 16-byte block with high bit = 1
        lda #1
        jsr poly1305_block

        ; Advance pointer by 16
        clc
        lda chacha20poly1305_zp_ptr1
        adc #16
        sta chacha20poly1305_zp_ptr1
        lda chacha20poly1305_zp_ptr1+1
        adc #0
        sta chacha20poly1305_zp_ptr1+1

        lda cc20_remain
        sec
        sbc #16
        sta cc20_remain
        bne @next_block
        rts

@last_block:
        ; Partial block: copy to aead_scratch with padding
        ; Zero the scratch buffer first
        ldx #15
        lda #0
@zero_scratch:
        sta aead_scratch,x
        dex
        bpl @zero_scratch

        ; Copy remaining bytes
        ldy #0
        ldx cc20_remain
        beq @pad_done
@copy_partial:
        lda (chacha20poly1305_zp_ptr1),y
        sta aead_scratch,y
        iny
        dex
        bne @copy_partial
@pad_done:
        ; Set 0x01 after the message bytes (at position n)
        ; This encodes the block as: data + 2^(8*n) per RFC 7539
        lda #$01
        sta aead_scratch,y

        ; Point chacha20poly1305_zp_ptr1 to scratch buffer
        lda #<aead_scratch
        sta chacha20poly1305_zp_ptr1
        lda #>aead_scratch
        sta chacha20poly1305_zp_ptr1+1

        ; Process with high bit = 0 (the 0x01 in the buffer handles it)
        lda #0
        jsr poly1305_block

        lda #0
        sta cc20_remain

@upd_done:
        rts

; =============================================================================
; poly1305_final - Finalize Poly1305 tag
;
; 1. Full reduction of h mod 2^130-5
; 2. h += s
; 3. Output low 16 bytes to poly1305_tag
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_final:
        ; --- Full reduction mod 2^130 - 5 ---
        ; Check if h >= p = 2^130 - 5
        ; Compute h + 5, check if it overflows 2^130
        ; If so, use h + 5 (mod 2^130), otherwise keep h

        ; Add 5 to h, store result in poly_product as temp
        clc
        lda poly_h
        adc #5
        sta poly_product
        ldy #16                ; 16 remaining bytes (indices 1..16)
        ldx #1
@add5:
        lda poly_h,x
        adc #0
        sta poly_product,x
        inx
        dey                    ; DEY doesn't affect carry
        bne @add5

        ; F1 fix (v0.3.0 CT): branchless mask-blend h := (h+5) if h >= p
        ; else h. Build mask = $FF if bit 130 of (h+5) is set, $00 else.
        ; Then blend poly_h[x] = poly_h[x] ^ ((poly_h[x] ^ product[x]) & mask)
        ; for x = 0..15. For the high limb poly_h+16, the same blend applies
        ; but with product+16 pre-masked to #$03 (130-bit clamp); in the no-
        ; reduce path (mask=$00) this leaves poly_h+16 untouched.
        ;
        ; Original reduce branch (`and #$04 / beq @no_reduce`) leaked which
        ; vectors underwent reduction via both execution-time skew and the
        ; taken-vs-not-taken cycle delta (see CT_ANALYSIS.md §2.F1).
        ; Cost: ~200 cy one-shot per tag, unconditional. Negligible.
        lda poly_product+16
        and #$04                ; $04 if bit 130 set, $00 otherwise
        cmp #$01                ; C=1 if A=$04, C=0 if A=$00
        lda #$00
        sbc #$00                ; C=1: 0; C=0: $FF
        eor #$FF                ; bit-set: $FF; bit-clear: $00
        sta poly_tmp            ; mask

        ldx #0
@blend:
        lda poly_h,x
        eor poly_product,x
        and poly_tmp
        eor poly_h,x
        sta poly_h,x
        inx
        cpx #16
        bcc @blend

        ; High limb: blend (product+16 & $03) into poly_h+16 via the same mask.
        lda poly_product+16
        and #$03
        eor poly_h+16
        and poly_tmp
        eor poly_h+16
        sta poly_h+16

        ; --- Add s to h, write tag in same pass ---
        ; Fused finalize: the original code did two separate 16-iter loops
        ; (h+=s then copy h->tag). The output bytes are exactly the result
        ; bytes of (h+s) low 16, so we can store to both poly_h,x and
        ; poly1305_tag,x in one pass. INX and DEY don't touch carry, so the
        ; ADC chain is preserved. Straight-line, constant-time (no new
        ; data-dependent branch). Saves the second loop's overhead
        ; (~177 cy/packet) plus the redundant lda poly_h,x reload.
        clc
        ldy #16                ; 16 bytes
        ldx #0
@add_s_out:
        lda poly_h,x
        adc poly_s,x
        sta poly_h,x
        sta poly1305_tag,x
        inx
        dey                    ; DEY doesn't affect carry
        bne @add_s_out
        rts
