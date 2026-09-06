; =============================================================================
; lib/mul_8x8_legacy.s - SPEC §8.3 back-compat `mul_8x8` body
;
; THIS IS THE ONE ISOLATION IN ISSUE #108 ITEM 2 WITH A MEASURABLE
; CONSUMER-VISIBLE EFFECT, and it is worth saying exactly why, because the
; other splits in this set are conformance for its own sake.
;
; ld65 pulls an archive member only to satisfy a reference. Of the eight
; §8.1/§8.3 names this library displaces, SEVEN are referenced by the
; library's own code (poly1305_lib.o calls mul_tables_init; poly1305_core.o
; calls ct_mul_8x8 and reads poly_prod_lo/hi and the two SMC sites), so
; their members are pulled whatever the member layout is, and only the
; deferral switches can keep them out of a link.
;
; `mul_8x8` is the exception: NOTHING inside this library references it.
; It is the pre-v0.3.0 multiplier, replaced on every hot path by the
; constant-time `ct_mul_8x8`, and kept exported solely because the Python
; test harness jsr()s into it (hence the LIB_VARIANT_AEAD_ONLY gate below —
; the trimmed archive does not export it). While it rode inside
; poly1305_lib.o it reached every consumer link that touched Poly1305 at
; all: dead code the consumer pays for, and an exported bare name that
; collides with the identical `mul_8x8` a sibling §8.3 adopter exports.
; That is §6.1's "the member arrives uninvited" in the literal.
;
; In its own TU it is pulled only if a CONSUMER references it. A consumer
; that does not — which is every consumer of the AEAD ABI — links neither
; the body nor the name.
;
; The body is unchanged, and it stays gated on `SHARED_CT_MUL_8X8`: it is
; part of the §8.3 surface this library either owns or defers, and
; c64-x25519 exports the same name (issue #47).
;
; DO NOT REORDER: this TU sits between shared_prod_scratch.o and
; shared_ct_mul.o on every link line. See poly1305_lib.s's header.
; =============================================================================

.setcpu "6502"

.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_CT_MUL_8X8
.ifndef LIB_VARIANT_AEAD_ONLY
.export mul_8x8
.endif
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

; =============================================================================
; mul_8x8 - 8-bit x 8-bit → 16-bit multiply using quarter-square table
;
; Input: A = multiplicand, X = multiplier
; Output: poly_prod_lo/hi = A * X (16-bit result)
;
; Uses identity: a*b = sqtab[a+b] - sqtab[|a-b|]
; Clobbers: A, X, Y
; =============================================================================
mul_8x8:
        sta mul_a               ; save A
        stx mul_b               ; save X

        ; Compute sum = a + b
        clc
        adc mul_b               ; A = a + b (low byte)
        tax                     ; X = sum low byte
        lda #0
        adc #0                  ; carry → sum page (0 or 1)
        sta mul_s_pg            ; sum page

        ; Compute |a - b|
        lda mul_a
        sec
        sbc mul_b
        bcs :+
        eor #$ff
        adc #1                  ; negate (carry was clear, so ADC adds 1)
:       tay                     ; Y = |a-b| (always page 0, ≤255)

        ; sqtab[sum] - sqtab[|diff|]
        lda mul_s_pg
        beq @s0
        ; sum is in page 1 (256..510)
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
@s0:
        ; sum is in page 0 (0..255)
        lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts

mul_a:          .byte 0
mul_b:          .byte 0
mul_s_pg:       .byte 0
.endif          ; .ifndef SHARED_CT_MUL_8X8
.endif          ; .ifndef POLY1305_PROFILE_LONG (issue #34 F1)
