; =============================================================================
; lib/poly1305_ripple.s - poly_ripple, the multi-precision carry propagator
;
; ONE ROUTINE, AND IT IS ITS OWN TU FOR A PURELY MECHANICAL REASON — read
; this before merging it back into poly1305_core.s.
;
; ld65 aligns each object's contribution to a segment (its "section") to
; that section's own alignment, which ca65 sets to the widest `.align`
; anywhere inside it. `poly1305_core.s` contains `.align 256` for
; `poly_reduce_shl6_tab` (a CT invariant — see the note there), so
; poly1305_core.o's section starts on a page boundary. In v0.10.0's single
; poly1305_lib.s, `poly_ripple` sat between the §8.3 ct_mul_8x8 body and
; that aligned table INSIDE one section, at $1C8B on Profile B — not on a
; page boundary. Leaving it in poly1305_core.s would push it to the page
; and move every byte after it.
;
; So the issue #108 split puts it here, unaligned, between shared_ct_mul.o
; and poly1305_core.o, which reproduces the v0.10.0 image exactly: all four
; profile PRGs are byte-identical to the release.
;
; Nothing here is displaceable; this file is not a §6.1 isolation TU. It is
; the seam that makes the isolation TUs byte-neutral.
;
; DO NOT REORDER: this TU sits between shared_ct_mul.o and poly1305_core.o
; on every link line. See poly1305_lib.s's header for the full order.
; =============================================================================

.include "constants_lib.s"

.import poly_product

.export poly_ripple

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)

; =============================================================================
; poly_ripple - propagate a set carry upward through poly_product starting
; at index X. Entered only when the just-completed add left carry set.
;
; Uses INC/BNE instead of SEC/ADC#0 — ripple stops as soon as a byte doesn't
; wrap to zero. Bounded by poly_product size (33 bytes, indices 0..32).
;
; Note on constant-time: the ripple loop branches on carry (INC's Z flag),
; which is a function of hardware flags after an addition. This is
; standard for multi-precision arithmetic on 6502 and is *not* a CT
; violation — the CT contract is "no branches on secret operand bytes
; directly". The early-exits removed from poly1305_multiply (beq on
; h[i] / r[j]) were such violations; carry-out branches are not.
;
; Clobbers: A, X
; =============================================================================
poly_ripple:
@loop:
        cpx #33
        bcs @done
        inc poly_product,x
        bne @done              ; carry absorbed
        inx
        bne @loop              ; always taken (X never wraps before bounds hit)
@done:
        rts

