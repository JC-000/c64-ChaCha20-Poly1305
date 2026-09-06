; =============================================================================
; lib/shared_prod_scratch.s - c64-lib-contract SPEC §8.3 product scratch
;
; `poly_prod_lo` / `poly_prod_hi` are two of the five names SPEC §8.3 names
; as the provider surface ("the product scratch"), and they are displaced
; together with the rest of that surface by `-D SHARED_CT_MUL_8X8=1`.
;
; They are a separate TU from shared_ct_mul.s for one reason only, and it is
; a mechanical one: in v0.10.0's single poly1305_lib.s these two bytes are
; emitted BEFORE the legacy `mul_8x8` body and the ct_mul_8x8 body comes
; AFTER it. Isolating `mul_8x8` (see mul_8x8_legacy.s for why that is the
; one isolation with a measurable consumer-visible effect) therefore forces
; a three-way split of the §8.3 region if the emitted byte order — and with
; it the byte-identical profile PRGs — is to be preserved. Merging this file
; into shared_ct_mul.s would move `mul_8x8` in the image.
;
; Isolation-wise the split is free: every name here is displaceable, so this
; member can never drag a non-displaceable import into a consumer's link.
; A consumer or sibling that owns §8.3 supplies all five names per §8.3's
; provider surface, in which case neither this member nor shared_ct_mul.o is
; ever pulled.
;
; DO NOT REORDER: this TU sits between shared_sqtab_init.o and
; mul_8x8_legacy.o on every link line. See poly1305_lib.s's header.
; =============================================================================

.setcpu "6502"

.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_CT_MUL_8X8
.export poly_prod_lo, poly_prod_hi
.endif
.endif

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)

.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_CT_MUL_8X8
; 16-bit result of mul_8x8 / ct_mul_8x8. SPEC §8.3 provider surface.
poly_prod_lo:   .byte 0
poly_prod_hi:   .byte 0
.endif
.endif
