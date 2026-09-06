; =============================================================================
; app_owned_consumer.s — SPEC §8.0 APP_OWNED consumer, linked against the
; DEFAULT archive.
;
; This is the configuration c64-lib-contract SPEC §6.1 member isolation is
; written for: a consumer that provides the §8.1 / §8.3 shared primitives
; from its own modules and links the library's shipped default archive
; without rebuilding it and without passing any deferral define.
;
; The consumer's object is on the ld65 command line, so its definitions are
; in the symbol table before any archive is scanned. If the library's
; displaceable names are ISOLATED, the library's own imports resolve against
; the consumer and the library's members are never pulled. If they share a
; member with an entry point the consumer imports, that member arrives
; uninvited and ld65 reports a duplicate.
;
; Bodies are link-only stubs — this PRG is never executed.
; =============================================================================

        .p02

.import poly1305_lib_init
.import aead_encrypt, aead_decrypt

; --- the app-owned §8.1 surface -------------------------------------------
.export mul_tables_init, sqtab_init
; --- the app-owned §8.3 surface (SPEC §8.3 "Provider surface") ------------
.export ct_mul_8x8, poly_prod_lo, poly_prod_hi
.export smc_sum_a_imm, smc_diff_a_imm

.segment "CODE"

.export entry
entry:
        jsr poly1305_lib_init
        jsr aead_encrypt
        jsr aead_decrypt
        rts

mul_tables_init:
sqtab_init:
        rts

ct_mul_8x8:
smc_sum_a_imm:
        adc #$00
smc_diff_a_imm:
        sbc #$00
        rts

poly_prod_lo:   .byte 0
poly_prod_hi:   .byte 0
