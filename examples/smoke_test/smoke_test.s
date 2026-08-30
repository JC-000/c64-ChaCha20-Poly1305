; =============================================================================
; smoke_test.s — External-consumer smoke test for c64-chacha20poly1305
;
; Simulates a downstream ca65 project (e.g. c64-wireguard, c64-https) that
; has adopted the library and calls its public API from its own main
; program. Consumer-owned end to end: this module, smoke_test.cfg and the
; Makefile are all written from the consumer's side of the API.
;
; What it does:
;   1. Call poly1305_lib_init       (one-time sqtab build on Profile B)
;   2. Load RFC 7539 §2.8.2 AEAD test vector into aead_* state
;   3. Poison aead_tag and poly1305_tag with $EE, then call aead_encrypt
;   4. Byte-compare (ciphertext, aead_tag, poly1305_tag) against RFC
;      known answers
;   5. Call aead_decrypt on the produced ciphertext+tag (in place), with
;      NO tag reload — aead_tag already holds what aead_encrypt published
;   6. Check return A == 0 (tag valid) AND decrypted plaintext matches input
;   7. Write a status byte to screen RAM ($0400) and spin:
;        $01 success
;        $80 aead_encrypt ciphertext mismatch
;        $81 aead_encrypt aead_tag mismatch
;        $82 aead_decrypt returned nonzero (tag-verify failure)
;        $83 aead_decrypt plaintext mismatch
;        $84 aead_encrypt poly1305_tag mismatch
;
; A Python harness driver (run_smoke_test.py) boots this PRG in VICE, waits
; for the status byte, and reports pass/fail. The status byte alone is the
; oracle — the program otherwise never touches BASIC, KERNAL, or the VIC-II,
; which keeps the consumer's view of the library deliberately thin.
;
; -----------------------------------------------------------------------------
; WHICH LIBRARY THIS BUILDS AGAINST
;
; The repository's own src/ tree — the CURRENT library. This example
; previously built a frozen snapshot under
; third_party/c64-chacha20poly1305-v0.3.0/, which documents `aead_tag` as
; aead_encrypt's output (its data_lib.s exports it; its
; chacha20poly1305_lib.s header calls it "authentication tag" under
; Output:) but contains no `sta aead_tag` anywhere — only the verify-side
; `eor aead_tag,x`. An example pinned to that snapshot could only report
; PASS by asserting on something other than the documented output, which
; makes it a worked example of how NOT to validate a library. The snapshot
; is kept for reference (see its ORIGIN.txt) and is no longer built.
;
; -----------------------------------------------------------------------------
; TAG HANDLING
;
; Both tag buffers are poisoned with $EE before aead_encrypt, so neither
; assertion can pass on a value the library never wrote. `aead_tag` — the
; ABI's documented encrypt output — is the primary assertion; `poly1305_tag`
; is asserted separately as the Poly1305 module's own output buffer, not as
; a stand-in for aead_tag. aead_decrypt is then called with no tag reload,
; so it must consume exactly the tag aead_encrypt published. The RFC
; fixture is never copied into aead_tag: doing so would let the decrypt leg
; pass even if aead_encrypt produced no tag at all.
; =============================================================================

        .p02

; --- Pull in the library's constants (profile flags, and one .importzp
;     per ZP slot). The consumer's build line adds ../../src/lib to the
;     ca65 -I path so this resolves into the library sources; the ZP slots
;     themselves are defined by ../../src/zp_config.s, which this example
;     assembles as one of its own objects (contract §6.2). ---
.include "constants_lib.s"

; --- §6.7 image guard -------------------------------------------------------
; The library places its tables by *equate*, not by segment: sqtab at
; LIB_SHARED_SQTAB_BASE ($8000 default, Profile B) and the Shoup
; r_tab_lo/hi at $6000/$7000 (Profile A). MAIN spans $0900-$9FFF and so
; contains both windows, which ld65 knows nothing about — a growing image
; would be linked straight across a table, with no error at any stage and
; silent corruption at runtime. src/main.s carries this guard for the
; library's own PRG and states that consumers must mirror it against their
; own `__<AREA>_LAST__`; this is that mirror.
;
; __MAIN_LAST__ must stay a hard .import: an lderror assert whose operand
; is missing degrades to "Warning: Cannot evaluate assertion", i.e. a
; silent no-op. The unresolved external is what keeps the guard honest.
; It is published by `define = yes` on MAIN in smoke_test.cfg.
.import __MAIN_LAST__
.ifdef POLY1305_PROFILE_LONG
    .assert __MAIN_LAST__ <= r_tab_lo, lderror, "image overruns the Profile A Shoup table window (r_tab_lo) — shrink the image"
.else
    .include "sqtab_base.inc"
    .assert __MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE, lderror, "image overruns the sqtab window (LIB_SHARED_SQTAB_BASE) — relocate the table with -D LIB_SHARED_SQTAB_BASE=0x<addr> or shrink the image"
.endif

; --- Library imports (data + entry points). ---
.import poly1305_lib_init
.import aead_encrypt, aead_decrypt
.import aead_key, aead_nonce, aead_aad_ptr, aead_aad_len
.import aead_data_ptr, aead_data_len, aead_tag, poly1305_tag

; =============================================================================
; Load address + BASIC stub
; =============================================================================
.segment "LOADADDR"
        .word $0801

.segment "BASICSTUB"
        ; 10 SYS 2304
        .byte $0c, $08, $0a, $00, $9e, $20, $32, $33, $30, $34, $00, $00, $00

; =============================================================================
; Main program — entry at $0900 (the first byte of the CODE segment, which
; ld65 aligns to $0100 and which the linker config starts at $0900).
; =============================================================================
.segment "CODE"

.export smoke_main
smoke_main:
        sei                     ; IRQs off — we don't want KERNAL IRQ prodding
                                ; ZP while we're testing

        ; --- 1. One-time library init -------------------------------------
        jsr poly1305_lib_init

        ; --- 2. Load test vector into library state -----------------------
        ; Key: 32 bytes
        ldx #31
@copy_key:
        lda rfc_key,x
        sta aead_key,x
        dex
        bpl @copy_key

        ; Nonce: 12 bytes
        ldx #11
@copy_nonce:
        lda rfc_nonce,x
        sta aead_nonce,x
        dex
        bpl @copy_nonce

        ; AAD: 12 bytes, library reads via aead_aad_ptr
        lda #<rfc_aad
        sta aead_aad_ptr
        lda #>rfc_aad
        sta aead_aad_ptr+1
        lda #12
        sta aead_aad_len

        ; Plaintext: copy 114 bytes into work buffer so aead_encrypt can
        ; modify it in place. The buffer lives at $C000 (free C64 RAM,
        ; clear of KERNAL/BASIC, library tables, and the PRG image).
        ldx #0
@copy_pt:
        lda rfc_plaintext,x
        sta work_buf,x
        inx
        cpx #114
        bne @copy_pt

        lda #<work_buf
        sta aead_data_ptr
        lda #>work_buf
        sta aead_data_ptr+1
        lda #114                ; data_len low
        sta aead_data_len
        lda #0                  ; data_len high
        sta aead_data_len+1

        ; --- 3. Encrypt ----------------------------------------------------
        ; Poison both tag buffers so neither assertion below can pass on a
        ; value the library never wrote.
        lda #$ee
        ldx #15
@poison_tag:
        sta poly1305_tag,x
        sta aead_tag,x
        dex
        bpl @poison_tag

        jsr aead_encrypt

        ; --- 4a. Compare ciphertext (work_buf) against rfc_expected_ct ----
        ldx #0
@cmp_ct:
        lda work_buf,x
        cmp rfc_expected_ct,x
        bne ct_fail
        inx
        cpx #114
        bne @cmp_ct

        ; --- 4b. Compare aead_tag against rfc_expected_tag ----------------
        ; aead_tag is the ABI's documented encrypt output. It was poisoned
        ; to $EE above, so this fails if aead_encrypt did not publish it.
        ldx #15
@cmp_tag:
        lda aead_tag,x
        cmp rfc_expected_tag,x
        bne tag_fail
        dex
        bpl @cmp_tag

        ; --- 4c. Compare poly1305_tag against rfc_expected_tag ------------
        ; The Poly1305 module's own output buffer, asserted separately —
        ; not as a stand-in for aead_tag.
        ldx #15
@cmp_poly_tag:
        lda poly1305_tag,x
        cmp rfc_expected_tag,x
        bne poly_tag_fail
        dex
        bpl @cmp_poly_tag

        ; --- 5. Decrypt in place -----------------------------------------
        ; work_buf still holds the ciphertext, and aead_tag still holds the
        ; tag aead_encrypt published — which is exactly the value
        ; aead_decrypt must verify against, so there is no tag reload here.
        ; Copying rfc_expected_tag in would let this leg pass even if
        ; aead_encrypt had produced no tag at all.
        ;
        ; aead_data_ptr / aead_data_len / aead_key / aead_nonce / aead_aad_*
        ; are still set from the encrypt call — no reload needed there
        ; either.
        jsr aead_decrypt
        cmp #0
        bne decrypt_auth_fail

        ; --- 6. Compare decrypted plaintext against original vector ------
        ldx #0
@cmp_pt:
        lda work_buf,x
        cmp rfc_plaintext,x
        bne decrypt_pt_fail
        inx
        cpx #114
        bne @cmp_pt

        ; --- 7. Success ---------------------------------------------------
        lda #$01
        sta $0400               ; screen RAM[0] = 1 → harness sees PASS
        jmp spin

ct_fail:
        lda #$80
        sta $0400
        jmp spin

tag_fail:
        lda #$81
        sta $0400
        jmp spin

decrypt_auth_fail:
        lda #$82
        sta $0400
        jmp spin

decrypt_pt_fail:
        lda #$83
        sta $0400
        jmp spin

poly_tag_fail:
        lda #$84
        sta $0400
        jmp spin

; Distinct spin address so the harness could also set a breakpoint if
; it wanted to (we rely on the status byte instead).
.export smoke_done
smoke_done:
spin:   jmp spin

; =============================================================================
; RFC 7539 §2.8.2 test vector — the bit-exact known answer every RFC 8439
; implementation must produce. Taken from RFC 7539 §2.8.2 and mirrored in
; test/rfc7539_vectors.json in the upstream library.
; =============================================================================
rfc_key:
        .byte $80, $81, $82, $83, $84, $85, $86, $87
        .byte $88, $89, $8a, $8b, $8c, $8d, $8e, $8f
        .byte $90, $91, $92, $93, $94, $95, $96, $97
        .byte $98, $99, $9a, $9b, $9c, $9d, $9e, $9f

rfc_nonce:
        .byte $07, $00, $00, $00, $40, $41, $42, $43
        .byte $44, $45, $46, $47

rfc_aad:
        .byte $50, $51, $52, $53, $c0, $c1, $c2, $c3
        .byte $c4, $c5, $c6, $c7

; 114-byte plaintext: "Ladies and Gentlemen of the class of '99: If I
; could offer you only one tip for the future, sunscreen would be it."
rfc_plaintext:
        .byte $4c, $61, $64, $69, $65, $73, $20, $61
        .byte $6e, $64, $20, $47, $65, $6e, $74, $6c
        .byte $65, $6d, $65, $6e, $20, $6f, $66, $20
        .byte $74, $68, $65, $20, $63, $6c, $61, $73
        .byte $73, $20, $6f, $66, $20, $27, $39, $39
        .byte $3a, $20, $49, $66, $20, $49, $20, $63
        .byte $6f, $75, $6c, $64, $20, $6f, $66, $66
        .byte $65, $72, $20, $79, $6f, $75, $20, $6f
        .byte $6e, $6c, $79, $20, $6f, $6e, $65, $20
        .byte $74, $69, $70, $20, $66, $6f, $72, $20
        .byte $74, $68, $65, $20, $66, $75, $74, $75
        .byte $72, $65, $2c, $20, $73, $75, $6e, $73
        .byte $63, $72, $65, $65, $6e, $20, $77, $6f
        .byte $75, $6c, $64, $20, $62, $65, $20, $69
        .byte $74, $2e

; 114-byte expected ciphertext (RFC 7539 §2.8.2)
rfc_expected_ct:
        .byte $d3, $1a, $8d, $34, $64, $8e, $60, $db
        .byte $7b, $86, $af, $bc, $53, $ef, $7e, $c2
        .byte $a4, $ad, $ed, $51, $29, $6e, $08, $fe
        .byte $a9, $e2, $b5, $a7, $36, $ee, $62, $d6
        .byte $3d, $be, $a4, $5e, $8c, $a9, $67, $12
        .byte $82, $fa, $fb, $69, $da, $92, $72, $8b
        .byte $1a, $71, $de, $0a, $9e, $06, $0b, $29
        .byte $05, $d6, $a5, $b6, $7e, $cd, $3b, $36
        .byte $92, $dd, $bd, $7f, $2d, $77, $8b, $8c
        .byte $98, $03, $ae, $e3, $28, $09, $1b, $58
        .byte $fa, $b3, $24, $e4, $fa, $d6, $75, $94
        .byte $55, $85, $80, $8b, $48, $31, $d7, $bc
        .byte $3f, $f4, $de, $f0, $8e, $4b, $7a, $9d
        .byte $e5, $76, $d2, $65, $86, $ce, $c6, $4b
        .byte $61, $16

; 16-byte expected Poly1305 tag (RFC 7539 §2.8.2)
rfc_expected_tag:
        .byte $1a, $e1, $0b, $59, $4f, $09, $e2, $6a
        .byte $7e, $90, $2e, $cb, $d0, $60, $06, $91

; =============================================================================
; Consumer-owned scratch buffer. $C000-$C071 sits in free C64 RAM — clear of
; BASIC ($0800), KERNAL ($E000), the library's code+data (MAIN area,
; $0900-$9FFF in this cfg but only occupied up to the BSS tail), the Shoup
; tables ($6000-$7FFF, Profile A only) and sqtab ($8000-$83FF, Profile B
; only). A real consumer would similarly carve out its own buffer; see
; docs/MEMORY_MAP.md §4 for the full list of addresses to avoid.
; =============================================================================
work_buf        = $C000
