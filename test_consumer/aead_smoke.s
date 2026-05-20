; =============================================================================
; aead_smoke.s — Self-running smoke test for the aead-only archive variant.
;
; Mirrors examples/smoke_test/smoke_test.s exactly but is linked against
; build/lib/c64-chacha20-poly1305-aead-only.a (or the full archive) via the
; test_consumer/Makefile. RFC 7539 §2.8.2 known answer; writes a status byte
; to $0400 so a Python harness can read pass/fail.
;
; Status protocol:
;   $01 PASS
;   $80 aead_encrypt ciphertext mismatch
;   $81 aead_encrypt Poly1305 tag mismatch
;   $82 aead_decrypt auth-verify returned nonzero
;   $83 aead_decrypt plaintext mismatch
; =============================================================================

        .p02

.import poly1305_lib_init
.import aead_encrypt, aead_decrypt
.import aead_key, aead_nonce, aead_aad_ptr, aead_aad_len
.import aead_data_ptr, aead_data_len, aead_tag, poly1305_tag

; --- Load address ---
.segment "LOADADDR"
        .word $0801

; --- BASIC stub: 10 SYS 2304 ---
.segment "BASICSTUB"
        .byte $0c, $08, $0a, $00, $9e, $20, $32, $33, $30, $34, $00, $00, $00

.segment "CODE"

.export smoke_main
smoke_main:
        sei

        jsr poly1305_lib_init

        ldx #31
@copy_key:
        lda rfc_key,x
        sta aead_key,x
        dex
        bpl @copy_key

        ldx #11
@copy_nonce:
        lda rfc_nonce,x
        sta aead_nonce,x
        dex
        bpl @copy_nonce

        lda #<rfc_aad
        sta aead_aad_ptr
        lda #>rfc_aad
        sta aead_aad_ptr+1
        lda #12
        sta aead_aad_len

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
        lda #114
        sta aead_data_len
        lda #0
        sta aead_data_len+1

        jsr aead_encrypt

        ldx #0
@cmp_ct:
        lda work_buf,x
        cmp rfc_expected_ct,x
        bne ct_fail
        inx
        cpx #114
        bne @cmp_ct

        ldx #15
@cmp_tag:
        lda poly1305_tag,x
        cmp rfc_expected_tag,x
        bne tag_fail
        dex
        bpl @cmp_tag

        ldx #15
@load_tag:
        lda rfc_expected_tag,x
        sta aead_tag,x
        dex
        bpl @load_tag

        jsr aead_decrypt
        cmp #0
        bne decrypt_auth_fail

        ldx #0
@cmp_pt:
        lda work_buf,x
        cmp rfc_plaintext,x
        bne decrypt_pt_fail
        inx
        cpx #114
        bne @cmp_pt

        lda #$01
        sta $0400
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

spin:   jmp spin

; RFC 7539 §2.8.2 known answer.
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
rfc_expected_tag:
        .byte $1a, $e1, $0b, $59, $4f, $09, $e2, $6a
        .byte $7e, $90, $2e, $cb, $d0, $60, $06, $91

work_buf        = $C000
