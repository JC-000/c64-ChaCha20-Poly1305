; =============================================================================
; chacha20_compact.inc - size-first ChaCha20 core (LIB_VARIANT_COMPACT)
;
; Assembled in place of the unrolled core by src/lib/chacha20_lib.s when
; LIB_VARIANT_COMPACT is defined; never assembled on its own. Same entry
; points, same state layout, same ZP slots and the same keystream contract
; (cc20_keystream aliases cc20_work) as the default core, so the AEAD
; wrapper and every caller are unchanged.
;
; What is different is the shape. The default core inlines all 8 quarter-
; rounds of a double round against literal ZP addresses (~3.3 KB) and
; rotates by 4 through two page-aligned 256-byte LUTs (512 B). Here one
; quarter-round routine is called 80 times per block, its four steps are
; one rolled loop, and every rotation is composed from two primitives that
; touch no table: rotate left by one byte and rotate right by one bit.
;
;   rotl 16 = 2 byte-rotations
;   rotl 12 = 2 byte-rotations, then rotr 4 bits
;   rotl  8 = 1 byte-rotation
;   rotl  7 = 1 byte-rotation,  then rotr 1 bit
;
; CONSTANT TIME. Every branch below is on a loop counter or on a schedule
; constant (the QR index table, the per-step rotation counts) — never on
; key, nonce, counter-derived state or keystream bytes. There is no table
; indexed by secret data, so this core needs no page-alignment invariant:
; the X/Y indices into cc20_work are word offsets from cc20_qr_table, which
; are public. `adc/eor cc20_work+I,y` assembles as abs,y (there is no zp,y
; form of either); the base is a zero-page address and Y <= 63, so with
; cc20_work's 64 bytes inside page zero the access never crosses a page.
; The `.assert` below makes that a build error rather than an assumption.
;
; ZP: cc20_work, cc20_round, cc20_qr_idx, cc20_data_ptr, cc20_remain,
; cc20_buf_pos (as the default core) plus chacha20poly1305_zp_tmp1/_tmp2 as
; the step counter / step base. RAM: cc20_qr_off (6 B, data_lib.s).
; =============================================================================

.import cc20_qr_off

qr_k = chacha20poly1305_zp_tmp1         ; step 0..3 within a quarter-round
qr_m = chacha20poly1305_zp_tmp2         ; 0 on even steps, 2 on odd steps

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)

; --- ChaCha20 constants ("expand 32-byte k" as LE uint32 words) ---
cc20_constants:
        .byte $65, $78, $70, $61     ; 0x61707865 "expa" (LE)
        .byte $6e, $64, $20, $33     ; 0x3320646e "nd 3" (LE)
        .byte $32, $2d, $62, $79     ; 0x79622d32 "2-by" (LE)
        .byte $74, $65, $20, $6b     ; 0x6b206574 "te k" (LE)

; --- Quarter-round index table: word indices (a, b, c, d) ---
; Unlike the default core, chacha20_block DOES read this table, so treat it
; as read-only. The test suite drives chacha20_quarter_round through the
; shipped row 0 (QR 0,4,8,12) and checks the row is unchanged afterwards.
cc20_qr_table:
        .byte  0,  4,  8, 12          ; column rounds
        .byte  1,  5,  9, 13
        .byte  2,  6, 10, 14
        .byte  3,  7, 11, 15
        .byte  0,  5, 10, 15          ; diagonal rounds
        .byte  1,  6, 11, 12
        .byte  2,  7,  8, 13
        .byte  3,  4,  9, 14

; Per-step rotation as (byte-rotations left, bit-rotations right).
qr_rot_bytes:   .byte 2, 2, 1, 1
qr_rot_bits:    .byte 0, 4, 0, 1

; =============================================================================
; chacha20_quarter_round - one QR on cc20_work
;
; Input: cc20_qr_idx = byte offset of a row of cc20_qr_table (0, 4, .. 28).
;
; The four RFC 8439 steps
;     a += b; d ^= a; d <<<= 16
;     c += d; b ^= c; b <<<= 12
;     a += b; d ^= a; d <<<= 8
;     c += d; b ^= c; b <<<= 7
; are all  p += q; s ^= p; s <<<= n  over (p,q,s) = (a,b,d) then (c,d,b).
; With the offsets laid out as a,b,c,d,a,b the step at base m is
; (off[m], off[m+1], off[m+3]) for m = 0,2,0,2, so one loop body serves
; all four.
;
; Clobbers: A, X, Y
; =============================================================================
chacha20_quarter_round:
        ldx cc20_qr_idx
        ldy #0
@load:  lda cc20_qr_table,x
        asl
        asl                     ; word index -> byte offset
        sta cc20_qr_off,y
        inx
        iny
        cpy #4
        bne @load
        lda cc20_qr_off
        sta cc20_qr_off+4       ; off[4] = a
        lda cc20_qr_off+1
        sta cc20_qr_off+5       ; off[5] = b

        ldy #0
@step:  sty qr_k
        tya
        and #1
        asl
        sta qr_m                ; m = 0 / 2
        tax
        lda cc20_qr_off+1,x
        tay                     ; Y = q
        lda cc20_qr_off,x
        tax                     ; X = p

        ; --- p += q ---
        clc
        .repeat 4, I
            lda cc20_work+I,x
            adc cc20_work+I,y
            sta cc20_work+I,x
        .endrepeat

        ; --- s ^= p ---
        txa
        tay                     ; Y = p
        ldx qr_m
        lda cc20_qr_off+3,x
        tax                     ; X = s
        .repeat 4, I
            lda cc20_work+I,x
            eor cc20_work+I,y
            sta cc20_work+I,x
        .endrepeat

        ; --- s <<<= n: whole-byte rotations left ... ---
        ldy qr_k
        lda qr_rot_bytes,y
        tay
@rotb:  lda cc20_work+3,x
        pha
        lda cc20_work+2,x
        sta cc20_work+3,x
        lda cc20_work+1,x
        sta cc20_work+2,x
        lda cc20_work,x
        sta cc20_work+1,x
        pla
        sta cc20_work,x
        dey
        bne @rotb

        ; --- ... then single-bit rotations right (count 0, 1 or 4) ---
        ldy qr_k
        lda qr_rot_bits,y
        beq @next               ; schedule constant, not data
        tay
@rotr:  lda cc20_work,x
        lsr                     ; C = bit 0 of the word
        ror cc20_work+3,x
        ror cc20_work+2,x
        ror cc20_work+1,x
        ror cc20_work,x
        dey
        bne @rotr

@next:  ldy qr_k
        iny
        cpy #4
        beq @qr_done
        jmp @step               ; body is past BNE range
@qr_done:
        rts

; Both abs,y operands above index from cc20_work with Y <= 63. Keep the
; whole working state inside page zero so none of them can cross a page.
.assert cc20_work + 63 <= $FF, error, "compact ChaCha20 core: cc20_work must lie wholly in zero page"

; =============================================================================
; chacha20_init - Initialize ChaCha20 state
;
; Reads key from cc20_key (32 bytes) and nonce from cc20_nonce (12 bytes).
; Sets counter from cc20_counter (4 bytes).
;
; Clobbers: A, X, Y
; =============================================================================
chacha20_init:
        ldx #15
@const: lda cc20_constants,x
        sta cc20_state,x
        dex
        bpl @const
        ldx #31
@key:   lda cc20_key,x
        sta cc20_state+16,x
        dex
        bpl @key
        ldx #3
@ctr:   lda cc20_counter,x
        sta cc20_state+48,x
        dex
        bpl @ctr
        ldx #11
@nonce: lda cc20_nonce,x
        sta cc20_state+52,x
        dex
        bpl @nonce
        rts

; =============================================================================
; chacha20_block - Generate one 64-byte keystream block into cc20_keystream
;
; 1. Copy state -> work
; 2. 10 double-rounds of 8 table-driven quarter-rounds
; 3. Add initial state back
; 4. Increment the block counter in state
;
; Clobbers: A, X, Y
; =============================================================================
chacha20_block:
        ldx #63
@copy:  lda cc20_state,x
        sta cc20_work,x
        dex
        bpl @copy

        lda #10
        sta cc20_round
@dround:
        lda #0
@qr:    sta cc20_qr_idx
        jsr chacha20_quarter_round
        lda cc20_qr_idx
        clc
        adc #4
        cmp #32
        bne @qr
        dec cc20_round
        bne @dround

        ; work[w] += state[w] for 16 words. The carry chain restarts at
        ; each word boundary; CPX clobbers C, so it runs only after a
        ; word's four ADCs are done.
        ldx #0
@word:  clc
        ldy #4
@byte:  lda cc20_work,x
        adc cc20_state,x
        sta cc20_work,x
        inx
        dey
        bne @byte
        cpx #64
        bne @word

        ; Counter increment (word 12). The counter is public — it is the
        ; RFC 8439 block number — so the early-out is not a CT leak; the
        ; default core uses the same chain.
        inc cc20_state+48
        bne @done
        inc cc20_state+49
        bne @done
        inc cc20_state+50
        bne @done
        inc cc20_state+51
@done:  rts

; =============================================================================
; chacha20_encrypt - XOR the keystream into (cc20_data_ptr) in place
;
; Inputs:
;   cc20_data_ptr = pointer to plaintext/ciphertext
;   cc20_remain / cc20_remain_hi = 16-bit byte count
;   State must already be initialized via chacha20_init
;
; Identical to the default core's routine; the branches are on the public
; length only.
; =============================================================================
chacha20_encrypt:
        lda cc20_remain
        ora cc20_remain_hi
        beq @enc_done

@next_block:
        jsr chacha20_block
        lda cc20_remain_hi
        bne @full
        lda cc20_remain
        cmp #64
        bcc @partial
@full:  lda #64
@partial:
        tax                     ; X = count
        ldy #0
@xor:   lda (cc20_data_ptr),y
        eor cc20_keystream,y
        sta (cc20_data_ptr),y
        iny
        dex
        bne @xor

        tya                     ; Y = count
        clc
        adc cc20_data_ptr
        sta cc20_data_ptr
        lda cc20_data_ptr+1
        adc #0
        sta cc20_data_ptr+1

        sty cc20_buf_pos
        lda cc20_remain
        sec
        sbc cc20_buf_pos
        sta cc20_remain
        lda cc20_remain_hi
        sbc #0
        sta cc20_remain_hi
        ora cc20_remain
        bne @next_block

@enc_done:
        rts
