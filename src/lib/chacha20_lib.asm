; =============================================================================
; chacha20_lib.asm - ChaCha20 stream cipher (RFC 7539/8439)
;
; State layout: 16 x 32-bit words = 64 bytes (little-endian)
;   words[0-3]   = "expand 32-byte k" constants
;   words[4-11]  = 256-bit key
;   word[12]     = 32-bit block counter
;   words[13-15] = 96-bit nonce
;
; Hot path uses ZP-resident cc20_work (64 bytes at $40..$7f), so each
; state word w[i] lives at the *literal* ZP address (cc20_work + 4*i).
; Step 2 inlines all 8 quarter-rounds per double-round against these
; literal ZP addresses — no (w32_dst),y indirection, no JSR inside the QR.
; =============================================================================

; --- ChaCha20 constants ("expand 32-byte k" as LE uint32 words) ---
cc20_constants:
        !byte $65, $78, $70, $61     ; 0x61707865 "expa" (LE)
        !byte $6e, $64, $20, $33     ; 0x3320646e "nd 3" (LE)
        !byte $32, $2d, $62, $79     ; 0x79622d32 "2-by" (LE)
        !byte $74, $65, $20, $6b     ; 0x6b206574 "te k" (LE)

; --- Quarter-round index table (retained for test suite compatibility) ---
; The main chacha20_block hot path no longer uses this table — it inlines
; all 8 quarter-rounds per double-round with literal indices. The table
; and the `chacha20_quarter_round` entry point below are kept so the
; dynamic-index test vector in `tools/test_chacha20_poly1305.py` can still
; patch in arbitrary (a,b,c,d) tuples and exercise a single QR.
cc20_qr_table:
        ; Column rounds
        !byte  0,  4,  8, 12          ; QR(0, 4, 8, 12)
        !byte  1,  5,  9, 13          ; QR(1, 5, 9, 13)
        !byte  2,  6, 10, 14          ; QR(2, 6, 10, 14)
        !byte  3,  7, 11, 15          ; QR(3, 7, 11, 15)
        ; Diagonal rounds
        !byte  0,  5, 10, 15          ; QR(0, 5, 10, 15)
        !byte  1,  6, 11, 12          ; QR(1, 6, 11, 12)
        !byte  2,  7,  8, 13          ; QR(2, 7,  8, 13)
        !byte  3,  4,  9, 14          ; QR(3, 4,  9, 14)

; =============================================================================
; Inlined 32-bit op macros against literal ZP addresses
;
; Each macro takes one or two 4-byte ZP word bases (literal expressions the
; assembler evaluates at build time, e.g. cc20_work+4*0). All addressing is
; direct ZP (3 cy LDA/STA) — no (ptr),y (5 cy).
; =============================================================================

; w[dst] += w[src]  — 32-bit little-endian add-in-place
!macro add32_zp .dst, .src {
        clc
        lda .dst
        adc .src
        sta .dst
        lda .dst+1
        adc .src+1
        sta .dst+1
        lda .dst+2
        adc .src+2
        sta .dst+2
        lda .dst+3
        adc .src+3
        sta .dst+3
}

; w[dst] ^= w[src]  — 32-bit xor-in-place
!macro xor32_zp .dst, .src {
        lda .dst
        eor .src
        sta .dst
        lda .dst+1
        eor .src+1
        sta .dst+1
        lda .dst+2
        eor .src+2
        sta .dst+2
        lda .dst+3
        eor .src+3
        sta .dst+3
}

; w[dst] <<<= 16  — swap halves of LE word: [b0 b1 b2 b3] -> [b2 b3 b0 b1]
; Uses Y as a temp (preserves X). Two independent byte swaps.
!macro rotl32_16_zp .dst {
        lda .dst
        ldy .dst+2
        sty .dst
        sta .dst+2
        lda .dst+1
        ldy .dst+3
        sty .dst+1
        sta .dst+3
}

; w[dst] <<<= 8  — LE byte rotate left by 8: [b0 b1 b2 b3] -> [b3 b0 b1 b2]
; new_b0 = old_b3, new_b1 = old_b0, new_b2 = old_b1, new_b3 = old_b2
!macro rotl32_8_zp .dst {
        ldy .dst+3             ; save b3
        lda .dst+2
        sta .dst+3             ; b3' = b2
        lda .dst+1
        sta .dst+2             ; b2' = b1
        lda .dst
        sta .dst+1             ; b1' = b0
        sty .dst               ; b0' = old b3
}

; w[dst] <<<= 4  — LE nibble rotate left by 4
;   new_b0 = (b0 << 4) | (b3 >> 4)
;   new_b1 = (b1 << 4) | (b0 >> 4)
;   new_b2 = (b2 << 4) | (b1 >> 4)
;   new_b3 = (b3 << 4) | (b2 >> 4)
; We save b3 high nibble (wraps into b0 low), then process b3,b2,b1,b0 in
; that order so each low nibble comes from the *old* value of the previous
; byte. Uses zp_tmp1 as scratch for the wrap.
!macro rotl32_4_zp .dst {
        lda .dst+3
        lsr
        lsr
        lsr
        lsr
        sta zp_tmp1            ; b3 >> 4 (wrap into b0 low)

        lda .dst+3
        asl
        asl
        asl
        asl
        sta .dst+3             ; b3 = b3 << 4 (low nibble will be filled)
        lda .dst+2
        lsr
        lsr
        lsr
        lsr
        ora .dst+3
        sta .dst+3             ; b3 = (b3 << 4) | (b2 >> 4)

        lda .dst+2
        asl
        asl
        asl
        asl
        sta .dst+2
        lda .dst+1
        lsr
        lsr
        lsr
        lsr
        ora .dst+2
        sta .dst+2             ; b2 = (b2 << 4) | (b1 >> 4)

        lda .dst+1
        asl
        asl
        asl
        asl
        sta .dst+1
        lda .dst
        lsr
        lsr
        lsr
        lsr
        ora .dst+1
        sta .dst+1             ; b1 = (b1 << 4) | (b0 >> 4)

        lda .dst
        asl
        asl
        asl
        asl
        ora zp_tmp1
        sta .dst               ; b0 = (b0 << 4) | (b3 >> 4)
}

; w[dst] <<<= 12  — rotl8 then rotl4
!macro rotl32_12_zp .dst {
        +rotl32_8_zp .dst
        +rotl32_4_zp .dst
}

; w[dst] <<<= 1  — 32-bit rotate left by 1 (LE: start from LSB)
; Uses a branchless-ish carry wrap: after 4× rol, carry = old MSB bit.
!macro rotl32_1_zp .dst {
        clc
        lda .dst
        rol
        sta .dst
        lda .dst+1
        rol
        sta .dst+1
        lda .dst+2
        rol
        sta .dst+2
        lda .dst+3
        rol
        sta .dst+3
        bcc +
        lda .dst
        ora #$01
        sta .dst
+
}

; w[dst] <<<= 7  — rotl8 then rotr1. Since rotl8 is free-ish, we do
; rotl8 then rotate right by 1 to get a net <<< 7.
!macro rotr32_1_zp .dst {
        clc
        lda .dst+3
        ror
        sta .dst+3
        lda .dst+2
        ror
        sta .dst+2
        lda .dst+1
        ror
        sta .dst+1
        lda .dst
        ror
        sta .dst
        bcc +
        lda .dst+3
        ora #$80
        sta .dst+3
+
}

!macro rotl32_7_zp .dst {
        +rotl32_8_zp .dst
        +rotr32_1_zp .dst
}

; =============================================================================
; Quarter-round macro
;
; QR(a, b, c, d) where a,b,c,d are word *indices* (0..15). The macro
; expands to the 4 op groups with all 32-bit ops inlined against literal
; ZP addresses (cc20_work + 4*i).
;
;   a += b; d ^= a; d <<<= 16
;   c += d; b ^= c; b <<<= 12
;   a += b; d ^= a; d <<<= 8
;   c += d; b ^= c; b <<<= 7
; =============================================================================
!macro cc20_qr .ia, .ib, .ic, .id {
        +add32_zp    cc20_work+4*.ia, cc20_work+4*.ib
        +xor32_zp    cc20_work+4*.id, cc20_work+4*.ia
        +rotl32_16_zp cc20_work+4*.id

        +add32_zp    cc20_work+4*.ic, cc20_work+4*.id
        +xor32_zp    cc20_work+4*.ib, cc20_work+4*.ic
        +rotl32_12_zp cc20_work+4*.ib

        +add32_zp    cc20_work+4*.ia, cc20_work+4*.ib
        +xor32_zp    cc20_work+4*.id, cc20_work+4*.ia
        +rotl32_8_zp cc20_work+4*.id

        +add32_zp    cc20_work+4*.ic, cc20_work+4*.id
        +xor32_zp    cc20_work+4*.ib, cc20_work+4*.ic
        +rotl32_7_zp cc20_work+4*.ib
}

; =============================================================================
; chacha20_quarter_round - Perform one quarter-round on cc20_work
;
; *** Test-only entry point. Not used by chacha20_block. ***
;
; Input: cc20_qr_idx = index into cc20_qr_table (0, 4, 8, ... 28)
;        pointing to 4 byte indices (a, b, c, d).
;
; This is the original (slow) JSR-driven implementation retained so
; the `test_chacha20_quarter_round` vector can patch cc20_qr_table with
; arbitrary (a,b,c,d) tuples and exercise a single QR. chacha20_block
; itself uses the inlined +cc20_qr macro above — no table lookups, no
; JSR — for speed.
; =============================================================================

; Set w32_dst to cc20_work + word_index*4 (index from cc20_qr_table[X+.off])
!macro cc20_set_dst .tbl_off {
        ldx cc20_qr_idx
        lda cc20_qr_table+.tbl_off,x
        asl
        asl                    ; *4 for byte offset
        clc
        adc #<cc20_work
        sta w32_dst
        lda #>cc20_work
        adc #0
        sta w32_dst+1
}

!macro cc20_set_src1 .tbl_off {
        ldx cc20_qr_idx
        lda cc20_qr_table+.tbl_off,x
        asl
        asl
        clc
        adc #<cc20_work
        sta w32_src1
        lda #>cc20_work
        adc #0
        sta w32_src1+1
}

chacha20_quarter_round:
        +cc20_set_src1 1
        +cc20_set_dst 0
        jsr add32_to_dst        ; a += b

        +cc20_set_src1 0
        +cc20_set_dst 3
        jsr xor32_in_place      ; d ^= a
        jsr rotr32_16           ; d <<<= 16

        +cc20_set_src1 3
        +cc20_set_dst 2
        jsr add32_to_dst        ; c += d

        +cc20_set_src1 2
        +cc20_set_dst 1
        jsr xor32_in_place      ; b ^= c
        jsr rotl32_12           ; b <<<= 12

        +cc20_set_src1 1
        +cc20_set_dst 0
        jsr add32_to_dst        ; a += b

        +cc20_set_src1 0
        +cc20_set_dst 3
        jsr xor32_in_place      ; d ^= a
        jsr rotl32_8            ; d <<<= 8

        +cc20_set_src1 3
        +cc20_set_dst 2
        jsr add32_to_dst        ; c += d

        +cc20_set_src1 2
        +cc20_set_dst 1
        jsr xor32_in_place      ; b ^= c
        jsr rotl32_7            ; b <<<= 7
        rts

; =============================================================================
; chacha20_init - Initialize ChaCha20 state
;
; Reads key from cc20_key (32 bytes) and nonce from cc20_nonce (12 bytes).
; Sets counter from cc20_counter (4 bytes).
;
; Clobbers: A, X, Y
; =============================================================================
chacha20_init:
        ; Copy constants to state[0..15] (16 bytes = words 0-3)
        ldx #15
@copy_const:
        lda cc20_constants,x
        sta cc20_state,x
        dex
        bpl @copy_const

        ; Copy key to state[16..47] (32 bytes = words 4-11)
        ldx #31
@copy_key:
        lda cc20_key,x
        sta cc20_state+16,x
        dex
        bpl @copy_key

        ; Copy counter to state[48..51] (4 bytes = word 12)
        ldx #3
@copy_ctr:
        lda cc20_counter,x
        sta cc20_state+48,x
        dex
        bpl @copy_ctr

        ; Copy nonce to state[52..63] (12 bytes = words 13-15)
        ldx #11
@copy_nonce:
        lda cc20_nonce,x
        sta cc20_state+52,x
        dex
        bpl @copy_nonce
        rts

; =============================================================================
; chacha20_block - Generate one 64-byte keystream block
;
; 1. Copy state → work
; 2. 10 double-rounds, each containing 8 inlined quarter-rounds
;    (4 column + 4 diagonal)
; 3. Add initial state back: work[i] += state[i] for all 16 words
; 4. Copy work → keystream
; 5. Increment counter in state
; =============================================================================
chacha20_block:
        ; 1. Copy state → work (64 bytes)
        ldx #63
@copy_to_work:
        lda cc20_state,x
        sta cc20_work,x
        dex
        bpl @copy_to_work

        ; 2. 10 double-rounds
        lda #10
        sta cc20_round
@double_round:
        ; --- Column rounds ---
        +cc20_qr  0,  4,  8, 12
        +cc20_qr  1,  5,  9, 13
        +cc20_qr  2,  6, 10, 14
        +cc20_qr  3,  7, 11, 15
        ; --- Diagonal rounds ---
        +cc20_qr  0,  5, 10, 15
        +cc20_qr  1,  6, 11, 12
        +cc20_qr  2,  7,  8, 13
        +cc20_qr  3,  4,  9, 14

        dec cc20_round
        beq @rounds_done
        jmp @double_round
@rounds_done:

        ; 3. Add initial state back: work[i] += state[i] for each of 64 bytes.
        ; Since cc20_work is ZP and both are little-endian byte arrays, we
        ; can add byte-by-byte with a single carry chain *per word*. Unroll
        ; as 16 × 4-byte adds against literal ZP addresses.
        ;
        ; We use a macro that expands to a single 4-byte add.
!macro add_state_word .i {
        clc
        lda cc20_work+4*.i
        adc cc20_state+4*.i
        sta cc20_work+4*.i
        lda cc20_work+4*.i+1
        adc cc20_state+4*.i+1
        sta cc20_work+4*.i+1
        lda cc20_work+4*.i+2
        adc cc20_state+4*.i+2
        sta cc20_work+4*.i+2
        lda cc20_work+4*.i+3
        adc cc20_state+4*.i+3
        sta cc20_work+4*.i+3
}
        +add_state_word 0
        +add_state_word 1
        +add_state_word 2
        +add_state_word 3
        +add_state_word 4
        +add_state_word 5
        +add_state_word 6
        +add_state_word 7
        +add_state_word 8
        +add_state_word 9
        +add_state_word 10
        +add_state_word 11
        +add_state_word 12
        +add_state_word 13
        +add_state_word 14
        +add_state_word 15

        ; 4. Copy work → keystream (64 bytes)
        ldx #63
@copy_keystream:
        lda cc20_work,x
        sta cc20_keystream,x
        dex
        bpl @copy_keystream

        ; 5. Increment counter in state (word 12, bytes 48-51)
        inc cc20_state+48
        bne @ctr_done
        inc cc20_state+49
        bne @ctr_done
        inc cc20_state+50
        bne @ctr_done
        inc cc20_state+51
@ctr_done:
        rts

; =============================================================================
; chacha20_encrypt - Encrypt/decrypt data using ChaCha20 stream
;
; Inputs:
;   cc20_data_ptr ($16-$17) = pointer to plaintext/ciphertext (in-place XOR)
;   cc20_remain ($18) = number of bytes to process (low byte)
;   cc20_remain_hi = high byte of byte count (16-bit total)
;   State must already be initialized via chacha20_init
; =============================================================================
chacha20_encrypt:
        ; Check if anything to do (16-bit)
        lda cc20_remain
        ora cc20_remain_hi
        beq @enc_done          ; nothing to do

@next_block:
        ; Generate a keystream block
        jsr chacha20_block

        ; Determine how many bytes to XOR from this block: min(remain, 64)
        lda cc20_remain_hi
        bne @full              ; > 255 remaining, definitely 64
        lda cc20_remain
        cmp #64
        bcc @partial           ; < 64 bytes remaining
@full:
        lda #64                ; full block
@partial:
        sta cc20_buf_pos       ; bytes to XOR this iteration
        tax                    ; X = count

        ; XOR keystream with data
        ldy #0
@xor_loop:
        lda (cc20_data_ptr),y
        eor cc20_keystream,y
        sta (cc20_data_ptr),y
        iny
        dex
        bne @xor_loop

        ; Advance data pointer
        clc
        lda cc20_data_ptr
        adc cc20_buf_pos
        sta cc20_data_ptr
        lda cc20_data_ptr+1
        adc #0
        sta cc20_data_ptr+1

        ; 16-bit subtract processed bytes from remaining
        lda cc20_remain
        sec
        sbc cc20_buf_pos
        sta cc20_remain
        lda cc20_remain_hi
        sbc #0
        sta cc20_remain_hi

        ; Check if done (16-bit)
        ora cc20_remain
        bne @next_block        ; more bytes to process

@enc_done:
        rts
