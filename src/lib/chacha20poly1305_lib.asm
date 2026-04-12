; =============================================================================
; chacha20poly1305_lib.asm - ChaCha20-Poly1305 AEAD (RFC 7539 §2.8)
;
; Imported verbatim from c64-wireguard/src/aead.asm as the baseline for C64
; optimization. Public entry points: aead_encrypt, aead_decrypt.
; -----------------------------------------------------------------------------
; aead.asm - ChaCha20-Poly1305 AEAD (RFC 7539 §2.8)
;
; Encrypt: derive OTK, encrypt plaintext, compute tag
; Decrypt: derive OTK, verify tag, decrypt ciphertext
;
; Interface (set in memory before call):
;   aead_key      (32 bytes) — symmetric key
;   aead_nonce    (12 bytes) — nonce
;   aead_aad_ptr  (2 bytes)  — pointer to AAD
;   aead_aad_len  (1 byte)   — AAD length (0-255)
;   aead_data_ptr (2 bytes)  — pointer to plaintext/ciphertext
;   aead_data_len (2 bytes)  — data length (16-bit, up to 1500)
;
; Output:
;   Ciphertext written in-place at aead_data_ptr
;   aead_tag (16 bytes) — authentication tag
;   A register: 0 = success (decrypt), nonzero = auth failure
; =============================================================================

; =============================================================================
; aead_encrypt - ChaCha20-Poly1305 authenticated encryption
;
; 1. Derive Poly1305 OTK using ChaCha20 block with counter=0
; 2. Encrypt plaintext with ChaCha20 starting at counter=1
; 3. Compute Poly1305 tag over (AAD ‖ pad ‖ ciphertext ‖ pad ‖ lengths)
;
; Clobbers: A, X, Y
; =============================================================================
aead_encrypt:
        ; --- 1. Derive Poly1305 OTK ---
        ; A5 (S8): aead_derive_otk already ran chacha20_init and one
        ; chacha20_block. The block's tail increments cc20_state+48 from
        ; 0 -> 1, so cc20_state is already primed with counter=1 and the
        ; correct key/nonce. We therefore skip the redundant counter set,
        ; aead_setup_chacha, and chacha20_init that the old flow performed
        ; here. Save: 1x setup_chacha + 1x chacha20_init per packet
        ; (~2 000 cy).
        jsr aead_derive_otk

        ; --- 2. Encrypt plaintext with ChaCha20 (counter=1, state primed) ---
        ; Set up encryption pointers
        lda aead_data_ptr
        sta cc20_data_ptr
        lda aead_data_ptr+1
        sta cc20_data_ptr+1
        lda aead_data_len
        sta cc20_remain
        lda aead_data_len+1
        sta cc20_remain_hi
        jsr chacha20_encrypt

        ; --- 3. Compute Poly1305 tag ---
        jsr aead_compute_tag
        rts

; =============================================================================
; aead_decrypt - ChaCha20-Poly1305 authenticated decryption
;
; 1. Derive Poly1305 OTK
; 2. Compute expected tag over (AAD ‖ pad ‖ ciphertext ‖ pad ‖ lengths)
; 3. Verify tag (constant-time comparison)
; 4. If valid, decrypt ciphertext
;
; Output: A = 0 if tag valid, nonzero if tag mismatch
; Clobbers: A, X, Y
; =============================================================================
aead_decrypt:
        ; --- 1. Derive Poly1305 OTK ---
        jsr aead_derive_otk

        ; --- 2. Compute expected tag (over ciphertext, not plaintext) ---
        jsr aead_compute_tag

        ; --- 3. Verify tag ---
        jsr aead_verify_tag
        bne @auth_fail          ; A != 0 means tag mismatch

        ; --- 4. Decrypt ciphertext with ChaCha20 (counter=1) ---
        ; A6 (S8): aead_derive_otk already set up key/nonce and ran one
        ; chacha20_block, whose tail bumped cc20_state+48 to 1. The tag
        ; compute between derive_otk and here only calls Poly1305
        ; routines, so cc20_state is still primed with counter=1 and the
        ; right key/nonce. Skip the redundant setup_chacha + init
        ; (~500 cy saved per decrypt).
        lda aead_data_ptr
        sta cc20_data_ptr
        lda aead_data_ptr+1
        sta cc20_data_ptr+1
        lda aead_data_len
        sta cc20_remain
        lda aead_data_len+1
        sta cc20_remain_hi
        jsr chacha20_encrypt    ; XOR = decrypt

        lda #0                  ; success
        rts

@auth_fail:
        lda #$ff               ; failure
        rts

; =============================================================================
; aead_derive_otk - Derive Poly1305 one-time key
;
; ChaCha20 block with counter=0, take first 32 bytes as OTK
; First 16 → poly_r, next 16 → poly_s
; Then initialize Poly1305 state
;
; Clobbers: A, X, Y
; =============================================================================
aead_derive_otk:
        ; Set counter = 0
        lda #0
        sta cc20_counter
        sta cc20_counter+1
        sta cc20_counter+2
        sta cc20_counter+3

        ; Set up ChaCha20 with key/nonce
        jsr aead_setup_chacha
        jsr chacha20_init
        jsr chacha20_block      ; generate 64-byte keystream

        ; Copy first 16 bytes → poly_r
        ldx #15
@copy_r:
        lda cc20_keystream,x
        sta poly_r,x
        dex
        bpl @copy_r

        ; Copy bytes 16-31 → poly_s
        ldx #15
@copy_s:
        lda cc20_keystream+16,x
        sta poly_s,x
        dex
        bpl @copy_s

        ; Initialize Poly1305 (clamp r, zero h, build sqtab)
        jsr poly1305_init
        rts

; =============================================================================
; aead_setup_chacha - Copy aead_key→cc20_key, aead_nonce→cc20_nonce
;
; Also copies cc20_counter (already set by caller).
; Clobbers: A, X
; =============================================================================
aead_setup_chacha:
        ldx #31
@copy_key:
        lda aead_key,x
        sta cc20_key,x
        dex
        bpl @copy_key

        ldx #11
@copy_nonce:
        lda aead_nonce,x
        sta cc20_nonce,x
        dex
        bpl @copy_nonce
        rts

; =============================================================================
; aead_compute_tag - Compute Poly1305 tag for AEAD construction
;
; Poly1305 over: AAD ‖ pad16(AAD) ‖ ciphertext ‖ pad16(CT) ‖ len(AAD) ‖ len(CT)
; where pad16 pads to 16-byte boundary and lengths are 8-byte little-endian
;
; All data is processed as full 16-byte Poly1305 blocks with hibit=1.
; Partial data at the end of AAD or CT is zero-padded to fill a complete block.
;
; Clobbers: A, X, Y
; =============================================================================
aead_compute_tag:
        ; --- Process AAD ---
        lda aead_aad_len
        beq @skip_aad
        sta cc20_remain
        lda #0
        sta cc20_remain_hi      ; AAD length is always <= 255
        lda aead_aad_ptr
        sta zp_ptr1
        lda aead_aad_ptr+1
        sta zp_ptr1+1
        jsr aead_process_padded

@skip_aad:
        ; --- Process ciphertext (16-bit length) ---
        lda aead_data_len
        ora aead_data_len+1
        beq @skip_ct
        lda aead_data_len
        sta cc20_remain
        lda aead_data_len+1
        sta cc20_remain_hi
        lda aead_data_ptr
        sta zp_ptr1
        lda aead_data_ptr+1
        sta zp_ptr1+1
        jsr aead_process_padded

@skip_ct:
        ; --- Process lengths block (16 bytes) ---
        ; Build: aad_len as 8-byte LE ‖ data_len as 8-byte LE
        ; A3 (S8): unrolled 16 straight stores — no loop overhead (-80 cy).
        ; The three "live" bytes (aad_len at 0, data_len lo at 8, hi at 9)
        ; are written directly with no intermediate zero store.
        lda #0
        sta aead_scratch+1
        sta aead_scratch+2
        sta aead_scratch+3
        sta aead_scratch+4
        sta aead_scratch+5
        sta aead_scratch+6
        sta aead_scratch+7
        sta aead_scratch+10
        sta aead_scratch+11
        sta aead_scratch+12
        sta aead_scratch+13
        sta aead_scratch+14
        sta aead_scratch+15

        lda aead_aad_len
        sta aead_scratch        ; low byte of AAD length (rest is 0)
        lda aead_data_len
        sta aead_scratch+8      ; low byte of CT length
        lda aead_data_len+1
        sta aead_scratch+9      ; high byte of CT length

        ; Process as one 16-byte block with hibit=1
        lda #<aead_scratch
        sta zp_ptr1
        lda #>aead_scratch
        sta zp_ptr1+1
        lda #1
        jsr poly1305_block

        ; Finalize tag
        jsr poly1305_final
        rts

; =============================================================================
; aead_process_padded - Process data as Poly1305 blocks, zero-padding last block
;
; Input: zp_ptr1 = data pointer
;        cc20_remain = length low byte, cc20_remain_hi = length high byte
; All blocks processed with hibit=1. Last partial block is zero-padded to 16.
;
; Clobbers: A, X, Y
; =============================================================================
aead_process_padded:
@next_block:
        ; Check if done (16-bit)
        lda cc20_remain
        ora cc20_remain_hi
        bne @have_data
        jmp @done
@have_data:

        ; Check if >= 16 bytes remain
        lda cc20_remain_hi
        bne @full_block         ; > 255 remaining, definitely >= 16
        lda cc20_remain
        cmp #16
        bcc @partial            ; < 16 bytes left

@full_block:
        ; Full 16-byte block with hibit=1
        lda #1
        jsr poly1305_block

        ; Advance pointer by 16
        clc
        lda zp_ptr1
        adc #16
        sta zp_ptr1
        lda zp_ptr1+1
        adc #0
        sta zp_ptr1+1

        ; 16-bit subtract 16
        lda cc20_remain
        sec
        sbc #16
        sta cc20_remain
        lda cc20_remain_hi
        sbc #0
        sta cc20_remain_hi
        jmp @next_block

@partial:
        ; A4 (S8): merged partial-block copy + zero-fill via SMC jump
        ; dispatch. cc20_remain holds n (1..15) — a public length, so
        ; branching on it is CT-safe.
        ;
        ; Copy chain: 15 identical fixed-size (6-byte) slots. Slot @cp_k
        ; copies byte k from (zp_ptr1),y into aead_scratch,y and bumps
        ; Y. Jumping to @cp_base + (15-n)*6 leaves exactly n slots to
        ; fall through, so bytes 0..n-1 get copied and Y ends at n.
        ;
        ; Zero-fill chain: 15 identical fixed-size (3-byte) `sta abs`
        ; slots @zf1..@zf15 writing to aead_scratch+1..+15. Jumping to
        ; @zf1 + (n-1)*3 leaves slots @zf_n..@zf15 to fall through,
        ; writing zero into aead_scratch+n..+15. aead_scratch+0 is
        ; handled by the copy chain (n>=1 always here).
        lda cc20_remain         ; n in 1..15
        sta zp_tmp1             ; stash n for zfill dispatch
        ; --- compute copy-chain entry = @cp_base + (15-n)*6 ---
        ; n is in 1..15 so `eor #15` yields (15-n) (xor = subtract when
        ; the minuend has all low bits set and the subtrahend has none
        ; beyond them).
        eor #15                 ; A = 15 - n
        sta zp_tmp2             ; k = 15 - n
        asl                     ; 2k
        clc
        adc zp_tmp2             ; 3k
        asl                     ; 6k
        clc
        adc #<@cp_base
        sta @partial_smc+1
        lda #0
        adc #>@cp_base
        sta @partial_smc+2
        ldy #0
@partial_smc:
        jmp $0000
@cp_base:
@cp15:  lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp14:  lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp13:  lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp12:  lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp11:  lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp10:  lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp9:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp8:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp7:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp6:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp5:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp4:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp3:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp2:   lda (zp_ptr1),y : sta aead_scratch,y : iny
@cp1:   lda (zp_ptr1),y : sta aead_scratch,y : iny

        ; --- compute zfill entry = @zf1 + (n-1)*3 ---
        lda zp_tmp1             ; n
        sec
        sbc #1                  ; n-1
        sta zp_tmp2             ; m = n-1 (0..14)
        asl                     ; 2m
        clc
        adc zp_tmp2             ; 3m
        clc
        adc #<@zf1
        sta @zfill_smc+1
        lda #0
        adc #>@zf1
        sta @zfill_smc+2
        lda #0
@zfill_smc:
        jmp $0000
@zf1:   sta aead_scratch+1
@zf2:   sta aead_scratch+2
@zf3:   sta aead_scratch+3
@zf4:   sta aead_scratch+4
@zf5:   sta aead_scratch+5
@zf6:   sta aead_scratch+6
@zf7:   sta aead_scratch+7
@zf8:   sta aead_scratch+8
@zf9:   sta aead_scratch+9
@zf10:  sta aead_scratch+10
@zf11:  sta aead_scratch+11
@zf12:  sta aead_scratch+12
@zf13:  sta aead_scratch+13
@zf14:  sta aead_scratch+14
@zf15:  sta aead_scratch+15

        ; Process zero-padded block with hibit=1
        lda #<aead_scratch
        sta zp_ptr1
        lda #>aead_scratch
        sta zp_ptr1+1
        lda #1
        jsr poly1305_block

@done:
        rts

; =============================================================================
; aead_verify_tag - Constant-time comparison of computed vs provided tag
;
; Compares poly1305_tag with aead_tag (16 bytes)
; Output: A = 0 if equal, nonzero if different
;
; Clobbers: A, X
; =============================================================================
aead_verify_tag:
        lda #0
        sta poly_carry          ; zero the accumulator
        ldx #15
@cmp_loop:
        lda poly1305_tag,x
        eor aead_tag,x
        ora poly_carry          ; accumulate differences
        sta poly_carry
        dex
        bpl @cmp_loop
        lda poly_carry          ; 0 = match, nonzero = mismatch
        rts
