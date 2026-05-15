; =============================================================================
; lib/data_lib.asm - Mutable data reservations for the ChaCha20-Poly1305 library
;
; Extracted from c64-wireguard/src/data.asm — only the cc20_*, poly_*, aead_*
; fields required by word32_lib / chacha20_lib / poly1305_lib /
; chacha20poly1305_lib. BLAKE2s / HMAC / KDF / fe25519 / X25519 / handshake /
; network / session / config / transport / disk entries were dropped.
; Field order and sizes match the upstream layout so the imported code runs
; unmodified.
; =============================================================================

; NOTE: These reservations live in the DATA segment (not BSS) so they emit
; zero bytes into the PRG file and load into RAM at a known-zero state.
; The original ACME build used !fill (initialized data), so when the PRG
; loads, all state fields are pre-zeroed. If we used BSS (.res in an
; uninitialized segment), poly1305_init's sqtab_ready check could read
; garbage from power-on RAM and skip sqtab_init, leaving the quarter-
; square table uninitialized and poisoning every Poly1305 multiplication.

.export cc20_state, cc20_key, cc20_nonce, cc20_counter, cc20_remain_hi
.export poly_h, poly_r, poly_s, poly_product, poly1305_tag
.export aead_key, aead_nonce, aead_aad_ptr, aead_aad_len
.export aead_data_ptr, aead_data_len, aead_tag, aead_scratch
.export sqtab_ready
.export chacha_nibswap_hi_tab, chacha_nibswap_lo_tab

.segment "DATA"

; --- ChaCha20 state (RFC 7539) ---
; Initial state: 16 x 32-bit words = 64 bytes
cc20_state:
        .res 64

; cc20_work (64 bytes) is now ZP-resident — see cc20_work equate in
; constants_lib.asm. No RAM reservation here.

; cc20_keystream is aliased to cc20_work in constants_lib.asm as of
; Step 8 (C7) — chacha20_block no longer needs a separate output buffer
; because its consumers can read directly from the ZP-resident work
; state. 64 bytes of RAM reclaimed. No .res here.

; 256-bit key
cc20_key:
        .res 32

; 96-bit nonce
cc20_nonce:
        .res 12

; 32-bit block counter
cc20_counter:
        .res 4

; High byte of cc20_remain for 16-bit length support
cc20_remain_hi:
        .res 1

; --- Poly1305 state ---
; 130-bit accumulator (17 bytes for carry room)
poly_h:
        .res 17

; Clamped key part r (16 bytes)
poly_r:
        .res 16

; Key part s (added at end)
poly_s:
        .res 16

; Multiplication scratch (33 bytes for 17x16 product)
poly_product:
        .res 33

; Output tag (16 bytes)
poly1305_tag:
        .res 16

; --- AEAD state ---
aead_key:
        .res 32
aead_nonce:
        .res 12
aead_aad_ptr:
        .res 2
aead_aad_len:
        .res 1
aead_data_ptr:
        .res 2
aead_data_len:
        .res 2                  ; 16-bit data length
aead_tag:
        .res 16

; Poly1305 padding/length block scratch (16 bytes)
aead_scratch:
        .res 16

; --- Library-init state ---
; sqtab_ready: non-zero once sqtab_init has been run at least once.
; Checked by poly1305_init to skip redundant sqtab rebuilds (Step 10).
sqtab_ready:
        .res 1

.segment "CODE"

; =============================================================================
; chacha_nibswap_hi_tab - 256-entry LUT: tab[V] = (V << 4) & $FF
;
; Used by C4 branchless rotl-by-4 (`rotl32_4_zp` in chacha20_lib.s) to
; produce the high-nibble half of `new_b_i = (b_i << 4) | (b_{(i-1) mod 4}
; >> 4)` without a four-shift `asl` chain. Pairs with chacha_nibswap_lo_tab.
;
; **Page-aligned** so that `lda chacha_nibswap_hi_tab,x` never crosses a
; page boundary. The index X is derived from secret state (ChaCha20 work
; bytes), so an `abs,x` page-cross penalty (+1 cy) would create a data-
; dependent timing variance — a CT violation. Aligning the table base low
; byte to $00 makes the access strictly constant-time.
; =============================================================================
        .align 256
chacha_nibswap_hi_tab:
        .repeat 256, V
            .byte (V << 4) & $FF
        .endrepeat

; =============================================================================
; chacha_nibswap_lo_tab - 256-entry LUT: tab[V] = V >> 4
;
; Companion table to chacha_nibswap_hi_tab: produces the low-nibble half
; of `new_b_i = (b_i << 4) | (b_{(i-1) mod 4} >> 4)`. Same CT rationale
; as above — `abs,x` with secret index, page-aligned to suppress the
; cross penalty.
; =============================================================================
        .align 256
chacha_nibswap_lo_tab:
        .repeat 256, V
            .byte V >> 4
        .endrepeat
