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

; --- ChaCha20 state (RFC 7539) ---
; Initial state: 16 x 32-bit words = 64 bytes
cc20_state:
        !fill 64, 0

; Working state during block computation
cc20_work:
        !fill 64, 0

; Generated keystream for XOR
cc20_keystream:
        !fill 64, 0

; 256-bit key
cc20_key:
        !fill 32, 0

; 96-bit nonce
cc20_nonce:
        !fill 12, 0

; 32-bit block counter
cc20_counter:
        !fill 4, 0

; High byte of cc20_remain for 16-bit length support
cc20_remain_hi:
        !byte 0

; --- Poly1305 state ---
; 130-bit accumulator (17 bytes for carry room)
poly_h:
        !fill 17, 0

; Clamped key part r (16 bytes)
poly_r:
        !fill 16, 0

; Key part s (added at end)
poly_s:
        !fill 16, 0

; Multiplication scratch (33 bytes for 17x16 product)
poly_product:
        !fill 33, 0

; Output tag (16 bytes)
poly1305_tag:
        !fill 16, 0

; --- AEAD state ---
aead_key:
        !fill 32, 0
aead_nonce:
        !fill 12, 0
aead_aad_ptr:
        !word 0
aead_aad_len:
        !byte 0
aead_data_ptr:
        !word 0
aead_data_len:
        !word 0                ; 16-bit data length
aead_tag:
        !fill 16, 0

; Poly1305 padding/length block scratch (16 bytes)
aead_scratch:
        !fill 16, 0
