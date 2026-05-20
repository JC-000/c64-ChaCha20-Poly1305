; =============================================================================
; min_aead_consumer.s
;
; Minimal consumer test program. Calls only the documented public AEAD
; ABI (poly1305_lib_init + aead_encrypt + aead_decrypt). Linked against
; both `c64-chacha20-poly1305.a` and `c64-chacha20-poly1305-aead-only.a`
; so the ld65 map.txt can be diffed to expose:
;
;   1. Per-symbol size delta — what test-only code the aead-only variant
;      ld65 omits because the body of `chacha20_quarter_round` is gated
;      under .ifndef LIB_VARIANT_AEAD_ONLY.
;
;   2. Externally-visible symbol set — what the consumer's `.import`
;      surface gains from one variant vs the other.
;
; Not intended to RUN on a C64 — the buffers aren't initialised and
; there's no BASIC stub. Just an ld65 input.
; =============================================================================

        .p02

.import poly1305_lib_init
.import aead_encrypt, aead_decrypt

.segment "CODE"

.export entry
entry:
        jsr poly1305_lib_init
        jsr aead_encrypt
        jsr aead_decrypt
        rts
