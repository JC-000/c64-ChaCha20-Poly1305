.setcpu "6502"

; =============================================================================
; zp_config.s - zero-page allocation for c64-ChaCha20-Poly1305 library.
;
; Consumers integrating this library (e.g. c64-https, c64-wireguard) can
; pre-define any of the symbols below before this module is assembled, or
; replace this file entirely, to pin the library's zero-page layout to
; whatever the host program needs. The library source refers to these
; locations only by symbolic name, so moving an address here is sufficient
; to relocate a slot.
;
; All slots are `.ifndef`-guarded with their historical default address
; and `.exportzp`-ed so they appear as labels in the linker symbol map
; and resolve cleanly across translation units.
;
; Slot inventory:
;   zp_tmp1/zp_tmp2                                     : 2 x 1-byte scratch
;   w32_src1/w32_src2/w32_dst                           : 3 x 2-byte pointers
;   cc20_round/cc20_qr_idx                              : 2 x 1-byte counters
;   cc20_data_ptr                                       : 1 x 2-byte pointer
;   cc20_remain/cc20_buf_pos                            : 2 x 1-byte counters
;   poly_i/poly_j/poly_carry/poly_tmp                   : 4 x 1-byte scratch
;   ct_diff_raw/ct_sign_mask                            : 2 x 1-byte scratch
;                                                         (Profile B ct_mul_8x8)
;   cc20_work                                           : 64-byte block
;                                                         ($40..$7F)
;   cc20_keystream                                      : alias of cc20_work
;   zp_ptr1/zp_ptr2                                     : 2 x 2-byte pointers
;
; See src/lib/constants_lib.s for per-slot purpose commentary.
; =============================================================================

.segment "ZEROPAGE"

; --- General-purpose ZP scratch (word32 nibble rotates) ---
.ifndef zp_tmp1
  zp_tmp1  = $02                        ; temp byte
.endif
.ifndef zp_tmp2
  zp_tmp2  = $03                        ; temp byte
.endif

; --- word32 operand pointers (32-bit add/xor/rotate primitives) ---
.ifndef w32_src1
  w32_src1 = $04                        ; 2-byte pointer ($04-$05)
.endif
.ifndef w32_src2
  w32_src2 = $06                        ; 2-byte pointer ($06-$07)
.endif
.ifndef w32_dst
  w32_dst  = $08                        ; 2-byte pointer ($08-$09)
.endif

; --- ChaCha20 state ZP ---
.ifndef cc20_round
  cc20_round    = $14                   ; double-round counter
.endif
.ifndef cc20_qr_idx
  cc20_qr_idx   = $15                   ; quarter-round parameter index
.endif
.ifndef cc20_data_ptr
  cc20_data_ptr = $16                   ; 2-byte data pointer ($16-$17)
.endif
.ifndef cc20_remain
  cc20_remain   = $18                   ; bytes remaining (low byte)
.endif
.ifndef cc20_buf_pos
  cc20_buf_pos  = $19                   ; position within 64-byte keystream
.endif

; --- Poly1305 ZP ---
.ifndef poly_i
  poly_i     = $1a                      ; outer loop counter
.endif
.ifndef poly_j
  poly_j     = $1b                      ; inner loop counter
.endif
.ifndef poly_carry
  poly_carry = $1c                      ; carry byte
.endif
.ifndef poly_tmp
  poly_tmp   = $1d                      ; multiply temp
.endif

; --- Profile B ct_mul_8x8 ZP scratch (v0.3.0 CT fix) ---
.ifndef ct_diff_raw
  ct_diff_raw  = $1e                    ; raw b-a (pre-sign)
.endif
.ifndef ct_sign_mask
  ct_sign_mask = $1f                    ; $00 if b>=a else $FF
.endif

; --- ChaCha20 working state (64 bytes, ZP-resident) ---
; The 16-word working state occupies $40..$7f. cc20_keystream aliases
; cc20_work so downstream consumers (XOR loop, aead_derive_otk, test
; suite) read the final keystream directly from the working buffer.
.ifndef cc20_work
  cc20_work     = $40                   ; 64 bytes: $40..$7f
.endif
.ifndef cc20_keystream
  cc20_keystream = cc20_work
.endif

; --- General-purpose 16-bit pointers (poly1305 / aead) ---
.ifndef zp_ptr1
  zp_ptr1 = $fb                         ; 2-byte pointer ($fb-$fc)
.endif
.ifndef zp_ptr2
  zp_ptr2 = $fd                         ; 2-byte pointer ($fd-$fe)
.endif

; --- Exports ---
.exportzp zp_tmp1, zp_tmp2
.exportzp w32_src1, w32_src2, w32_dst
.exportzp cc20_round, cc20_qr_idx, cc20_data_ptr, cc20_remain, cc20_buf_pos
.exportzp poly_i, poly_j, poly_carry, poly_tmp
.exportzp ct_diff_raw, ct_sign_mask
.exportzp cc20_work, cc20_keystream
.exportzp zp_ptr1, zp_ptr2
