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
;   chacha20poly1305_zp_tmp1/_zp_tmp2                   : 2 x 1-byte scratch
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
;   chacha20poly1305_zp_ptr1/_zp_ptr2                   : 2 x 2-byte pointers
;
; See src/lib/constants_lib.s for per-slot purpose commentary.
; =============================================================================

.segment "ZEROPAGE"

; --- General-purpose ZP scratch (word32 nibble rotates) ---
;
; Registry migration (contract v0.9.0 §2, gate added v0.9.1 §6.5). The
; bare `zp_tmp*` / `zp_ptr*` spellings are unregistered general-purpose
; names that c64-nist-curves also ships, so two libraries in one link
; collide on them (contract #83) — a collision that was the only thing
; preventing a silent address overlap between actively-used scratch.
; The canonical names take this library's `<shortname>_zp_<role>` form.
;
; The bare aliases further down ride the §6.5 rename window and are
; suppressed by LIB_NO_BARE_EXPORTS. Gating them is what makes the
; window worth anything: an ungated alias would keep the collision alive
; for the window's whole duration, so a composed link would be no better
; off the day the window opened than the day before.
;
; A consumer's deprecated-spelling override is still honoured, so
; `-D zp_tmp1=0x40` keeps working through the window and moves the
; canonical slot with it.
.ifndef chacha20poly1305_zp_tmp1
  .ifdef zp_tmp1
    chacha20poly1305_zp_tmp1 = zp_tmp1  ; deprecated override spelling
  .else
    chacha20poly1305_zp_tmp1 = $02      ; temp byte
  .endif
.endif
.ifndef chacha20poly1305_zp_tmp2
  .ifdef zp_tmp2
    chacha20poly1305_zp_tmp2 = zp_tmp2  ; deprecated override spelling
  .else
    chacha20poly1305_zp_tmp2 = $03      ; temp byte
  .endif
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
; Same registry migration as the scratch bytes above.
.ifndef chacha20poly1305_zp_ptr1
  .ifdef zp_ptr1
    chacha20poly1305_zp_ptr1 = zp_ptr1  ; deprecated override spelling
  .else
    chacha20poly1305_zp_ptr1 = $fb      ; 2-byte pointer ($fb-$fc)
  .endif
.endif
.ifndef chacha20poly1305_zp_ptr2
  .ifdef zp_ptr2
    chacha20poly1305_zp_ptr2 = zp_ptr2  ; deprecated override spelling
  .else
    chacha20poly1305_zp_ptr2 = $fd      ; 2-byte pointer ($fd-$fe)
  .endif
.endif

; --- Exports ---
.exportzp chacha20poly1305_zp_tmp1, chacha20poly1305_zp_tmp2
.exportzp w32_src1, w32_src2, w32_dst
.exportzp cc20_round, cc20_qr_idx, cc20_data_ptr, cc20_remain, cc20_buf_pos
.exportzp poly_i, poly_j, poly_carry, poly_tmp
.exportzp ct_diff_raw, ct_sign_mask
.exportzp cc20_work, cc20_keystream
.exportzp chacha20poly1305_zp_ptr1, chacha20poly1305_zp_ptr2

; --- Deprecated bare aliases (contract §6.5 rename window) ---
; Shipped for one MINOR alongside the canonical names, removed at the
; next MAJOR. Suppressed build-wide by `ca65 -D LIB_NO_BARE_EXPORTS=1`,
; which is the gate §6.5 names for bare-name cases and the same flag a
; composing consumer already sets for the §1 version exports.
.ifndef LIB_NO_BARE_EXPORTS
  .ifndef zp_tmp1
    zp_tmp1 = chacha20poly1305_zp_tmp1
  .endif
  .ifndef zp_tmp2
    zp_tmp2 = chacha20poly1305_zp_tmp2
  .endif
  .ifndef zp_ptr1
    zp_ptr1 = chacha20poly1305_zp_ptr1
  .endif
  .ifndef zp_ptr2
    zp_ptr2 = chacha20poly1305_zp_ptr2
  .endif
  .exportzp zp_tmp1, zp_tmp2
  .exportzp zp_ptr1, zp_ptr2
.endif
