; =============================================================================
; lib/constants_lib.asm - ChaCha20-Poly1305 library equates
;
; ZP + shared equates used by the ChaCha20-Poly1305 library only.
; No KERNAL / PETSCII / hardware references. No code emitted.
;
; Each ZP equate is wrapped in !ifndef so a host project can pre-define its
; own ZP layout before !source'ing this file.
; =============================================================================

; --- General-purpose ZP pointers / scratch ---
!ifndef zp_tmp1  { zp_tmp1  = $02 }   ; temp byte (word32 nibble rotates)
!ifndef zp_tmp2  { zp_tmp2  = $03 }   ; temp byte (word32 nibble rotates)

; --- word32 operand pointers (32-bit add/xor/rotate primitives) ---
!ifndef w32_src1 { w32_src1 = $04 }   ; 2-byte pointer ($04-$05)
!ifndef w32_src2 { w32_src2 = $06 }   ; 2-byte pointer ($06-$07)
!ifndef w32_dst  { w32_dst  = $08 }   ; 2-byte pointer ($08-$09)

; --- ChaCha20 state ZP ---
!ifndef cc20_round    { cc20_round    = $14 } ; double-round counter
!ifndef cc20_qr_idx   { cc20_qr_idx   = $15 } ; quarter-round parameter index
!ifndef cc20_data_ptr { cc20_data_ptr = $16 } ; 2-byte data pointer ($16-$17)
!ifndef cc20_remain   { cc20_remain   = $18 } ; bytes remaining (low byte)
!ifndef cc20_buf_pos  { cc20_buf_pos  = $19 } ; position within 64-byte keystream

; --- ChaCha20 working state (64 bytes, ZP-resident per Step 1 / C1) ---
; Placed at $40..$7f — clear of $02-$1d (chacha/poly/word32 scratch) and
; $fb-$fe (generic pointer pair). The entire 16-word working state is the
; hot inner loop of chacha20_block; keeping it in ZP turns every
; (w32_dst),y indirect into a zero-page indirect whose target lives in ZP,
; and turns the `sta cc20_work,x` direct stores into zp,x addressing
; (4 cy vs 5 cy absolute,x). The host project may override if it wants
; to place cc20_work elsewhere in ZP.
!ifndef cc20_work     { cc20_work     = $40 } ; 64 bytes: $40..$7f

; --- Poly1305 ZP ---
!ifndef poly_i     { poly_i     = $1a }   ; outer loop counter
!ifndef poly_j     { poly_j     = $1b }   ; inner loop counter
!ifndef poly_carry { poly_carry = $1c }   ; carry byte for multi-precision arith
!ifndef poly_tmp   { poly_tmp   = $1d }   ; temp for multiply

; --- General-purpose 16-bit pointers used by poly1305 / aead ---
!ifndef zp_ptr1 { zp_ptr1 = $fb }        ; 2-byte pointer ($fb-$fc)
!ifndef zp_ptr2 { zp_ptr2 = $fd }        ; 2-byte pointer ($fd-$fe)
