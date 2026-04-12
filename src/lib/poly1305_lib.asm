; =============================================================================
; poly1305_lib.asm - Poly1305 MAC (RFC 7539)
;
; Imported verbatim from c64-wireguard/src/poly1305.asm as the baseline for
; C64 optimization. Public entry points: poly1305_init, poly1305_block,
; poly1305_update, poly1305_final. Uses a quarter-square lookup table at
; $8000-$83FF (built at runtime by sqtab_init).
; -----------------------------------------------------------------------------
; poly1305.asm - Poly1305 MAC (RFC 7539)
;
; 130-bit modular arithmetic using quarter-square lookup table for fast
; 8x8→16-bit byte multiplication.
;
; Accumulator h: 17 bytes (136 bits, room for carries in 130-bit range)
; Key r: 16 bytes (clamped per RFC 7539)
; Key s: 16 bytes (added to final result)
;
; Quarter-square table: sqtab_lo/hi at $8000-$83FF (1024 bytes)
; Identity: a*b = floor((a+b)^2/4) - floor((a-b)^2/4)
; =============================================================================

; Quarter-square table addresses (page-aligned for speed)
sqtab_lo        = $8000         ; 512 bytes: low bytes of floor(n^2/4)
sqtab_hi        = $8200         ; 512 bytes: high bytes of floor(n^2/4)

; =============================================================================
; poly1305_lib_init - One-time library initialization (Step 10)
;
; Builds the 1 KB quarter-square lookup table at sqtab_lo/hi ($8000-$83FF).
; This table is a pure function of the platform (integer squares) — it never
; changes regardless of key, nonce, or r. Calling this once at application
; startup saves ~80-90 k cy on every subsequent poly1305_init / aead_encrypt
; / aead_decrypt call for both profiles.
;
; Safe to call multiple times (idempotent via sqtab_ready flag).
; Must be called at least once before any aead_encrypt / aead_decrypt.
;
; REU backup (Profile A, POLY1305_REU=1): after building sqtab, DMA the
; 1 KB table to REU bank 0 at offset $0000 as a fast-restore backup.
; poly1305_reu_restore can later reload sqtab from REU in ~1.1 k cy if
; the $8000-$83FF region is ever clobbered by external code.
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_lib_init:
        lda sqtab_ready
        bne @already_done       ; skip if already built
        jsr sqtab_init
        lda #1
        sta sqtab_ready

!ifdef POLY1305_PROFILE_LONG {
!ifdef POLY1305_REU {
        ; DMA sqtab (1024 bytes at $8000) to REU bank 0, offset $0000.
        ; C64 → REU transfer (command = $90: stash, no autoload, no FF00 trigger).
        lda #$00
        sta $DF04               ; REU base address lo
        sta $DF05               ; REU base address hi
        sta $DF06               ; REU bank
        lda #<sqtab_lo
        sta $DF02               ; C64 base address lo
        lda #>sqtab_lo
        sta $DF03               ; C64 base address hi
        lda #<1024
        sta $DF07               ; transfer length lo
        lda #>1024
        sta $DF08               ; transfer length hi
        lda #$00
        sta $DF0A               ; address control: increment both
        lda #$90                ; command: C64→REU, no autoload, execute
        sta $DF01
}
}

@already_done:
        rts

!ifdef POLY1305_PROFILE_LONG {
!ifdef POLY1305_REU {
; =============================================================================
; poly1305_reu_restore - DMA sqtab back from REU to main RAM
;
; Restores the 1 KB quarter-square table from REU bank 0 offset $0000
; to $8000-$83FF. Use this if external code clobbers the sqtab region.
; Cost: ~1.1 k cy (50 cy setup + 1024 cy DMA).
;
; Clobbers: A
; =============================================================================
poly1305_reu_restore:
        lda #$00
        sta $DF04               ; REU base address lo
        sta $DF05               ; REU base address hi
        sta $DF06               ; REU bank
        lda #<sqtab_lo
        sta $DF02               ; C64 base address lo
        lda #>sqtab_lo
        sta $DF03               ; C64 base address hi
        lda #<1024
        sta $DF07               ; transfer length lo
        lda #>1024
        sta $DF08               ; transfer length hi
        lda #$00
        sta $DF0A               ; address control: increment both
        lda #$91                ; command: REU→C64, no autoload, execute
        sta $DF01
        rts
}
}

; =============================================================================
; poly1305_init - Initialize Poly1305 state
;
; Input: 32-byte one-time key at poly_r (first 16 bytes) and poly_s (next 16)
;        Caller must write the OTK: first 16 bytes → poly_r, next 16 → poly_s
;
; Operations:
;   1. Clamp r
;   2. Zero accumulator h
;   3. Build quarter-square multiply table (skipped if already built)
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_init:
        ; 1. Clamp r per RFC 7539 §2.5
        jsr poly1305_clamp

        ; 2. Zero accumulator (17 bytes)
        ldx #16
        lda #0
@zero_h:
        sta poly_h,x
        dex
        bpl @zero_h

        ; 3. Build quarter-square table (skip if poly1305_lib_init already ran)
        lda sqtab_ready
        bne @sqtab_done
        jsr sqtab_init
        lda #1
        sta sqtab_ready
@sqtab_done:

!ifdef POLY1305_PROFILE_LONG {
        ; 4. Build Shoup per-r tables (Step 6 / P3, Profile A only).
        ;    Uses mul_8x8 (sqtab-backed) 4096 times, one per
        ;    (limb j, byte value x). Amortized across >= 2 blocks.
        jsr shoup_init
}
        rts

!ifdef POLY1305_PROFILE_LONG {
; =============================================================================
; shoup_init - Populate r_tab_lo / r_tab_hi with T_j[x] = x * r[j]
;
; For each j in 0..15, for each x in 0..255:
;   (hi,lo) = x * r[j]   (16-bit via mul_8x8 + sqtab)
;   r_tab_lo + j*256 + x = lo
;   r_tab_hi + j*256 + x = hi
;
; Called from poly1305_init AFTER poly1305_clamp and sqtab_init. ~4096
; calls to mul_8x8, amortized over all subsequent poly1305_block calls
; for this message (r is fixed per packet).
;
; Self-modifies the inner mul_8x8 multiplier immediate and the two
; store high bytes so the inner loop is a straight-line sequence of
; absolute addressing modes.
;
; Clobbers: A, X, Y
; =============================================================================
shoup_init:
        lda #0
        sta poly_j              ; reuse as j counter (0..15)
.shoup_j_loop:
        ; Patch store high bytes to (r_tab_lo + j*256) and (r_tab_hi + j*256).
        lda poly_j
        clc
        adc #>r_tab_lo
        sta .shoup_sta_lo+2
        lda poly_j
        clc
        adc #>r_tab_hi
        sta .shoup_sta_hi+2

        ; Patch the inner mul multiplier to r[j].
        ldy poly_j
        lda poly_r,y
        sta .shoup_rj_val+1

        ; Inner loop: x = 0..255.
        lda #0
        sta poly_i              ; reuse as x counter
.shoup_x_loop:
        lda poly_i              ; A = x (multiplicand)
.shoup_rj_val: ldx #$00         ; X = r[j] (SMC, multiplier)
        jsr mul_8x8             ; -> poly_prod_lo / poly_prod_hi
        ldy poly_i
        lda poly_prod_lo
.shoup_sta_lo: sta r_tab_lo,y   ; SMC high byte
        lda poly_prod_hi
.shoup_sta_hi: sta r_tab_hi,y   ; SMC high byte

        inc poly_i
        bne .shoup_x_loop        ; 256 iterations

        inc poly_j
        lda poly_j
        cmp #16
        bne .shoup_j_loop
        rts
}

; =============================================================================
; poly1305_clamp - Clamp r per RFC 7539
;
; Clear top 4 bits of bytes 3, 7, 11, 15
; Clear bottom 2 bits of bytes 4, 8, 12
; =============================================================================
poly1305_clamp:
        ; Clear top 4 bits of r[3], r[7], r[11], r[15]
        lda poly_r+3
        and #$0f
        sta poly_r+3
        lda poly_r+7
        and #$0f
        sta poly_r+7
        lda poly_r+11
        and #$0f
        sta poly_r+11
        lda poly_r+15
        and #$0f
        sta poly_r+15

        ; Clear bottom 2 bits of r[4], r[8], r[12]
        lda poly_r+4
        and #$fc
        sta poly_r+4
        lda poly_r+8
        and #$fc
        sta poly_r+8
        lda poly_r+12
        and #$fc
        sta poly_r+12
        rts

; =============================================================================
; sqtab_init - Build quarter-square lookup table at $7800-$7BFF
;
; Computes floor(i^2/4) for i = 0..511 using recurrence i^2 = (i-1)^2 + 2i - 1
; Ported from c64-aes256-ecdsa fp_init_sqtab.
;
; Clobbers: A, X, Y
; =============================================================================
sqtab_init:
        lda #0
        sta sq_acc              ; accumulator = 0
        sta sq_acc+1
        sta sq_acc+2
        sta sq_i                ; index = 0
        sta sq_i+1

@loop:
        ; Compute f(i) = sq_acc >> 2 (divide by 4)
        lda sq_acc+2
        lsr
        sta sq_sh+2
        lda sq_acc+1
        ror
        sta sq_sh+1
        lda sq_acc
        ror
        sta sq_sh
        lsr sq_sh+2
        ror sq_sh+1
        ror sq_sh

        ; Store in table at index sq_i (0..511)
        ldx sq_i                ; low byte of index
        lda sq_i+1
        beq @pg0
        ; Page 1 (256..511)
        lda sq_sh
        sta sqtab_lo+256,x
        lda sq_sh+1
        sta sqtab_hi+256,x
        jmp @advance
@pg0:
        lda sq_sh
        sta sqtab_lo,x
        lda sq_sh+1
        sta sqtab_hi,x

@advance:
        ; sq_acc += 2*i + 1 (recurrence: (i+1)^2 = i^2 + 2i + 1)
        lda sq_i
        asl
        sta sq_ad
        lda sq_i+1
        rol
        sta sq_ad+1
        inc sq_ad
        bne +
        inc sq_ad+1
+
        clc
        lda sq_acc
        adc sq_ad
        sta sq_acc
        lda sq_acc+1
        adc sq_ad+1
        sta sq_acc+1
        lda sq_acc+2
        adc #0
        sta sq_acc+2

        inc sq_i
        bne +
        inc sq_i+1
+       lda sq_i+1
        cmp #2                  ; check if i reached 512 (0x200)
        beq @done
        jmp @loop
@done:  rts

; Temporaries for sqtab_init
sq_acc: !fill 3, 0              ; 24-bit accumulator for i^2
sq_sh:  !fill 3, 0              ; 24-bit shifted result (i^2 / 4)
sq_ad:  !fill 2, 0              ; 16-bit addition term (2i+1)
sq_i:   !fill 2, 0              ; 16-bit index counter (0..511)

; =============================================================================
; mul_8x8 - 8-bit x 8-bit → 16-bit multiply using quarter-square table
;
; Input: A = multiplicand, X = multiplier
; Output: poly_prod_lo/hi = A * X (16-bit result)
;
; Uses identity: a*b = sqtab[a+b] - sqtab[|a-b|]
; Clobbers: A, X, Y
; =============================================================================
poly_prod_lo:   !byte 0
poly_prod_hi:   !byte 0

mul_8x8:
        sta mul_a               ; save A
        stx mul_b               ; save X

        ; Compute sum = a + b
        clc
        adc mul_b               ; A = a + b (low byte)
        tax                     ; X = sum low byte
        lda #0
        adc #0                  ; carry → sum page (0 or 1)
        sta mul_s_pg            ; sum page

        ; Compute |a - b|
        lda mul_a
        sec
        sbc mul_b
        bcs +
        eor #$ff
        adc #1                  ; negate (carry was clear, so ADC adds 1)
+       tay                     ; Y = |a-b| (always page 0, ≤255)

        ; sqtab[sum] - sqtab[|diff|]
        lda mul_s_pg
        beq @s0
        ; sum is in page 1 (256..510)
        lda sqtab_lo+256,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi+256,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts
@s0:
        ; sum is in page 0 (0..255)
        lda sqtab_lo,x
        sec
        sbc sqtab_lo,y
        sta poly_prod_lo
        lda sqtab_hi,x
        sbc sqtab_hi,y
        sta poly_prod_hi
        rts

mul_a:          !byte 0
mul_b:          !byte 0
mul_s_pg:       !byte 0

; =============================================================================
; poly_ripple - propagate a set carry upward through poly_product starting
; at index X. Entered only when the just-completed add left carry set.
;
; Uses INC/BNE instead of SEC/ADC#0 — ripple stops as soon as a byte doesn't
; wrap to zero. Bounded by poly_product size (33 bytes, indices 0..32).
;
; Note on constant-time: the ripple loop branches on carry (INC's Z flag),
; which is a function of hardware flags after an addition. This is
; standard for multi-precision arithmetic on 6502 and is *not* a CT
; violation — the CT contract is "no branches on secret operand bytes
; directly". The early-exits removed from poly1305_multiply (beq on
; h[i] / r[j]) were such violations; carry-out branches are not.
;
; Clobbers: A, X
; =============================================================================
poly_ripple:
@loop:
        cpx #33
        bcs @done
        inc poly_product,x
        bne @done              ; carry absorbed
        inx
        bne @loop              ; always taken (X never wraps before bounds hit)
@done:
        rts

; =============================================================================
; poly1305_multiply - Multiply h (17 bytes) by r (16 bytes), reduce mod 2^130-5
;
; Fully unrolled 17x16 schoolbook multiply (272 partial products) as a
; straight-line macro expansion. Eliminates the inner/outer loop overhead
; from the old loopy form (~12 k cy per block) and removes the two
; data-dependent early-exits (`beq @skip_h_zero`, `beq @skip_r_zero`)
; which were constant-time violations — every partial product is now
; computed unconditionally regardless of h[i] or r[j] being zero.
;
; Each partial product h[i]*r[j] is added to poly_product[i+j..i+j+1]
; via a 16-bit add; if that add leaves carry set, poly_ripple propagates
; it upward. Final reduction mod 2^130-5 is handled by poly1305_reduce.
;
; Clobbers: A, X, Y
; =============================================================================

; Macro: emit one partial product h[.i] * r[.j] — Profile B (schoolbook
; via sqtab-backed mul_8x8). Profile A replaces this with Shoup per-r
; table lookups (see +poly_pp_shoup below).
!macro poly_pp .i, .j {
        lda poly_h + .i
        ldx poly_r + .j
        jsr mul_8x8             ; poly_prod_lo/hi = h[i] * r[j]
        clc
        lda poly_product + (.i + .j)
        adc poly_prod_lo
        sta poly_product + (.i + .j)
        lda poly_product + (.i + .j + 1)
        adc poly_prod_hi
        sta poly_product + (.i + .j + 1)
        bcc +
        ldx #(.i + .j + 2)
        jsr poly_ripple
+
}

!ifdef POLY1305_PROFILE_LONG {
; Macro: Shoup-table partial product h[.i] * r[.j] — Profile A.
;
; Precondition on entry: X = poly_h + .i (loaded once per outer row).
; The Shoup table at r_tab_lo + .j*256 holds T_j[x] = (x * r[j]) & $ff,
; and r_tab_hi + .j*256 holds the high byte. Two page-indexed loads
; replace the sqtab-based 8x8 multiply entirely.
;
; Postcondition: X still equals poly_h + .i (reloaded from RAM only
; on the rare ripple path).
;
; No branches depend on the *value* of h[i] or r[j]; the only branch
; (bcc) depends on carry-out from the addition, which is standard
; multi-precision arithmetic and CT-safe on 6502.
!macro poly_pp_shoup .i, .j {
        clc
        lda r_tab_lo + (.j * 256), x
        adc poly_product + (.i + .j)
        sta poly_product + (.i + .j)
        lda r_tab_hi + (.j * 256), x
        adc poly_product + (.i + .j + 1)
        sta poly_product + (.i + .j + 1)
        bcc +
        ldx #(.i + .j + 2)
        jsr poly_ripple
        ldx poly_h + .i         ; ripple clobbered X; restore row base
+
}
}

; =============================================================================
; poly_reduce_shl6_tab - 256-entry LUT: tab[y] = (y & 3) << 6
;
; Used by the unrolled fused poly1305_reduce to land the top 2 bits of
; product[17+k] at bit positions 6..7 of the overflow byte without six
; in-line `asl`s. Saves ~10 cy per inner iteration × 16 iterations.
;
; **Page-aligned** so that `lda poly_reduce_shl6_tab,y` never crosses a
; page boundary — `lda abs,y` adds a 1-cycle penalty on page cross, and
; Y here is derived from h*r (secret), so a cross-dependent timing
; would be a CT violation. Aligning the base low byte to $00 makes the
; access strictly constant-time.
; =============================================================================
        !align 255, 0
poly_reduce_shl6_tab:
        !for .V, 0, 255 {
            !byte (.V & 3) << 6
        }

poly1305_multiply:
        ; Zero the product buffer (33 bytes) — unrolled store chain.
        lda #0
        !for .Z, 0, 32 {
            sta poly_product + .Z
        }

!ifdef POLY1305_PROFILE_LONG {
        ; Fully unrolled 17x16 schoolbook via Shoup per-r tables (P3).
        ; X is hoisted out of the j loop: h[i] is constant for all 16
        ; inner iterations of a given row.
        !for .I, 0, 16 {
            ldx poly_h + .I
            !for .J, 0, 15 {
                +poly_pp_shoup .I, .J
            }
        }
} else {
        ; Fully unrolled 17x16 schoolbook: 272 partial products
        !for .I, 0, 16 {
            !for .J, 0, 15 {
                +poly_pp .I, .J
            }
        }
}

        ; Fall through to poly1305_reduce (fused Donna wrap).

; =============================================================================
; poly1305_reduce - Reduce poly_product (33 bytes) mod 2^130-5 into poly_h
;
; Step 7 (P4 Donna-style fused wrap): the schoolbook above still fills
; poly_product[0..32] as a 33-byte intermediate, but this reduction is
; rewritten as a single fused pass that merges the old two 1-bit right-
; shift passes and the 17-byte *5 running-carry loop into straight-line
; code that computes each overflow byte on the fly.
;
; Identity: product = L + 2^130 * H  where
;     L = product[0..15] + (product[16] & 3) << 128   (130 bits)
;     H = product[16..32] >> 2                        (124 bits, 17 bytes)
; and  product mod (2^130 - 5) = L + 5*H  (since 2^130 ≡ 5 mod p).
;
; overflow byte k = (product[16+k] >> 2) | ((product[17+k] & 3) << 6),
; with product[33] implicitly zero for k=16.
;
; Each overflow byte is multiplied by 5 via (x<<2)+x and added to h[k]
; with a running 16-bit carry.
;
; CT contract: the only branches are (a) ripple on adder carry, which is
; a function of hardware flags and independent of secret bytes beyond
; standard multi-precision arithmetic, and (b) loop control on a fixed
; 17-iteration unroll (fully straight-line here).
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_reduce:
        ; 1. Copy low 130 bits of product → h (straight-line).
        !for .K, 0, 15 {
            lda poly_product + .K
            sta poly_h + .K
        }
        lda poly_product + 16
        and #$03
        sta poly_h + 16

        ; 2. Fused overflow-shift + *5 + add-to-h, fully unrolled for
        ;    k = 0..16. Running carry_in kept in poly_carry.
        ;
        ;    Per iteration:
        ;      ov    = (p[16+k] >> 2) | ((p[17+k] & 3) << 6)  ; k<16
        ;      ov    = (p[32] >> 2)                           ; k=16
        ;      prod5 = ov * 5                                 ; 16-bit (max 1275)
        ;      sum16 = prod5 + carry_in                       ; 16-bit
        ;      h[k] += sum16_lo; carry_out = sum16_hi + add_carry
        ;      carry_in := carry_out
        ;
        ;    All arithmetic is branch-free (no early-outs on secret ov),
        ;    matching the Step 4 CT cleanup.
        lda #0
        sta poly_carry

        !for .K, 0, 16 {
            ; --- form overflow byte .K in A.
            lda poly_product + 16 + .K
            lsr
            lsr                     ; A = p[16+.K] >> 2 (bits 6..7 cleared)
            !if .K < 16 {
                sta poly_tmp        ; stash low 6 bits of ov
                ldy poly_product + 17 + .K
                lda poly_reduce_shl6_tab,y  ; A = (y & 3) << 6  (via 256-entry LUT)
                ora poly_tmp        ; A = overflow byte .K
            }
            sta poly_tmp            ; poly_tmp = ov (stash for ov*5)

            ; --- compute ov*5 into (poly_i : A) branch-free.
            ;     poly_i is unused outside shoup_init, repurposed as the
            ;     running 8-bit hi scratch (max ov*5 = 1275, hi ≤ 4).
            lda #0
            sta poly_i
            lda poly_tmp            ; A = ov
            asl                     ; A = (ov<<1)&$ff, C = ov bit7
            rol poly_i              ; poly_i:A = ov*2
            asl
            rol poly_i              ; poly_i:A = ov*4
                                    ; rol leaves C = old poly_i bit7 = 0,
                                    ; so the following adc doesn't need clc.
            adc poly_tmp            ; A = (ov*4 + ov) lo = (ov*5) lo
            sta poly_tmp            ; poly_tmp = ov*5 lo (reuse)
            lda poly_i
            adc #0                  ; hi of ov*5
            sta poly_i              ; poly_i  = ov*5 hi

            ; --- add running carry_in to ov*5
            clc
            lda poly_tmp
            adc poly_carry
            sta poly_tmp
            lda poly_i
            adc #0
            sta poly_i              ; (poly_i : poly_tmp) = ov*5 + carry_in

            ; --- add to h[.K], produce new carry_in for next k
            clc
            lda poly_h + .K
            adc poly_tmp
            sta poly_h + .K
            lda poly_i
            adc #0
            sta poly_carry          ; carry_in for iteration .K+1
        }

        rts

; =============================================================================
; poly1305_block - Process one 16-byte block
;
; Input: zp_ptr1 points to 16-byte block
;        A = high bit to add (1 for normal blocks, 0 for final partial)
;
; Operations: h += block (with high bit), then h *= r mod p
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_block:
        sta poly_carry          ; save high bit value

        ; h += block (16 bytes from (zp_ptr1))
        ; IMPORTANT: Use DEX/BNE for loop control — CPY clobbers carry,
        ; which would break carry propagation in the multi-byte addition.
        clc
        ldx #16                ; byte counter
        ldy #0
@add_block:
        lda poly_h,y
        adc (zp_ptr1),y
        sta poly_h,y
        iny
        dex
        bne @add_block

        ; h[16] += high bit + carry
        lda poly_h+16
        adc poly_carry
        sta poly_h+16

        ; h *= r mod p
        jsr poly1305_multiply
        rts

; =============================================================================
; poly1305_update - Process message data
;
; Input: zp_ptr1 = pointer to data, cc20_remain = length
;        (Reuses cc20_remain as a general byte counter)
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_update:
        lda cc20_remain
        beq @upd_done

@next_block:
        lda cc20_remain
        cmp #16
        bcc @last_block         ; < 16 bytes remaining = partial final block

        ; Full 16-byte block with high bit = 1
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

        lda cc20_remain
        sec
        sbc #16
        sta cc20_remain
        bne @next_block
        rts

@last_block:
        ; Partial block: copy to aead_scratch with padding
        ; Zero the scratch buffer first
        ldx #15
        lda #0
@zero_scratch:
        sta aead_scratch,x
        dex
        bpl @zero_scratch

        ; Copy remaining bytes
        ldy #0
        ldx cc20_remain
        beq @pad_done
@copy_partial:
        lda (zp_ptr1),y
        sta aead_scratch,y
        iny
        dex
        bne @copy_partial
@pad_done:
        ; Set 0x01 after the message bytes (at position n)
        ; This encodes the block as: data + 2^(8*n) per RFC 7539
        lda #$01
        sta aead_scratch,y

        ; Point zp_ptr1 to scratch buffer
        lda #<aead_scratch
        sta zp_ptr1
        lda #>aead_scratch
        sta zp_ptr1+1

        ; Process with high bit = 0 (the 0x01 in the buffer handles it)
        lda #0
        jsr poly1305_block

        lda #0
        sta cc20_remain

@upd_done:
        rts

; =============================================================================
; poly1305_final - Finalize Poly1305 tag
;
; 1. Full reduction of h mod 2^130-5
; 2. h += s
; 3. Output low 16 bytes to poly1305_tag
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_final:
        ; --- Full reduction mod 2^130 - 5 ---
        ; Check if h >= p = 2^130 - 5
        ; Compute h + 5, check if it overflows 2^130
        ; If so, use h + 5 (mod 2^130), otherwise keep h

        ; Add 5 to h, store result in poly_product as temp
        clc
        lda poly_h
        adc #5
        sta poly_product
        ldy #16                ; 16 remaining bytes (indices 1..16)
        ldx #1
@add5:
        lda poly_h,x
        adc #0
        sta poly_product,x
        inx
        dey                    ; DEY doesn't affect carry
        bne @add5

        ; Check if bit 130 is set in the result (byte 16, bit 2)
        lda poly_product+16
        and #$04
        beq @no_reduce          ; h + 5 < 2^130, keep h as is

        ; h >= p, use reduced value (mask to 130 bits)
        ldx #0
@use_reduced:
        lda poly_product,x
        sta poly_h,x
        inx
        cpx #16
        bcc @use_reduced
        lda poly_product+16
        and #$03               ; mask to 2 bits (130 bits total)
        sta poly_h+16

@no_reduce:
        ; --- Add s to h ---
        clc
        ldy #16                ; 16 bytes
        ldx #0
@add_s:
        lda poly_h,x
        adc poly_s,x
        sta poly_h,x
        inx
        dey                    ; DEY doesn't affect carry
        bne @add_s

        ; --- Output tag: low 16 bytes of h ---
        ldx #0
@output:
        lda poly_h,x
        sta poly1305_tag,x
        inx
        cpx #16
        bcc @output
        rts
