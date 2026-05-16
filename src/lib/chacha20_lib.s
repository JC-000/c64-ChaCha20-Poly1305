; =============================================================================
; chacha20_lib.s - ChaCha20 stream cipher (RFC 7539/8439)
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

.include "constants_lib.s"

; Cross-module imports: word32 primitives used by the test-only
; chacha20_quarter_round entry point below.
.import add32_to_dst, xor32_in_place
.import rotr32_16, rotl32_12, rotl32_8, rotl32_7

; Cross-module imports: data_lib state (main-RAM, not ZP).
.import cc20_state, cc20_key, cc20_nonce, cc20_counter, cc20_remain_hi

; Cross-module imports: page-aligned nibble-swap LUTs used by the C4
; branchless rotl32_4_zp macro. Defined in data_lib.s.
.import chacha_nibswap_hi_tab, chacha_nibswap_lo_tab

.export chacha20_init, chacha20_block, chacha20_quarter_round
.export chacha20_encrypt
.export cc20_qr_table, cc20_constants

.segment "CODE"

; --- ChaCha20 constants ("expand 32-byte k" as LE uint32 words) ---
cc20_constants:
        .byte $65, $78, $70, $61     ; 0x61707865 "expa" (LE)
        .byte $6e, $64, $20, $33     ; 0x3320646e "nd 3" (LE)
        .byte $32, $2d, $62, $79     ; 0x79622d32 "2-by" (LE)
        .byte $74, $65, $20, $6b     ; 0x6b206574 "te k" (LE)

; --- Quarter-round index table (retained for test suite compatibility) ---
; The main chacha20_block hot path no longer uses this table — it inlines
; all 8 quarter-rounds per double-round with literal indices. The table
; and the `chacha20_quarter_round` entry point below are kept so the
; dynamic-index test vector in `tools/test_chacha20_poly1305.py` can still
; patch in arbitrary (a,b,c,d) tuples and exercise a single QR.
cc20_qr_table:
        ; Column rounds
        .byte  0,  4,  8, 12          ; QR(0, 4, 8, 12)
        .byte  1,  5,  9, 13          ; QR(1, 5, 9, 13)
        .byte  2,  6, 10, 14          ; QR(2, 6, 10, 14)
        .byte  3,  7, 11, 15          ; QR(3, 7, 11, 15)
        ; Diagonal rounds
        .byte  0,  5, 10, 15          ; QR(0, 5, 10, 15)
        .byte  1,  6, 11, 12          ; QR(1, 6, 11, 12)
        .byte  2,  7,  8, 13          ; QR(2, 7,  8, 13)
        .byte  3,  4,  9, 14          ; QR(3, 4,  9, 14)

; =============================================================================
; Inlined 32-bit op macros against literal ZP addresses
;
; Each macro takes one or two 4-byte ZP word bases (literal expressions the
; assembler evaluates at build time, e.g. cc20_work+4*0). All addressing is
; direct ZP (3 cy LDA/STA) — no (ptr),y (5 cy).
; =============================================================================

; w[dst] += w[src]  — 32-bit little-endian add-in-place
.macro add32_zp dst, src
        clc
        lda dst
        adc src
        sta dst
        lda dst+1
        adc src+1
        sta dst+1
        lda dst+2
        adc src+2
        sta dst+2
        lda dst+3
        adc src+3
        sta dst+3
.endmacro

; w[dst] ^= w[src]  — 32-bit xor-in-place
.macro xor32_zp dst, src
        lda dst
        eor src
        sta dst
        lda dst+1
        eor src+1
        sta dst+1
        lda dst+2
        eor src+2
        sta dst+2
        lda dst+3
        eor src+3
        sta dst+3
.endmacro

; w[dst] <<<= 16  — swap halves of LE word: [b0 b1 b2 b3] -> [b2 b3 b0 b1]
; Uses Y as a temp (preserves X). Two independent byte swaps.
.macro rotl32_16_zp dst
        lda dst
        ldy dst+2
        sty dst
        sta dst+2
        lda dst+1
        ldy dst+3
        sty dst+1
        sta dst+3
.endmacro

; w[dst] <<<= 8  — LE byte rotate left by 8: [b0 b1 b2 b3] -> [b3 b0 b1 b2]
; new_b0 = old_b3, new_b1 = old_b0, new_b2 = old_b1, new_b3 = old_b2
.macro rotl32_8_zp dst
        ldy dst+3             ; save b3
        lda dst+2
        sta dst+3             ; b3' = b2
        lda dst+1
        sta dst+2             ; b2' = b1
        lda dst
        sta dst+1             ; b1' = b0
        sty dst               ; b0' = old b3
.endmacro

; w[dst] <<<= 4  — LE nibble rotate left by 4 (C4: branchless LUT form).
;   new_b0 = (b0 << 4) | (b3 >> 4)
;   new_b1 = (b1 << 4) | (b0 >> 4)
;   new_b2 = (b2 << 4) | (b1 >> 4)
;   new_b3 = (b3 << 4) | (b2 >> 4)
; Stitches two 256-byte page-aligned LUTs (chacha_nibswap_hi_tab,
; chacha_nibswap_lo_tab) across the four bytes in straight-line code.
; Each (lda abs,x) is 4 cy with no page-cross penalty thanks to .align 256
; — preserves CT (X is derived from secret state).
;
; Pre-save b3>>4 into zp_tmp1 (wraps into new_b0), then walk b3..b0:
; each step keeps X = old b_i across the two LUT reads (hi_tab[b_i],
; lo_tab[b_{i-1}]) before X is reloaded with b_{i-1}. 80 cy total
; (vs ~124 cy for the prior asl/lsr/ora chain). Clobbers A and X.
.macro rotl32_4_zp dst
        ; Save (b3 >> 4) — wraps into new_b0's low nibble.
        ldx dst+3
        lda chacha_nibswap_lo_tab,x
        sta zp_tmp1

        ; new_b3 = (b3 << 4) | (b2 >> 4)
        lda chacha_nibswap_hi_tab,x   ; b3 << 4 (X still = old b3)
        sta dst+3                      ; park hi half
        ldx dst+2
        lda chacha_nibswap_lo_tab,x   ; b2 >> 4
        ora dst+3
        sta dst+3

        ; new_b2 = (b2 << 4) | (b1 >> 4)
        lda chacha_nibswap_hi_tab,x   ; b2 << 4 (X still = old b2)
        sta dst+2                      ; park hi half
        ldx dst+1
        lda chacha_nibswap_lo_tab,x   ; b1 >> 4
        ora dst+2
        sta dst+2

        ; new_b1 = (b1 << 4) | (b0 >> 4)
        lda chacha_nibswap_hi_tab,x   ; b1 << 4 (X still = old b1)
        sta dst+1                      ; park hi half
        ldx dst
        lda chacha_nibswap_lo_tab,x   ; b0 >> 4
        ora dst+1
        sta dst+1

        ; new_b0 = (b0 << 4) | (b3 >> 4 from zp_tmp1)
        lda chacha_nibswap_hi_tab,x   ; b0 << 4 (X still = old b0)
        ora zp_tmp1
        sta dst
.endmacro

; w[dst] <<<= 12  — rotl8 then rotl4
.macro rotl32_12_zp dst
        rotl32_8_zp dst
        rotl32_4_zp dst
.endmacro

; w[dst] <<<= 1  — 32-bit rotate left by 1 (LE: start from LSB).
; F2 fix (v0.3.0 CT): branchless. Pre-extract the wrap bit (old bit 31
; of dst) into C via asl on dst+3, then rol-rmw the four bytes. The
; wrap bit feeds back in as the new LSB of dst via the initial rol.
; CT: no data-dependent branches. Also a net win vs the old
; lda/rol/sta cascade (25 cy vs 37/44 cy old best/worst).
.macro rotl32_1_zp dst
        lda dst+3
        asl             ; C = old bit 31 of dst
        rol dst         ; dst:   (old<<1) | C_in; C_out = old bit 7
        rol dst+1
        rol dst+2
        rol dst+3
.endmacro

; w[dst] >>>= 1  — 32-bit rotate right by 1.
; F2 fix (v0.3.0 CT): branchless. Pre-extract the wrap bit (old bit 0
; of dst) into C via lsr on dst, then ror-rmw from dst+3 down. The
; wrap bit feeds back in as the new MSB of dst+3.
; Note on naming: this macro is still called from rotl32_7_zp (rotl8
; then rotr1) to realise ChaCha20's <<< 7.
.macro rotr32_1_zp dst
        lda dst
        lsr             ; C = old bit 0 of dst
        ror dst+3
        ror dst+2
        ror dst+1
        ror dst
.endmacro

.macro rotl32_7_zp dst
        rotl32_8_zp dst
        rotr32_1_zp dst
.endmacro

; =============================================================================
; Permuted-read add/xor macros
;
; These emit a 32-bit add or xor where the destination and/or source word
; is accessed with a byte-offset permutation (implementing a byte-level
; rotate-left as a compile-time rename). Parameters are the four physical
; byte offsets from the base for logical byte 0,1,2,3.
;
; Convention: P[j] is the physical offset (relative to the word base) of
; logical byte j. For natural order P = (0,1,2,3). For rotl-8 renamed,
; P = (3,0,1,2). For rotl-16, P = (2,3,0,1). For rotl-24, P = (1,2,3,0).
;
; The carry chain (for add) still flows from logical byte 0 → 3.
; =============================================================================

; dst ^= src (both with permutations).
.macro xor32_perm dst, dp0, dp1, dp2, dp3, src, sp0, sp1, sp2, sp3
        lda dst + dp0
        eor src + sp0
        sta dst + dp0
        lda dst + dp1
        eor src + sp1
        sta dst + dp1
        lda dst + dp2
        eor src + sp2
        sta dst + dp2
        lda dst + dp3
        eor src + sp3
        sta dst + dp3
.endmacro

; dst += src (both with permutations). Carry chain flows low→high logically.
.macro add32_perm dst, dp0, dp1, dp2, dp3, src, sp0, sp1, sp2, sp3
        clc
        lda dst + dp0
        adc src + sp0
        sta dst + dp0
        lda dst + dp1
        adc src + sp1
        sta dst + dp1
        lda dst + dp2
        adc src + sp2
        sta dst + dp2
        lda dst + dp3
        adc src + sp3
        sta dst + dp3
.endmacro

; End-of-QR normalization: copy a word from offset-permuted physical layout
; back to natural byte order. Writes logical[j] = phys[P[j]] into phys[j].
; For rotl-16 (P=2,3,0,1) this is a half-swap. For rotl-8 (P=3,0,1,2) it's
; a 4-byte cycle. Uses Y as temp to free A/X.
;
; Since rotl-16 is a symmetric swap, we can do it in place with two pairs
; of byte swaps. For rotl-8 / rotl-24, we cycle through 4 bytes using Y
; as a single-register scratch.

.macro normalize_rot16 base
        ; P = (2,3,0,1): swap b[0]<->b[2], b[1]<->b[3]
        lda base+0
        ldy base+2
        sty base+0
        sta base+2
        lda base+1
        ldy base+3
        sty base+1
        sta base+3
.endmacro

.macro normalize_rot24 base
        ; Current P = (1,2,3,0): logical[j] = phys[(j+1) mod 4].
        ; We want phys[j] := logical[j] for all j.
        ; new_phys[0] = old_phys[1]
        ; new_phys[1] = old_phys[2]
        ; new_phys[2] = old_phys[3]
        ; new_phys[3] = old_phys[0]
        ldy base+0             ; save old phys[0]
        lda base+1
        sta base+0
        lda base+2
        sta base+1
        lda base+3
        sta base+2
        sty base+3
.endmacro

; =============================================================================
; Quarter-round macro (C3: rot-8/16 as offset rename)
;
; QR(a, b, c, d) where a,b,c,d are word *indices* (0..15). All words start
; at natural byte order (P=(0,1,2,3)). Byte-aligned rotations are absorbed
; into the byte offsets of subsequent reads/writes. Rot-12 = rename-8 +
; phys rotl-4; rot-7 = rename-8 + phys rotr-1. At QR end, we normalize b
; (cumulative R=16) and d (cumulative R=24) back to natural order.
;
; Cumulative offset trace:
;   start:                     R_a=0  R_b=0  R_c=0  R_d=0
;   a+=b; d^=a; d<<<=16        R_a=0  R_b=0  R_c=0  R_d=16
;   c+=d; b^=c; b<<<=12        R_a=0  R_b=8  R_c=0  R_d=16   (+rotl4 on phys-b)
;   a+=b; d^=a; d<<<=8         R_a=0  R_b=8  R_c=0  R_d=24
;   c+=d; b^=c; b<<<=7         R_a=0  R_b=16 R_c=0  R_d=24   (+rotr1 on phys-b)
;   normalize b (R=16), d (R=24) → all natural
;
; Permutation table per R (multiple of 8):
;   R=0  : (0,1,2,3)   natural
;   R=8  : (3,0,1,2)   rotl-8  renamed
;   R=16 : (2,3,0,1)   rotl-16 renamed
;   R=24 : (1,2,3,0)   rotl-24 renamed
; =============================================================================
; cc20_qr — shared QR body.
;
; Implemented as two halves so that `cc20_qr_first` (C5 site 2, first column
; round of the first double-round) can substitute its own immediate-baked
; step-1 prelude and then reuse the shared steps 2..4 via `cc20_qr_body_rest`.
; `cc20_qr` itself just emits the normal step 1 + body-rest.
; =============================================================================

; Step 1: a += b; d ^= a; d <<<= 16 (natural-order version).
.macro cc20_qr_step1 ia, ib, id
        add32_zp    cc20_work+4*ia, cc20_work+4*ib
        xor32_zp    cc20_work+4*id, cc20_work+4*ia
        ; R_d = 16 (pure rename, no code).
.endmacro

; Steps 2..4 + normalize. Shared by cc20_qr and cc20_qr_first.
.macro cc20_qr_body_rest ia, ib, ic, id
        ; --- 2. c += d;   b ^= c;   b <<<= 12 ---
        ; d is at R=16, P=(2,3,0,1). c, b natural.
        add32_perm  cc20_work+4*ic, 0,1,2,3, cc20_work+4*id, 2,3,0,1
        xor32_zp    cc20_work+4*ib, cc20_work+4*ic
        ; b <<<= 12 = rename-8 (R_b += 8 → 8) + phys rotl-4
        rotl32_4_zp cc20_work+4*ib
        ; R_b = 8, R_d = 16

        ; --- 3. a += b;   d ^= a;   d <<<= 8 ---
        ; b at R=8, P=(3,0,1,2). d at R=16, P=(2,3,0,1). a natural.
        add32_perm  cc20_work+4*ia, 0,1,2,3, cc20_work+4*ib, 3,0,1,2
        xor32_perm  cc20_work+4*id, 2,3,0,1, cc20_work+4*ia, 0,1,2,3
        ; d <<<= 8 rename: R_d = 16 + 8 = 24, P=(1,2,3,0)
        ; R_b = 8, R_d = 24

        ; --- 4. c += d;   b ^= c;   b <<<= 7 ---
        ; d at R=24, P=(1,2,3,0). b at R=8, P=(3,0,1,2). c natural.
        add32_perm  cc20_work+4*ic, 0,1,2,3, cc20_work+4*id, 1,2,3,0
        xor32_perm  cc20_work+4*ib, 3,0,1,2, cc20_work+4*ic, 0,1,2,3
        ; b <<<= 7 = rename-8 (R_b += 8 → 16) + phys rotr-1
        rotr32_1_zp cc20_work+4*ib
        ; R_b = 16, R_d = 24

        ; --- End of QR: normalize b and d back to natural order ---
        normalize_rot16 cc20_work+4*ib
        normalize_rot24 cc20_work+4*id
.endmacro

.macro cc20_qr ia, ib, ic, id
        cc20_qr_step1      ia, ib, id
        cc20_qr_body_rest  ia, ib, ic, id
.endmacro

; =============================================================================
; cc20_qr_first — C5 site 2 variant of cc20_qr.
;
; Used ONLY in the first column round of the first double-round, where the
; `a` operand (cc20_work[4*ia] for ia ∈ {0,1,2,3}) is still the expand-32-byte-k
; constant word. Each `a += b` step here reads the a-operand as an immediate
; via `lda #imm_b<n>` instead of `lda cc20_work+4*ia+n`.
;
; Paper check (why this is safe):
;   - chacha20_block prelude copies cc20_state → cc20_work. Row 0 of cc20_state
;     (words 0..3) is initialised by chacha20_init to the 16 "expand 32-byte k"
;     bytes (see cc20_constants: $65 $78 $70 $61 $6e $64 $20 $33 $32 $2d $62 $79
;     $74 $65 $20 $6b). These bytes do not change between chacha20_init and the
;     start of the first double-round — nothing writes to cc20_state[0..15] in
;     the window between.
;   - The first column round is QR(0,4,8,12), QR(1,5,9,13), QR(2,6,10,14),
;     QR(3,7,11,15). The `a` operand of QR k is word k (k ∈ {0,1,2,3}) —
;     exactly row 0.
;   - QR k's very first operation is `a += b`, which READS cc20_work[4*k..+3]
;     (still the expand constant) before writing to it. The subsequent writes
;     clobber row 0 word k; but QR k+1 reads word k+1, which QR k did NOT
;     touch (QR k's destinations are words k, k+12, k+8, k+4, disjoint from
;     {k+1, k+2, k+3}). Therefore all four QRs in this first column round
;     see their row-0 word still equal to the expand constant at the moment
;     of the baked read.
;   - After the first column round completes, row 0 is irrevocably scrambled,
;     so this bake applies to EXACTLY these four sites and nowhere else.
;
; The parameters b0..b3 are the four little-endian bytes of the expand
; constant word that equals cc20_state[4*ia..4*ia+3].
; =============================================================================
.macro cc20_qr_first ia, ib, ic, id, b0, b1, b2, b3
        ; --- 1. a += b;   d ^= a;   d <<<= 16 ---
        ; C5 site 2: bake a-operand reads as immediates. Replaces four
        ; `lda cc20_work+4*ia+n` (3 cy ZP) with `lda #imm` (2 cy), −4 cy / QR.
        clc
        lda #b0
        adc cc20_work+4*ib+0
        sta cc20_work+4*ia+0
        lda #b1
        adc cc20_work+4*ib+1
        sta cc20_work+4*ia+1
        lda #b2
        adc cc20_work+4*ib+2
        sta cc20_work+4*ia+2
        lda #b3
        adc cc20_work+4*ib+3
        sta cc20_work+4*ia+3
        xor32_zp    cc20_work+4*id, cc20_work+4*ia
        ; R_d = 16
        cc20_qr_body_rest  ia, ib, ic, id
.endmacro

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
.macro cc20_set_dst tbl_off
        ldx cc20_qr_idx
        lda cc20_qr_table+tbl_off,x
        asl
        asl                    ; *4 for byte offset
        clc
        adc #<cc20_work
        sta w32_dst
        lda #>cc20_work
        adc #0
        sta w32_dst+1
.endmacro

.macro cc20_set_src1 tbl_off
        ldx cc20_qr_idx
        lda cc20_qr_table+tbl_off,x
        asl
        asl
        clc
        adc #<cc20_work
        sta w32_src1
        lda #>cc20_work
        adc #0
        sta w32_src1+1
.endmacro

chacha20_quarter_round:
        cc20_set_src1 1
        cc20_set_dst 0
        jsr add32_to_dst        ; a += b

        cc20_set_src1 0
        cc20_set_dst 3
        jsr xor32_in_place      ; d ^= a
        jsr rotr32_16           ; d <<<= 16

        cc20_set_src1 3
        cc20_set_dst 2
        jsr add32_to_dst        ; c += d

        cc20_set_src1 2
        cc20_set_dst 1
        jsr xor32_in_place      ; b ^= c
        jsr rotl32_12           ; b <<<= 12

        cc20_set_src1 1
        cc20_set_dst 0
        jsr add32_to_dst        ; a += b

        cc20_set_src1 0
        cc20_set_dst 3
        jsr xor32_in_place      ; d ^= a
        jsr rotl32_8            ; d <<<= 8

        cc20_set_src1 3
        cc20_set_dst 2
        jsr add32_to_dst        ; c += d

        cc20_set_src1 2
        cc20_set_dst 1
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
        ; 1. Copy state → work (64 bytes).
        ;    C8: straight-line unrolled state→work prelude (was a 64-iter
        ;        ldx / abs,x / zp,x / dex / bpl loop — ~13 cy × 64 ≈ 832 cy).
        ;    C5 site 1: for row 0 (bytes 0..15) the source is the fixed
        ;        "expand 32-byte k" constant, so use `lda #imm` (2 cy) in
        ;        place of `lda cc20_state+n` (4 cy abs). Row-0 byte values
        ;        are the little-endian encoding of
        ;          state[0]=0x61707865 ("expa") -> $65 $78 $70 $61
        ;          state[1]=0x3320646e ("nd 3") -> $6e $64 $20 $33
        ;          state[2]=0x79622d32 ("2-by") -> $32 $2d $62 $79
        ;          state[3]=0x6b206574 ("te k") -> $74 $65 $20 $6b
        ;        These match cc20_constants[] above byte-for-byte.
        lda #$65
        sta cc20_work+0
        lda #$78
        sta cc20_work+1
        lda #$70
        sta cc20_work+2
        lda #$61
        sta cc20_work+3
        lda #$6e
        sta cc20_work+4
        lda #$64
        sta cc20_work+5
        lda #$20
        sta cc20_work+6
        lda #$33
        sta cc20_work+7
        lda #$32
        sta cc20_work+8
        lda #$2d
        sta cc20_work+9
        lda #$62
        sta cc20_work+10
        lda #$79
        sta cc20_work+11
        lda #$74
        sta cc20_work+12
        lda #$65
        sta cc20_work+13
        lda #$20
        sta cc20_work+14
        lda #$6b
        sta cc20_work+15

        ; Rows 1..3: unrolled plain copies (C8). 48 × (4 + 3) = 336 cy.
.repeat 48, i
        lda cc20_state+16+i
        sta cc20_work+16+i
.endrepeat

        ; 2. 10 double-rounds.
        ;    NOTE: C5 site 2 (baked row-0 a-operand in first column round)
        ;    was evaluated but NOT shipped. Rationale: hoisting the first
        ;    column round out of the loop to attach the baked a-operand
        ;    duplicates ≥ 4 QRs of inlined code (~1400 B extra) or the
        ;    full first double-round (8 QRs, ~2900 B extra), for a
        ;    measured saving of only ~16 cy/block. The per-block saving
        ;    is dominated by the PRG size growth, which pushes the BSS
        ;    tail past the benchmark plaintext buffer at $5000 and would
        ;    require relocating pt_addr sitewide. Sites 1 (row-0 imm
        ;    state→work) and 3 (row-0 imm work+=state) ship; site 2 is
        ;    deferred to a future step with a different shape (e.g. SMC
        ;    patching the live cc20_qr expansions instead of duplicating
        ;    them). The cc20_qr_first macro and paper-check comment are
        ;    retained above for that future attempt.
        lda #10
        sta cc20_round
@double_round:
        ; --- Column rounds ---
        cc20_qr  0,  4,  8, 12
        cc20_qr  1,  5,  9, 13
        cc20_qr  2,  6, 10, 14
        cc20_qr  3,  7, 11, 15
        ; --- Diagonal rounds ---
        cc20_qr  0,  5, 10, 15
        cc20_qr  1,  6, 11, 12
        cc20_qr  2,  7,  8, 13
        cc20_qr  3,  4,  9, 14

        dec cc20_round
        beq @rounds_done
        jmp @double_round
@rounds_done:

        ; 3. Add initial state back: work[i] += state[i] for each of 64 bytes.
        ; Since cc20_work is ZP and both are little-endian byte arrays, we
        ; can add byte-by-byte with a single carry chain *per word*. Unroll
        ; as 16 × 4-byte adds against literal ZP addresses.
        ;
        ; Rows 1..3 (words 4..15): plain add against cc20_state (abs, 4 cy).
        ; Row 0 (words 0..3): C5 site 3 — the state bytes are the fixed
        ; expand-32-byte-k constants, so use `adc #imm` (2 cy) in place of
        ; `adc cc20_state+n` (4 cy abs), saving 2 cy × 16 = 32 cy.
.macro add_state_word i
        clc
        lda cc20_work+4*i
        adc cc20_state+4*i
        sta cc20_work+4*i
        lda cc20_work+4*i+1
        adc cc20_state+4*i+1
        sta cc20_work+4*i+1
        lda cc20_work+4*i+2
        adc cc20_state+4*i+2
        sta cc20_work+4*i+2
        lda cc20_work+4*i+3
        adc cc20_state+4*i+3
        sta cc20_work+4*i+3
.endmacro

; C5 site 3: work[i] += {b0,b1,b2,b3} where the four bytes are the known
; little-endian expand-32-byte-k constant word for row-0 index i ∈ {0..3}.
.macro add_state_word_imm i, b0, b1, b2, b3
        clc
        lda cc20_work+4*i
        adc #b0
        sta cc20_work+4*i
        lda cc20_work+4*i+1
        adc #b1
        sta cc20_work+4*i+1
        lda cc20_work+4*i+2
        adc #b2
        sta cc20_work+4*i+2
        lda cc20_work+4*i+3
        adc #b3
        sta cc20_work+4*i+3
.endmacro
        add_state_word_imm 0, $65, $78, $70, $61   ; "expa"
        add_state_word_imm 1, $6e, $64, $20, $33   ; "nd 3"
        add_state_word_imm 2, $32, $2d, $62, $79   ; "2-by"
        add_state_word_imm 3, $74, $65, $20, $6b   ; "te k"
        add_state_word 4
        add_state_word 5
        add_state_word 6
        add_state_word 7
        add_state_word 8
        add_state_word 9
        add_state_word 10
        add_state_word 11
        add_state_word 12
        add_state_word 13
        add_state_word 14
        add_state_word 15

        ; 4. (C7 / S8) Keystream copy elided. cc20_keystream is an alias
        ;    for cc20_work (see constants_lib.asm), so the 64-byte
        ;    work -> keystream copy that used to live here is a no-op.
        ;    Downstream callers read keystream bytes directly out of
        ;    the ZP working state.

        ; 5. Increment counter in state (word 12, bytes 48-51).
        ;    C6 (S8): kept here rather than folded into chacha20_encrypt.
        ;    A5 relies on chacha20_block's tail inc to prime cc20_state
        ;    with counter=1 for free after aead_derive_otk (counter
        ;    goes 0 -> 1 via this chain, so aead_encrypt / aead_decrypt
        ;    can skip their re-init). Moving the inc to the encrypt loop
        ;    would require A5 to add an explicit inc, cancelling C6's
        ;    savings — the per-block inc chain is already essentially
        ;    minimum-cost (taken branches only on wrap), so the
        ;    "fold" is net-zero in cycles. C6 is therefore noted but
        ;    not relocated; the cleanliness benefit is not worth the
        ;    coupling cost across aead_derive_otk / A5.
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
        ; D-chacha-2 (post-v0.5.0): count is in A; pass through X for the
        ; XOR loop counter. After the loop, Y == count (it counted up while
        ; X counted down), so we can drive the pointer-advance off TYA and
        ; only stash count to cc20_buf_pos once for the sbc step below.
        ; Saves the pre-loop `sta cc20_buf_pos` (replaced by a post-loop
        ; sty), and the data-pointer adc reads it from Y/A instead of
        ; cc20_buf_pos so we get a (tya:2) vs (lda zp:3) micro-win.
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
        ; X = 0, Y = count

        ; Advance data pointer (count is still in Y)
        tya
        clc
        adc cc20_data_ptr
        sta cc20_data_ptr
        lda cc20_data_ptr+1
        adc #0
        sta cc20_data_ptr+1

        ; 16-bit subtract processed bytes from remaining.
        ; Stash count into cc20_buf_pos once for the sbc operand.
        sty cc20_buf_pos
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
