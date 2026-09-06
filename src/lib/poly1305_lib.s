; =============================================================================
; poly1305_lib.asm - Poly1305 MAC (RFC 7539) — key schedule and boot half
;
; Imported verbatim from c64-wireguard/src/poly1305.asm as the baseline for
; C64 optimization. Public entry points: poly1305_init, poly1305_block,
; poly1305_update, poly1305_final. Uses a quarter-square lookup table at
; $8000-$83FF (built at runtime by mul_tables_init / sqtab_init).
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
; -----------------------------------------------------------------------------
; WHY THIS FILE IS ONE OF SIX (issue #108 item 2)
;
; c64-lib-contract SPEC §6.1 member isolation (v1.2.0; prefixed-counterpart
; carve-out v1.2.1; both collision directions named at v1.2.2):
;
;   "A symbol a consumer may displace ... MUST live in a translation unit
;    that exports nothing else a consumer may import — other displaceable
;    names included, their own prefixed counterparts excepted — and defines
;    nothing else the library's own code references."
;
; ld65 links whole archive members, so a displaceable name sharing a member
; with an entry point every consumer imports arrives in every link whether
; or not the consumer wants it. Until v0.10.0 this one file held BOTH the
; nine Poly1305 entry points AND the eight §8.1/§8.3 names an APP_OWNED
; consumer (or a sibling library) may define itself. It is now split, in
; emission order, so no member mixes the two categories:
;
;   poly1305_lib.s        this file — boot/key-schedule half: poly1305_lib_init,
;                         poly1305_init, poly1305_clamp, shoup_init (Profile A)
;   shared_sqtab_init.s   §8.1 mul_tables_init / sqtab_init + its sq_* scratch
;   shared_prod_scratch.s §8.3 poly_prod_lo / poly_prod_hi
;   mul_8x8_legacy.s      §8.3 back-compat mul_8x8 body + its mul_* scratch
;   shared_ct_mul.s       §8.3 ct_mul_8x8 + smc_sum_a_imm / smc_diff_a_imm
;   poly1305_core.s       arithmetic half: poly_ripple, poly1305_multiply,
;                         poly1305_reduce, poly1305_block/update/final
;
; THE SPLIT IS BYTE-NEUTRAL BY CONSTRUCTION. The six TUs contribute to
; LIB_CHACHA20_POLY1305_CODE in exactly the order the single file emitted
; them, and the Makefile lists their objects in that order on every link
; line, so all four profile PRGs are byte-identical to v0.10.0. Keep that
; order if you add to any of them.
;
; This half references the §8.1 init by its SPEC §8.1 CANONICAL name
; `mul_tables_init`, never by the historical `sqtab_init` alias, in every
; build. That is deliberate: a consumer that owns §8.1 defines
; `mul_tables_init`, and importing the canonical name is what lets ld65
; satisfy this reference from the consumer instead of dragging our own
; member in beside it.
; =============================================================================

.include "constants_lib.s"
.include "smc.inc"

; Cross-module imports: data_lib state.
.import poly_h, poly_r
.import sqtab_ready

.export poly1305_lib_init, poly1305_init, poly1305_clamp

; SPEC §8.1: the sqtab builder is a shared primitive and lives in
; src/lib/shared_sqtab_init.s. Import the CANONICAL name in every build —
; owner and deferral alike — so this TU never has to know which. See the
; header note above for why the canonical spelling rather than sqtab_init.
.ifndef POLY1305_PROFILE_LONG
.import mul_tables_init
.endif

.ifdef POLY1305_PROFILE_LONG
.export shoup_init
; Profile A no longer emits the 1 KB sqtab at $8000-$83FF, so the
; POLY1305_REU sqtab stash/restore plumbing (poly1305_reu_restore,
; poly1305_reu_sqtab_bank, poly1305_reu_sqtab_offset) is also gated
; out. Profile A consumers that previously imported these symbols
; should drop the imports — the sqtab the symbols managed no longer
; exists on Profile A. See issue #34 F1.
.endif

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)

; PAGE-ALIGN THIS SECTION. Nothing in this TU needs the alignment; it is
; here to reproduce v0.10.0's image byte-for-byte across the issue #108
; split, and removing it is a deliberate size decision, not a cleanup.
;
; ld65 aligns each object's contribution to a segment (its "section") to
; that section's own alignment, which ca65 derives from the widest `.align`
; inside it. Until #108 this file also carried poly1305_core.s's
; `.align 256` (for poly_reduce_shl6_tab), so poly1305_lib.o's whole
; section was page-aligned and ld65 padded up to $1B00 on Profile B before
; emitting poly1305_lib_init. Splitting the file moved that `.align` into
; another TU, which would have dropped this section to $1A48 and relocated
; five routines by 184 bytes — same PRG size, since the pad simply moves,
; but not the same bytes.
;
; Dropping this directive and letting the sections pack tightly would let
; poly_reduce_shl6_tab land a page EARLIER, shrinking every profile PRG by
; 256 B. That is a real saving and it is deliberately NOT taken here: #108
; is a member-isolation change and its verification bar is a byte-identical
; image. Take it as its own change, with its own re-measure of the five
; RESIDENT_BYTES literals.
        .align 256

; =============================================================================
; poly1305_lib_init - One-time library initialization (Step 10)
;
; Profile B: builds the 1 KB quarter-square lookup table at sqtab_lo/hi
; ($8000-$83FF). This table is a pure function of the platform (integer
; squares) — it never changes regardless of key, nonce, or r. Calling
; this once at application startup saves ~80-90 k cy on every subsequent
; poly1305_init / aead_encrypt / aead_decrypt call. Safe to call multiple
; times (idempotent via sqtab_ready flag).
;
; Profile A: no sqtab to build (issue #34 F1) — the body collapses to a
; bare rts. Retained as an exported entry point so consumers calling
; `jsr poly1305_lib_init` once at startup keep working on both profiles
; without source patching. shoup_init is still called from poly1305_init
; on every key change.
;
; Must be called at least once before any aead_encrypt / aead_decrypt
; on Profile B. (No-op on Profile A but still safe.)
;
; Clobbers: A, X, Y
; =============================================================================
poly1305_lib_init:
.ifndef POLY1305_PROFILE_LONG
        lda sqtab_ready
        bne @already_done       ; skip if already built
        jsr mul_tables_init      ; SPEC §8.1 canonical name (== sqtab_init)
        ; v0.3.0 CT fix: Profile B no longer builds sqtab2 or caches
        ; lmul0/lmul1 pointer high bytes — ct_mul_8x8 uses only sqtab_lo/hi
        ; via SMC-patched abs,x loads, no indirect-indexed pointers.
        lda #1
        sta sqtab_ready
@already_done:
.endif
        rts

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

.ifndef POLY1305_PROFILE_LONG
        ; 3. Build quarter-square table (skip if poly1305_lib_init already ran).
        ;    Profile B only — Profile A's shoup_init populates r_tab_{lo,hi}
        ;    via incremental ripple-add and does not consume sqtab. See
        ;    issue #34 F1.
        lda sqtab_ready
        bne @sqtab_done
        jsr mul_tables_init      ; SPEC §8.1 canonical name (== sqtab_init)
        lda #1
        sta sqtab_ready
@sqtab_done:
.endif

.ifdef POLY1305_PROFILE_LONG
        ; 4. Build Shoup per-r tables (Step 6 / P3, Profile A only).
        ;    Step 11 rewrote shoup_init to use a per-j incremental
        ;    ripple-add (~118 k cy) instead of the 4096-call mul_8x8
        ;    loop (~438 k cy) — sqtab is no longer required, and as
        ;    of issue #34 F1 is not even emitted on Profile A.
        jsr shoup_init
.endif
        rts

.ifdef POLY1305_PROFILE_LONG
; =============================================================================
; shoup_init - Populate r_tab_lo / r_tab_hi with T_j[k] = k * r[j]
;
; For each j in 0..15, for each k in 0..255:
;   (hi,lo) = k * r[j]   (16-bit)
;   r_tab_lo + j*256 + k = lo
;   r_tab_hi + j*256 + k = hi
;
; Called from poly1305_init AFTER poly1305_clamp and mul_tables_init.
;
; Step 11: replaced the 4096-call mul_8x8 loop (~438 k cy) with a per-j
; incremental ripple-add loop. For fixed j,
;   T_j[0] = 0
;   T_j[k] = T_j[k-1] + r[j]   (16-bit running sum)
; Max k*r[j] = 255*255 = 65025 = $FE01, so the hi byte never reaches
; $FF and the hi-byte ripple (`adc #0`) can never itself carry out.
; That means carry entering each loop iteration is always clear — a
; single `clc` before the k=1 step suffices for all 255 iterations.
;
; The inner loop reads T_j[k-1] (just written the previous iteration)
; via `lda r_tab_{lo,hi}_base-1, y` with y=k, and writes T_j[k] via
; `sta r_tab_{lo,hi}_base, y`. The base-1 load pays a fixed page-cross
; penalty (5 cy instead of 4) but avoids any register-juggling around
; the missing `stx abs,y` opcode. Using memory itself as the feed-
; forward storage keeps Y free as the index register.
;
; Self-modifies (all once per outer j):
;   - the inner `adc #rj` immediate (shoup_rj_val+1)
;   - four page bytes on the four `r_tab_{lo,hi}{load,store}` sites
;     (shoup_ld_lo, shoup_sta_lo, shoup_ld_hi, shoup_sta_hi)
;   - one page byte on the initial T_j[0] store (shoup_z_lo, shoup_z_hi)
;
; Cost: 29 cy per inner entry vs ~107 cy for mul_8x8 path. 16 j × 255
; inner steps × 29 cy ≈ 118 k cy vs ~438 k cy. Saves ~320 k cy on
; aead_encrypt for all n.
;
; Clobbers: A, X, Y
; =============================================================================
shoup_init:
        lda #0
        sta poly_j              ; reuse as j counter (0..15)
shoup_j_loop:
        ; Patch the six SMC page bytes to (r_tab_{lo,hi} + j*256).
        ; The `abs-1,y` read sites were assembled with high byte
        ; `>r_tab_{lo,hi} - 1` (since r_tab is page-aligned, base-1 is
        ; on the prior page). For table j we therefore patch them with
        ; `>r_tab_{lo,hi} - 1 + j` (i.e. the store page minus 1).
        lda poly_j
        clc
        adc #>r_tab_lo
        SMC_StoreHighByte shoup_z_lo
        SMC_StoreHighByte shoup_sta_lo
        sec
        sbc #1
        SMC_StoreHighByte shoup_ld_lo
        lda poly_j
        clc
        adc #>r_tab_hi
        SMC_StoreHighByte shoup_z_hi
        SMC_StoreHighByte shoup_sta_hi
        sec
        sbc #1
        SMC_StoreHighByte shoup_ld_hi

        ; Patch the inner `adc #rj` immediate to r[j].
        ldy poly_j
        lda poly_r,y
        SMC_StoreValue shoup_rj_val

        ; Seed T_j[0] = 0.
        ldy #0
        tya                     ; A = 0
        SMC shoup_z_lo, { sta r_tab_lo,y }   ; SMC high byte — T_j[0].lo = 0
        SMC shoup_z_hi, { sta r_tab_hi,y }   ; SMC high byte — T_j[0].hi = 0

        ; k-loop: Y runs k = 1..255, wraps to 0 to exit. Carry is clear
        ; entering the loop and is always clear at the bottom (because
        ; max hi = $FE, so `adc #0` for hi can never carry out).
        iny                     ; Y = 1
        clc
; The two `r_tab_*-1, y` loads below have a base low byte of $FF, so they
; cross a page on EVERY iteration — deliberately, and harmlessly. Y here is
; the public loop counter k = 1..255, not a secret: the page cross is
; unconditional rather than data-dependent, so it costs a fixed extra cycle
; per iteration and leaks nothing. This is the one indexed access in the
; library whose base is not page-aligned, and it is safe for a different
; reason than the aligned tables are — recorded so it reads as a decision
; rather than an oversight the CT audit missed.
shoup_k_loop:
        SMC shoup_ld_lo,  { lda r_tab_lo-1, y } ; SMC high byte — prev_lo = T_j[k-1]
        SMC shoup_rj_val, { adc #$00 }          ; SMC immediate = r[j]
        SMC shoup_sta_lo, { sta r_tab_lo,y }    ; SMC high byte — T_j[k].lo
        SMC shoup_ld_hi,  { lda r_tab_hi-1, y } ; SMC high byte — prev_hi = T_j[k-1].hi
        adc #$00                                ; + ripple carry from lo add
        SMC shoup_sta_hi, { sta r_tab_hi,y }    ; SMC high byte — T_j[k].hi
        iny
        bne shoup_k_loop        ; 255 iterations (y wraps 1..255 → 0)

        inc poly_j
        lda poly_j
        cmp #16
        bne shoup_j_loop
        rts
.endif

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
