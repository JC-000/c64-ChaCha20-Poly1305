; =============================================================================
; lib/constants_lib.s - ChaCha20-Poly1305 library equates
;
; ZP + shared equates used by the ChaCha20-Poly1305 library only.
; No KERNAL / PETSCII / hardware references. No code emitted.
;
; Each ZP equate is wrapped in .ifndef so a host project can pre-define its
; own ZP layout before .include'ing this file.
; =============================================================================

; --- General-purpose ZP pointers / scratch ---
.ifndef zp_tmp1
  zp_tmp1  = $02                        ; temp byte (word32 nibble rotates)
.endif
.ifndef zp_tmp2
  zp_tmp2  = $03                        ; temp byte (word32 nibble rotates)
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
  cc20_qr_idx   = $15                  ; quarter-round parameter index
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

; --- ChaCha20 working state (64 bytes, ZP-resident per Step 1 / C1) ---
; Placed at $40..$7f — clear of $02-$1d (chacha/poly/word32 scratch) and
; $fb-$fe (generic pointer pair). The entire 16-word working state is the
; hot inner loop of chacha20_block; keeping it in ZP turns every
; (w32_dst),y indirect into a zero-page indirect whose target lives in ZP,
; and turns the `sta cc20_work,x` direct stores into zp,x addressing
; (4 cy vs 5 cy absolute,x). The host project may override if it wants
; to place cc20_work elsewhere in ZP.
.ifndef cc20_work
  cc20_work     = $40                   ; 64 bytes: $40..$7f
.endif

; C7 (S8): cc20_keystream is an alias for cc20_work. chacha20_block used
; to copy its 64-byte result out of cc20_work into a separate RAM buffer
; named cc20_keystream, so downstream consumers (chacha20_encrypt XOR
; loop, aead_derive_otk's poly_r/poly_s copies, the test-suite read of
; the block output) would read from the buffer instead of the ZP
; working state. That 64-byte copy costs ~256 cy per block with no
; upside — the keystream bytes are *already* sitting in cc20_work at
; the end of the round-add step, and every consumer is happy to read
; them from there. Aliasing the label eliminates the copy pass and
; reclaims 64 bytes of RAM in data_lib.
.ifndef cc20_keystream
  cc20_keystream = cc20_work
.endif

; --- Poly1305 ZP ---
.ifndef poly_i
  poly_i     = $1a                      ; outer loop counter
.endif
.ifndef poly_j
  poly_j     = $1b                      ; inner loop counter
.endif
.ifndef poly_carry
  poly_carry = $1c                      ; carry byte for multi-precision arith
.endif
.ifndef poly_tmp
  poly_tmp   = $1d                      ; temp for multiply
.endif

; --- Profile B ct_mul_8x8 ZP scratch (v0.3.0 CT fix, Profile B only) ---
; The branchless constant-time 8×8 multiply primitive needs two bytes of
; scratch during sign-mask absolute-value computation. Placed in the
; old lmul0/lmul1 slot (Step 12 mult66 pointers, deleted in the CT fix).
; Net ZP delta from pre-CT-fix: −2 bytes.
.ifndef ct_diff_raw
  ct_diff_raw  = $1e                    ; 1-byte scratch: raw b-a (pre-sign)
.endif
.ifndef ct_sign_mask
  ct_sign_mask = $1f                    ; 1-byte scratch: $00 if b>=a else $FF
.endif

; --- General-purpose 16-bit pointers used by poly1305 / aead ---
.ifndef zp_ptr1
  zp_ptr1 = $fb                         ; 2-byte pointer ($fb-$fc)
.endif
.ifndef zp_ptr2
  zp_ptr2 = $fd                         ; 2-byte pointer ($fd-$fe)
.endif

; --- Build profile flag -----------------------------------------------------
; POLY1305_PROFILE_LONG selects "Profile A" (long-message / REU-assisted,
; primary optimization target) vs "Profile B" (stock C64, no REU, portable
; baseline). Profile A is the default.
;
; Steps 6 and 7 will gate their new code paths on .ifdef POLY1305_PROFILE_LONG
; so that Profile B continues to assemble and pass the test suite without
; the Shoup per-r tables (Step 6) or the Donna-style fused wrap reduction
; (Step 7). At Step 5 this flag is scaffold-only: no runtime code consumes it.
;
; Select via the Makefile:
;   make profile-a   -> ca65 -DPOLY1305_PROFILE_LONG=1 ...  (default)
;   make profile-b   -> ca65 ...                            (flag undefined)
;
; Step 6 note: prior to Step 6 this file defaulted POLY1305_PROFILE_LONG
; on when no `-D` was passed (so Profile B *via default* was identical
; to Profile A). Once Step 6 introduces real Profile-A-only code (Shoup
; per-r tables), that default would silently force Profile A on any
; caller that simply .include's this library. The default is therefore
; removed: callers that want Profile A must pass `-DPOLY1305_PROFILE_LONG=1`
; to ca65, which the top-level Makefile's `profile-a` target already
; does. Absence of the symbol selects Profile B (portable baseline).

; --- Shoup per-r tables (Profile A only) ---
; Step 6 (P3): precompute T_j[x] = x * r[j] as a 16-bit value for each
; j in 0..15, so the inner multiply becomes two table lookups per
; partial product instead of an 8x8 multiply via sqtab.
;
; Layout: 8 KB contiguous at $6000..$7FFF, page-aligned per limb.
;   r_tab_lo + j*256  -> 256 low bytes  of (x * r[j]) for x = 0..255
;   r_tab_hi + j*256  -> 256 high bytes of (x * r[j]) for x = 0..255
;
; The region fits between the bench plaintext window ($5000..$53FF
; for 1024-byte messages) and the quarter-square sqtab ($8000..$83FF),
; both of which remain in use. sqtab is retained because shoup_init
; itself calls mul_8x8 (which reads sqtab) to populate the tables.
;
; These are *reservations of address space only* — the tables are
; initialized at runtime by shoup_init (called from poly1305_init),
; so the PRG image does not grow by 8 KB of zeros.
.ifdef POLY1305_PROFILE_LONG
    r_tab_lo = $6000
    r_tab_hi = $7000

; --- REU DMA layout (Profile A + POLY1305_REU only) ---
; When POLY1305_REU is defined, poly1305_lib_init stashes the 1 KB
; quarter-square table to REU so that poly1305_reu_restore can reload
; it in ~1.1k cycles if external code clobbers $8000..$83FF. The
; destination bank/offset are overridable so that downstream projects
; linking multiple REU consumers (e.g. both this library and
; c64-x25519, which occupies banks 0-1) can allocate non-conflicting
; REU regions. Defaults preserve pre-v0.3.2 behavior (bank 0, offset
; $0000) — see CHANGELOG for the PRG byte-size note.
;
; As of v0.5.x the bank / offset are RAM-backed public symbols
; (`poly1305_reu_sqtab_bank`, `poly1305_reu_sqtab_offset`) which a
; consumer may patch *at runtime* before calling `poly1305_lib_init`.
; The assemble-time defines below remain supported and now select the
; *default values* the RAM cells are initialized to in
; `poly1305_lib_init`. I.e. a build invoked with
; `--asm-define POLY1305_REU_BANK=3 --asm-define POLY1305_REU_OFFSET=$1000`
; comes up with the RAM cells pre-set to bank 3 / offset $1000 and no
; runtime poke is required. A build that passes neither define lands
; the RAM cells on bank 0 / offset $0000, identical to the pre-v0.5.x
; immediate-operand path. See docs/API.md §3 for the runtime override
; protocol.
.ifdef POLY1305_REU
  .ifndef POLY1305_REU_BANK
    POLY1305_REU_BANK = 0
  .endif
  .ifndef POLY1305_REU_OFFSET
    POLY1305_REU_OFFSET = $0000
  .endif
.endif
.endif
