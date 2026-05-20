; =============================================================================
; lib/constants_lib.s - ChaCha20-Poly1305 library equates
;
; ZP + shared equates used by the ChaCha20-Poly1305 library only.
; No KERNAL / PETSCII / hardware references. No code emitted.
;
; ZP slot allocation has moved to src/zp_config.s (a standalone .s module
; that is assembled to its own .o and linked into the library). Each
; consuming module pulls in this file with `.include`, which emits one
; `.importzp` declaration per ZP slot so the linker resolves them from
; zp_config.s. To override a slot's address, either pre-define the
; symbol before zp_config.s is assembled, or replace zp_config.s in your
; build line; no edits to this file are required.
;
; Non-ZP equates (Profile A flag documentation, Shoup r_tab_{lo,hi}
; address reservations, REU bank/offset defaults) remain inline below.
; =============================================================================

; --- ZP imports (definitions live in src/zp_config.s) -----------------------
; General-purpose ZP scratch (word32 nibble rotates).
.importzp zp_tmp1, zp_tmp2

; word32 operand pointers (32-bit add/xor/rotate primitives).
.importzp w32_src1, w32_src2, w32_dst

; ChaCha20 state ZP (round/qr/data ptr/remain/buf-pos).
.importzp cc20_round, cc20_qr_idx, cc20_data_ptr, cc20_remain, cc20_buf_pos

; ChaCha20 working state (64 bytes at $40..$7f by default). cc20_keystream
; is an alias of cc20_work — see zp_config.s for the rationale (C7/S8:
; eliminating the 256-cy per-block copy out of the working buffer).
.importzp cc20_work, cc20_keystream

; Poly1305 ZP (loop counters / carry / multiply temp).
.importzp poly_i, poly_j, poly_carry, poly_tmp

; Profile B ct_mul_8x8 ZP scratch (v0.3.0 constant-time fix). Placed in
; the old lmul0/lmul1 slot (Step 12 mult66 pointers, deleted in the CT
; fix). Net ZP delta from pre-CT-fix: −2 bytes.
.importzp ct_diff_raw, ct_sign_mask

; General-purpose 16-bit pointers used by poly1305 / aead.
.importzp zp_ptr1, zp_ptr2

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
