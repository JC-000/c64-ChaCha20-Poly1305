; =============================================================================
; lib/lib_manifest.s - ChaCha20-Poly1305 aggregate manifest equates
;
; Aggregate equates so a consumer can statically verify REU bank and
; zero-page usage at assemble time (via `.assert`) before linking.
; Pairs with issue #19 (POLY1305_REU_BANK / POLY1305_REU_OFFSET
; assemble-time overrides) and issue #28 (LIB_VERSION_* constants).
;
; Names and semantics follow the c64-lib-contract SPEC §5 aggregate
; manifest convention (v0.1.0, 2026-05-20). The cross-consumer ABI
; contract pins these symbol names so c64-https, c64-wireguard and any
; future composing consumer can `.import` them by canonical name and
; static-assert layout fit without source patching.
;
; All four equates are exported as absolute byte/word values. No code
; emitted.
; =============================================================================

.setcpu "6502"

; Pull in POLY1305_REU_BANK default + Profile-A/B flag visibility so
; LIB_CHACHA20_POLY1305_REU_BANKS_USED below composes with whatever the
; consumer set via --asm-define -DPOLY1305_REU_BANK=N (issue #19).
.include "constants_lib.s"

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_REU_BANKS_USED — bitmask of REU banks this library claims.
;
; Per c64-lib-contract SPEC §5. Consumers compose per-library masks at
; assemble time to detect REU collisions:
;
;   .assert (LIB_NISTCURVES_REU_BANKS_USED .and LIB_CHACHA20_POLY1305_REU_BANKS_USED) = 0
;
; Profile A with POLY1305_REU defined: bit (1 << POLY1305_REU_BANK), so
;   bank 0 → $01, bank 3 → $08, bank 7 → $80. Composes with the issue
;   #19 consumer override --asm-define -DPOLY1305_REU_BANK=N.
; Profile A without POLY1305_REU, or Profile B: $00 (no REU claimed).
; ---------------------------------------------------------------------------
.ifdef POLY1305_PROFILE_LONG
    .ifdef POLY1305_REU
        LIB_CHACHA20_POLY1305_REU_BANKS_USED = 1 .shl POLY1305_REU_BANK
    .else
        LIB_CHACHA20_POLY1305_REU_BANKS_USED = $00            ; no REU compiled in
    .endif
.else
    LIB_CHACHA20_POLY1305_REU_BANKS_USED = $00                ; profile B: no REU
.endif

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES
;   Total bytes of zero-page this library owns.
;
;   $02-$03 zp_tmp1/2              (2 B)
;   $04-$09 w32_src1/src2/dst      (6 B)
;   $14-$19 cc20_round..buf_pos    (6 B)
;   $1A-$1F poly_i..ct_sign_mask   (6 B — $1E/$1F are Profile B only)
;   $40-$7F cc20_work hot state    (64 B)
;   $FB-$FE zp_ptr1/2              (4 B)
;   --------------------------------------
;   Total 88 B (counted as union of A+B for a safe consumer upper bound).
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES   = 88

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_RESIDENT_BYTES
;   Resident code+data footprint after build, measured from
;   build/profile-a/c64_chacha20_poly1305.prg (PRG file size minus the
;   2-byte LOADADDR header). Actual measurement at commit time: 16422 B.
;   Padded to 16640 (256-aligned, $4100) to provide a small headroom
;   buffer that absorbs incidental growth between releases without
;   forcing consumer `.assert` rewrites. Update on each release.
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 16640

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_COLD_BYTES
;   Rough overlay-able cold footprint. No hot/cold split today; reserved
;   for future overlay layout. Reports 0 so consumers using a `.assert
;   cold <= N` check pass trivially today but get a real number once an
;   overlay split lands.
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_COLD_BYTES       = 0

.export LIB_CHACHA20_POLY1305_REU_BANKS_USED
.export LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES
.export LIB_CHACHA20_POLY1305_RESIDENT_BYTES
.export LIB_CHACHA20_POLY1305_COLD_BYTES
