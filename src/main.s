; =============================================================================
; main.s - ChaCha20-Poly1305 library (C64 / 6502)
;
; Thin entry stub. Real code lives in src/lib/*.s, each of which is
; assembled to its own .o and linked together by ld65 via src/c64.cfg.
;
; The PRG is a loadable library shell: the entry routine just RTSes. Python
; test harnesses jsr() directly into the library routines by label.
; =============================================================================

        .p02

; --- Pull in shared equates for .exportzp below (no code emitted) ---
.include "constants_lib.s"

; --- Load address ---
.segment "LOADADDR"
        .word $0801

; --- BASIC stub: 10 SYS 2304 ---
.segment "BASICSTUB"
        .byte $0c, $08, $0a, $00, $9e, $20, $32, $33, $30, $34, $00, $00, $00

; --- Entry point at $0900 (2304) ---
.segment "CODE"

.export lib_entry
lib_entry:
        rts

; =============================================================================
; VICE label exports
;
; Library code and data live in separate .o files (see src/lib/*.s). The
; per-module files `.export` their own functions and data symbols to the
; linker. Here we only `.exportzp` the zero-page equates from
; constants_lib.s so they appear in the VICE label file — equates are
; assembled per-translation-unit, so declaring them `.exportzp` inside
; constants_lib.s itself would collide across every module that includes
; the file. Declaring them here (the one TU with main.s) emits exactly
; one export record per symbol.
; =============================================================================
.exportzp zp_tmp1, zp_tmp2
.exportzp w32_src1, w32_src2, w32_dst
.exportzp cc20_round, cc20_qr_idx, cc20_data_ptr, cc20_remain, cc20_buf_pos
.exportzp cc20_work, cc20_keystream
.exportzp poly_i, poly_j, poly_carry, poly_tmp
.exportzp zp_ptr1, zp_ptr2
