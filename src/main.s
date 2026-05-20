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
; linker. Zero-page slot allocations and their `.exportzp` declarations
; live in src/zp_config.s, which is assembled to its own .o and linked
; into the library. Consumers wishing to pin the ZP layout pre-define
; symbols before zp_config.s is assembled (or replace the file outright).
; =============================================================================
