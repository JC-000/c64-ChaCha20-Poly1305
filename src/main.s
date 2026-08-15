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

; --- §6.7 image guard: the equate-placed sqtab window ------------------------
;
; The §8.1 sqtab is placed by an *equate* (LIB_SHARED_SQTAB_BASE), not a
; segment, because §8.x requires independently-built adopters to agree on
; one address via -D. ld65 therefore does not know the region exists: MAIN
; spans $0900-$9FFF, which contains the $8000 default, so a growing segment
; could be placed straight across the table, link with no error, and
; corrupt it at runtime with no diagnostic at any stage. Contract v0.10.0
; §6.7 Rule 2 makes this guard mandatory.
;
; The value is obtained SOURCE-LEVEL, not by .import: §8.1's export
; discipline (v0.8.5) forbids libraries from exporting this equate, since
; two libraries exporting the same unprefixed name collide in any composed
; link. §6.7's prose says to compare against "the imported equate", which
; cannot be done for this equate — filed upstream. Including the shared
; header is equivalent for the property that matters: -D defines the symbol
; for the whole assembly, so a consumer relocation still moves the guard
; with the table.
;
; This TU is the right home because it ships in NO archive (verified: none
; of the three variants list main.o). §6.7 makes that a constraint, not a
; preference — an `.import __MAIN_LAST__` inside an archive member would
; force every consumer to declare a MAIN area with `define = yes` or eat an
; unresolved external. The guard protects this library's own image only;
; consumers mirror it against their own `__<AREA>_LAST__`.
;
; __MAIN_LAST__ must stay a hard import: an lderror assert whose operand is
; missing degrades to "Warning: Cannot evaluate assertion" — a silent
; no-op. The unresolved external is what keeps the guard honest.
;
; Profile-B only. Profile A (POLY1305_PROFILE_LONG=1) emits and consumes no
; sqtab, so there is no window to guard.
.ifndef POLY1305_PROFILE_LONG
    .include "sqtab_base.inc"
    .import __MAIN_LAST__
    .assert __MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE, lderror, "image overruns the sqtab window (LIB_SHARED_SQTAB_BASE) — relocate the table with -D LIB_SHARED_SQTAB_BASE=0x<addr> or shrink the image"
.endif

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
