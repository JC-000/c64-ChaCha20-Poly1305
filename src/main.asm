; =============================================================================
; main.asm - ChaCha20-Poly1305 library (C64 / 6502)
;
; Top-level assembly file. Build with:
;   cd src && acme -f cbm -o ../build/c64_chacha20_poly1305.prg \
;                  --vicelabels ../build/labels.txt main.asm
;
; Library / demo separation:
;   src/lib/*_lib.asm - Reusable ChaCha20, Poly1305, word32, AEAD primitives.
;                       These files must NOT set an absolute origin (no `* =`,
;                       no !pseudopc, no !org). They assemble at whatever
;                       program counter the host assembly has set before
;                       !source'ing them.
;   src/main.asm      - This entry stub. Owns the only `* =` binding in the
;                       tree (the $0801 BASIC stub).
;
; This PRG is a thin library shell: the entry routine just RTSes. The point
; of the PRG is to produce a loadable binary + labels.txt so Python test
; harnesses can jsr() directly into chacha20_*, poly1305_*, and aead_*
; routines by label.
; =============================================================================

        !cpu 6502

; --- Constants and equates (no code emitted) ---
!source "lib/constants_lib.asm"

; --- Program origin (BASIC stub) ---
        * = $0801

; BASIC stub: 10 SYS 2064
        !byte $0c, $08, $0a, $00, $9e, $20, $32, $30, $36, $34, $00, $00, $00

; Entry point at $0810 (2064)
        * = $0810
lib_entry:
        rts

; --- Library code modules (order matters: word32 primitives first) ---
!source "lib/word32_lib.asm"
!source "lib/chacha20_lib.asm"
!source "lib/poly1305_lib.asm"
!source "lib/chacha20poly1305_lib.asm"

; --- Mutable data reservations ---
!source "lib/data_lib.asm"
