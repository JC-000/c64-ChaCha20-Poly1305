; =============================================================================
; sqtab_base.inc — the §8.1 shared-sqtab placement equate.
;
; Contract §8.1 requires the *equate* form (not a segment) so that
; independently-built adopters can be pointed at one address with a single
; `ca65 -D LIB_SHARED_SQTAB_BASE=0x<addr>`. §8.1's export discipline
; (contract v0.8.5) additionally forbids libraries from `.export`-ing it:
; it is consumer *input*, and two libraries exporting the same unprefixed
; name is a guaranteed `ld65: Duplicate external identifier` in any
; composed link.
;
; Because it cannot be exported, a second TU that needs the value must
; derive it *source-level* — hence this header. It exists so the default
; is written once: `src/lib/poly1305_lib.s` derives sqtab_lo/sqtab_hi from
; it, and `src/main.s` compares the linked image against it for the §6.7
; image guard. Two copies of the default could silently disagree, and the
; §6.7 guard would then be checking a different window than the one the
; table actually occupies.
;
; The `.ifndef` guard is what preserves consumer relocation: `-D` defines
; the symbol for the whole assembly, so both including TUs see the
; overridden value and the guard moves with the table.
;
; Include only where the sqtab exists — it is Profile-B-only; Profile A
; (POLY1305_PROFILE_LONG=1) emits and consumes no sqtab.
; =============================================================================

.ifndef LIB_SHARED_SQTAB_BASE
LIB_SHARED_SQTAB_BASE = $8000     ; per-lib default for standalone builds
.endif

.assert (LIB_SHARED_SQTAB_BASE & $00ff) = 0, error, "sqtab base must be page-aligned"
