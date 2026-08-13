; precalc_table.inc — canonical per c64-lib-contract SPEC §8.0 catch-loop.
;
; CANONICAL SOURCE. The fenced code block in SPEC.md §8.0 is shown for
; readability; this file is the byte-for-byte source adopters copy into
; their own src/precalc_table.inc. Updates land via coordinated cross-repo
; PR; do not edit your local copy.
;
; Smoke-tested in examples/precalc_table_smoke.s and exercised by `make verify`
; at this repo's root.

.ifndef PRECALC_TABLE_INC_INCLUDED
PRECALC_TABLE_INC_INCLUDED = 1

PRECALC_REGION_RAM     = $01
PRECALC_REGION_REU     = $02
PRECALC_REGION_RODATA  = $03

PRECALC_SHARED_NO      = $00
PRECALC_SHARED_YES     = $01

; LIB_PRECALC_TABLE "name", size_bytes, region, shared [, "LIB"]
;
;   "name":       quoted string literal (becomes the symbol suffix;
;                 use lower_snake_case, no leading digit)
;   size_bytes:   total bytes claimed by the table
;   region:       PRECALC_REGION_RAM | _REU | _RODATA
;   shared:       PRECALC_SHARED_YES | PRECALC_SHARED_NO
;   "LIB":        quoted library prefix, UPPER_SNAKE_CASE, matching the
;                 <X> in this library's §5 LIB_<X>_* manifest equates
;                 (e.g. "X25519", "CHACHA20_POLY1305"). Required as of
;                 SPEC v0.7.0; omitted only by pre-v0.7.0 adopters that
;                 have not yet migrated.
;
; Emits, per invocation:
;
;   LIB_<LIB>_PRECALC_<name>_{SIZE,REGION,SHARED}   (when "LIB" is given)
;   LIB_PRECALC_<name>_{SIZE,REGION,SHARED}         (unless suppressed)
;
; The prefixed form is collision-free across libraries, so a consumer
; linking two libraries can .import both manifests and cross-check that
; they agree on a shared table's shape (SPEC #43). The bare form is
; DEPRECATED — it is the form that collides — and is scheduled for
; removal at contract v1.0.
;
; Define LIB_NO_BARE_EXPORTS (ca65 -D LIB_NO_BARE_EXPORTS=1) to suppress
; the deprecated bare form. A consumer composing two or more libraries
; that describe the same shared table MUST build them all with this
; define; otherwise ld65 rejects the link with
;   Duplicate external identifier: 'LIB_PRECALC_<name>_SHARED'
; Single-library consumers need not define it, and adopters assembling
; standalone keep the bare exports by default.
;
; The macro preserves the case of the `name` argument verbatim (ca65 has
; no built-in toupper), so `LIB_PRECALC_TABLE "sqtab", ...` emits the
; symbols in their lower-case form. The normative §8.x canonical names
; use lower_snake_case throughout, so cross-adopter audits grep on a
; single case convention — and on `_PRECALC_`, which matches both the
; prefixed and bare forms.
;
; SIZE is exported without an address-size hint so values > 16 bits
; (e.g. the 131072-byte REU mul table) export cleanly as 'far'
; without a "far but exported absolute" warning — its address size is
; value-dependent by design (absolute at 1024, far at 131072).
;
; REGION and SHARED are pinned ': abs' instead. They can never exceed a
; byte, so ca65 would infer 'zeropage' for them in every adopter, while
; a consumer's .import defaults to absolute — which makes the §8.4
; cross-check snippet emit an "Address size mismatch" warning on every
; composed build. The link succeeds and the asserts evaluate correctly,
; but the natural consumer reaction is to write '.import ... : zeropage',
; pinning a manifest constant to an address size that is an artifact of
; its current value rather than a property of the symbol.

.macro LIB_PRECALC_TABLE name, size_bytes, region, shared, lib
    .ifndef LIB_NO_BARE_EXPORTS
        .ident (.sprintf("LIB_PRECALC_%s_SIZE",   name)) = size_bytes
        .ident (.sprintf("LIB_PRECALC_%s_REGION", name)) = region
        .ident (.sprintf("LIB_PRECALC_%s_SHARED", name)) = shared

        .export .ident (.sprintf("LIB_PRECALC_%s_SIZE",   name))
        .export .ident (.sprintf("LIB_PRECALC_%s_REGION", name)): abs
        .export .ident (.sprintf("LIB_PRECALC_%s_SHARED", name)): abs
    .endif

    .if .not .blank (lib)
        .ident (.sprintf("LIB_%s_PRECALC_%s_SIZE",   lib, name)) = size_bytes
        .ident (.sprintf("LIB_%s_PRECALC_%s_REGION", lib, name)) = region
        .ident (.sprintf("LIB_%s_PRECALC_%s_SHARED", lib, name)) = shared

        .export .ident (.sprintf("LIB_%s_PRECALC_%s_SIZE",   lib, name))
        .export .ident (.sprintf("LIB_%s_PRECALC_%s_REGION", lib, name)): abs
        .export .ident (.sprintf("LIB_%s_PRECALC_%s_SHARED", lib, name)): abs
    .else
        .ifdef LIB_NO_BARE_EXPORTS
            .error "LIB_PRECALC_TABLE: LIB_NO_BARE_EXPORTS suppresses the bare exports, so the lib-prefix argument is required — this invocation would emit nothing"
        .endif
    .endif
.endmacro

.endif ; PRECALC_TABLE_INC_INCLUDED
