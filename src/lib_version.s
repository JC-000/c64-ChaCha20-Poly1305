.setcpu "6502"

; Library version constants for c64-ChaCha20-Poly1305.
;
; c64-lib-contract SPEC §1. Two forms are exported:
;
;   LIB_CHACHA20_POLY1305_VERSION_{MAJOR,MINOR,PATCH} / _ABI_VERSION
;       The required, collision-free form (contract v0.7.0). `<X>` is
;       CHACHA20_POLY1305, the same prefix as this library's §5 manifest
;       equates in src/lib/lib_manifest.s.
;
;   LIB_VERSION_{MAJOR,MINOR,PATCH} / LIB_ABI_VERSION
;       The historical bare form. Still REQUIRED through contract v0.x so
;       existing single-library consumers keep working unchanged, but
;       DEPRECATED and scheduled for removal at contract v1.0: the names
;       are identical across every adopter, so a consumer linking two
;       libraries and importing both manifests gets
;       `ld65: Error: Duplicate external identifier`.
;
;       Suppress them with `ca65 -D LIB_NO_BARE_EXPORTS=1`, applied to
;       every library in the link. See issue #57 for the measured
;       two-library collision against c64-x25519 v0.8.0.
;
; The bare names ALIAS the prefixed ones rather than restating the
; literals, so a release bump touches four lines and the two forms
; cannot drift apart (SPEC §1).
;
; Consumers can assemble-time guard against unsupported versions via:
;
;     .import LIB_CHACHA20_POLY1305_VERSION_MAJOR
;     .import LIB_CHACHA20_POLY1305_VERSION_MINOR
;     .if LIB_CHACHA20_POLY1305_VERSION_MAJOR = 0 .and LIB_CHACHA20_POLY1305_VERSION_MINOR < 6
;         .error "needs c64-ChaCha20-Poly1305 v0.6+"
;     .endif
;
; LIB_ABI_VERSION is the exported-symbol ABI surface; bump on any
; breaking change to public symbol names, calling conventions, or
; the public ZP-cell contract. This is the first published library-
; ABI surface, so it starts at 1.
;
; TU ISOLATION (SPEC §1, contract v0.7.0): this file MUST export the
; version equates and NOTHING else. ld65 links whole object members, so
; if the deprecated bare names shared a member with anything a consumer
; legitimately imports, they would enter the link uninvited and collide
; even when the consumer never referenced them. §5's aggregate equates
; and the §8.4 LIB_PRECALC_TABLE invocations therefore live in
; src/lib/lib_manifest.s. Do not add exports here.

LIB_CHACHA20_POLY1305_VERSION_MAJOR = 0
LIB_CHACHA20_POLY1305_VERSION_MINOR = 6
LIB_CHACHA20_POLY1305_VERSION_PATCH = 0
LIB_CHACHA20_POLY1305_ABI_VERSION   = 1

; Exported `:abs` so ca65 emits them as absolute values rather than
; zeropage: an integer equate <= $00ff would otherwise be tagged
; zeropage and trigger `Range error: '<n>' out of range [0,0]` at the
; consumer-side .import. Same reasoning as the §5/§8 equate exports in
; src/lib/lib_manifest.s.
.export LIB_CHACHA20_POLY1305_VERSION_MAJOR:abs
.export LIB_CHACHA20_POLY1305_VERSION_MINOR:abs
.export LIB_CHACHA20_POLY1305_VERSION_PATCH:abs
.export LIB_CHACHA20_POLY1305_ABI_VERSION:abs

.ifndef LIB_NO_BARE_EXPORTS
    ; Deprecated bare forms — removed at contract v1.0. A consumer
    ; composing two or more libraries suppresses these build-wide with
    ; `ca65 -D LIB_NO_BARE_EXPORTS=1` and imports the prefixed names.
    LIB_VERSION_MAJOR = LIB_CHACHA20_POLY1305_VERSION_MAJOR
    LIB_VERSION_MINOR = LIB_CHACHA20_POLY1305_VERSION_MINOR
    LIB_VERSION_PATCH = LIB_CHACHA20_POLY1305_VERSION_PATCH
    LIB_ABI_VERSION   = LIB_CHACHA20_POLY1305_ABI_VERSION

    .export LIB_VERSION_MAJOR:abs
    .export LIB_VERSION_MINOR:abs
    .export LIB_VERSION_PATCH:abs
    .export LIB_ABI_VERSION:abs
.endif
