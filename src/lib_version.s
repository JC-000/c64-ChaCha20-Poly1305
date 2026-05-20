.setcpu "6502"

; Library version constants for c64-ChaCha20-Poly1305.
;
; Semver tracks the released CHANGELOG.md version. Consumers can
; assemble-time guard against unsupported versions via:
;
;     .import LIB_VERSION_MAJOR, LIB_VERSION_MINOR
;     .if LIB_VERSION_MINOR < 5
;         .error "needs c64-ChaCha20-Poly1305 v0.5+"
;     .endif
;
; LIB_ABI_VERSION is the exported-symbol ABI surface; bump on any
; breaking change to public symbol names, calling conventions, or
; the public ZP-cell contract. This is the first published library-
; ABI surface, so it starts at 1.

LIB_VERSION_MAJOR = 0
LIB_VERSION_MINOR = 5
LIB_VERSION_PATCH = 0
LIB_ABI_VERSION   = 1

.export LIB_VERSION_MAJOR
.export LIB_VERSION_MINOR
.export LIB_VERSION_PATCH
.export LIB_ABI_VERSION
