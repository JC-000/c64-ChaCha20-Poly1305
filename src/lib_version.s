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
; Consumers guard against unsupported versions via:
;
;     .import LIB_CHACHA20_POLY1305_VERSION_MAJOR
;     .import LIB_CHACHA20_POLY1305_VERSION_MINOR
;     .assert (LIB_CHACHA20_POLY1305_VERSION_MAJOR > 0) .or (LIB_CHACHA20_POLY1305_VERSION_MINOR >= 8), lderror, "needs c64-ChaCha20-Poly1305 v0.8+"
;
; It MUST be `.assert` / `lderror`, not `.if` / `.error` (SPEC §1,
; contract v0.8.1). `.if` needs an assemble-time constant, and an
; `.import`ed symbol has no value until link, so ca65 rejects an
; `.if`-based gate outright with `Constant expression expected` — it
; never assembles at all. `.assert` with the `lderror` action defers
; evaluation to ld65, the only stage that knows the imported value.
; The guard therefore fires at link rather than assemble time, which is
; still before anything runs.
;
; LIB_ABI_VERSION is a MONOTONIC GENERATION COUNTER for the exported
; surface (SPEC §1/§7, contract v0.7.5) — deliberately NOT a mirror of
; MAJOR. It starts at 1 and increments on any breaking export change: a
; removed or renamed symbol, a changed calling convention, a changed
; memory model.
;
; It cannot track MAJOR because §7 permits breaking changes on MINOR
; bumps while a library is pre-1.0, so MAJOR stays 0 across breakage and
; carries no signal — a consumer gating on it would never fire for
; exactly the changes the gate exists to catch.
;
; Generation history:
;   1  v0.6.0 — first published ABI surface.
;   2  v0.7.0 — BREAKING: removed the exported §8.x bit constants
;               LIB_SHARED_PRIMITIVES_SQTAB / _CT_MUL_8X8 (issue #57),
;               and renamed every library segment CODE/DATA ->
;               LIB_CHACHA20_POLY1305_CODE/_DATA (issue #48).
;               The counter was left at 1 at release time under §1's
;               then-current "matches the MAJOR bump" wording, which
;               contract v0.7.5 has since repudiated; corrected here
;               (issue #67). The v0.7.0 tag itself still reports 1.
;   3  unreleased — BREAKING: the general-purpose ZP slots zp_tmp1,
;               zp_tmp2, zp_ptr1 and zp_ptr2 are renamed to
;               chacha20poly1305_zp_* per the SPEC §2 prefix registry
;               (issue #76). The library's TUs now .importzp the
;               canonical names, so a consumer that supplied the bare
;               slots from its own zp_config — c64-wireguard does — must
;               export the canonical spellings or the link fails with an
;               unresolved external.
;
;               The deprecated bare names are still exported by
;               src/zp_config.s for the §6.5 rename window, but they sit
;               behind LIB_NO_BARE_EXPORTS (contract v0.9.1 §6.5): a
;               composing consumer sets that flag, and for it the bare
;               exports disappear. That suppression is itself a removal
;               from the surface such a consumer sees, which is the
;               second reason this generation increments.
;
; TU ISOLATION (SPEC §1, contract v0.7.0): this file MUST export the
; version equates and NOTHING else. ld65 links whole object members, so
; if the deprecated bare names shared a member with anything a consumer
; legitimately imports, they would enter the link uninvited and collide
; even when the consumer never referenced them. §5's aggregate equates
; and the §8.4 LIB_PRECALC_TABLE invocations therefore live in
; src/lib/lib_manifest.s. Do not add exports here.

LIB_CHACHA20_POLY1305_VERSION_MAJOR = 0
LIB_CHACHA20_POLY1305_VERSION_MINOR = 9
LIB_CHACHA20_POLY1305_VERSION_PATCH = 0
LIB_CHACHA20_POLY1305_ABI_VERSION   = 3

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
