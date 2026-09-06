; =============================================================================
; lib/precalc_manifest.s - SPEC §8.4 catch-loop precalc-table enumeration
;
; This translation unit exists for one reason: c64-lib-contract SPEC §6.1
; **member isolation** (v1.2.0, carve-out at v1.2.1, rationale widened at
; v1.2.2). ld65 links whole archive members, so a displaceable symbol MUST
; live in a TU that "exports nothing else a consumer may import — other
; displaceable names included, their own prefixed counterparts excepted —
; and defines nothing else the library's own code references."
;
; One LIB_PRECALC_TABLE invocation emits SIX exported equates:
;
;   LIB_CHACHA20_POLY1305_PRECALC_<name>_{SIZE,REGION,SHARED}   prefixed
;   LIB_PRECALC_<name>_{SIZE,REGION,SHARED}                     bare, DEPRECATED
;
; The bare triple is displaceable — `-D LIB_NO_BARE_EXPORTS=1` suppresses it
; — and the prefixed triple is its own prefixed counterpart, so the two
; belong in one TU and the v1.2.1 carve-out reaches exactly that pairing.
; What the carve-out does NOT reach is co-residency with the §5 aggregates
; (LIB_CHACHA20_POLY1305_{REU_BANKS_USED,ZP_USAGE_BYTES,RESIDENT_BYTES,...})
; and the §8.0 masks: those are counterparts of nothing displaceable —
; there is no bare `LIB_ZP_USAGE_BYTES` — so they stay "something else a
; consumer may import" and their presence beside the bare `LIB_PRECALC_*`
; triples in lib_manifest.o was the violation (contract #177, ruled on in
; contract #186 / SPEC v1.2.1). Issue #108 item 1.
;
; THE HAZARD IS LIBRARY-VERSUS-LIBRARY, not consumer-versus-library. No
; consumer defines `LIB_PRECALC_sqtab_SHARED`; a SIBLING ADOPTER exports the
; identical bare name from its own §8.4 enumeration, and §8.4's whole point
; is that several adopters enumerate the same table. Composing two archives
; that each drag in a manifest member carrying the bare triple is a
; `Duplicate external identifier`, and the consumer's repair —
; `-D LIB_NO_BARE_EXPORTS=1` on both — only works if the suppressible names
; sit in a member the link is free not to pull. That is what this file buys:
; a consumer importing `LIB_CHACHA20_POLY1305_RESIDENT_BYTES` now pulls
; lib_manifest.o alone and never sees a bare `LIB_PRECALC_*` at all
; (contract v1.2.2 names both collision directions explicitly).
;
; Split out of src/lib/lib_manifest.s, verbatim. `c64-x25519` v0.14.0 made
; the identical split and contract #187 blesses that arrangement by name.
;
; §8.4 requires the macro be included from exactly ONE translation unit per
; library — `precalc_table.inc` is included here and nowhere else in this
; repo (the include guard would make a second include a silent no-op, and
; the macro would then be undefined in that TU).
;
; No code emitted: equates only, no `.segment`, no imports. Adding this
; object to a link therefore moves not one byte of any PRG.
;
; src/precalc_table.inc is a VERBATIM copy of the canonical contract source
; — never edit it.
; =============================================================================

.setcpu "6502"

; ---------------------------------------------------------------------------
; §8.4 catch-loop precalc-table enumeration. Per c64-lib-contract SPEC
; v0.3.1 §8.0; canonical macro source in src/precalc_table.inc (copied
; verbatim from the contract repo at b039ab9; do not edit local copy).
;
; Lists every precomputed table in this library that clears the §8.0
; floor (>= 256 B AND one of: REU-resident, hot-loop-read, page-aligned
; for fetch alignment). Each invocation emits three exported equates:
; LIB_PRECALC_<name>_{SIZE,REGION,SHARED}. Consumer-side audits grep
; on these to detect bit-identical precalc shapes across sibling libs
; that should be promoted to a §8.x shared-primitive clause.
;
; Below-the-floor items intentionally NOT enumerated here (see
; docs/precalc-tables.md for the full exempt list and rationale):
;   - ChaCha20 quarter-round constants ("expand 32-byte k", 16 B)
;   - sqtab_ready / cc20_work / scratch buffers (small or non-table)
; ---------------------------------------------------------------------------
.include "precalc_table.inc"

; sqtab — combined sqtab_lo + sqtab_hi at LIB_SHARED_SQTAB_BASE
; (sqtab_lo + $0200 = sqtab_hi; 512 B + 512 B = 1024 B contiguous).
; Shared via §8.1 (LIB_SHARED_PRIMITIVES_SQTAB bit, $0001 above).
;
; Profile-gated as of issue #51. This row was previously emitted
; unconditionally, on the reasoning that the §8.1 canonical-name
; back-link stays normative when any sibling in a composed build ships
; sqtab — which was coherent while the ownership mask also claimed the
; SQTAB bit unconditionally. Under the v0.5.0 three-state semantics that
; is no longer true: Profile A is a non-consumer of sqtab (#34 F1), so it
; must enumerate no sqtab row, exactly as it already omits the Shoup
; r_tab_* rows on Profile B. The enumeration now tracks the CONSUMES
; mask, which is the honest signal for the §8.4 catch-loop audit.
.ifndef POLY1305_PROFILE_LONG
LIB_PRECALC_TABLE "sqtab", 1024, PRECALC_REGION_RAM, PRECALC_SHARED_YES, "CHACHA20_POLY1305"
.endif

; chacha_nibswap_hi_tab / chacha_nibswap_lo_tab — C4 branchless
; rotl-4 LUTs (commit d0b1d40). 256 B each, page-aligned in the CODE
; segment, hot-loop-read with secret-index `lda abs,x` (8 inlined
; call sites per double-round in chacha20_block). Library-specific:
; bit shape is generic (V<<4&$FF, V>>4) but no other adopter ships a
; rotl-4 fast path today; promote to §8.x only after a second sibling
; converges on bit-identical bytes.
LIB_PRECALC_TABLE "chacha_nibswap_hi_tab", 256, PRECALC_REGION_RAM, PRECALC_SHARED_NO, "CHACHA20_POLY1305"
LIB_PRECALC_TABLE "chacha_nibswap_lo_tab", 256, PRECALC_REGION_RAM, PRECALC_SHARED_NO, "CHACHA20_POLY1305"

; r_tab_lo / r_tab_hi — Profile A Shoup per-r tables at $6000..$7FFF
; (4096 B each, page-aligned per limb). Library-private: the content
; T_j[x] = x * r[j] is keyed off the per-message random Poly1305 `r`
; value, so no sibling lib can converge on the same bytes — there is
; no candidate §8.x shared-primitive promotion path. Profile B does
; not allocate these tables (uses sqtab via ct_mul_8x8 instead).
.ifdef POLY1305_PROFILE_LONG
LIB_PRECALC_TABLE "r_tab_lo", 4096, PRECALC_REGION_RAM, PRECALC_SHARED_NO, "CHACHA20_POLY1305"
LIB_PRECALC_TABLE "r_tab_hi", 4096, PRECALC_REGION_RAM, PRECALC_SHARED_NO, "CHACHA20_POLY1305"
.endif
