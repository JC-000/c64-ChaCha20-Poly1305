; =============================================================================
; lib/lib_manifest.s - ChaCha20-Poly1305 aggregate manifest equates
;
; Aggregate equates so a consumer can statically verify REU bank and
; zero-page usage at assemble time (via `.assert`) before linking.
; Pairs with issue #28 (LIB_VERSION_* constants) and issue #34 F1
; (Profile A dead-code trim → per-profile resident-byte differentiation).
;
; Names and semantics follow the c64-lib-contract SPEC §5 aggregate
; manifest convention (v0.1.0, 2026-05-20). The cross-consumer ABI
; contract pins these symbol names so c64-https, c64-wireguard and any
; future composing consumer can `.import` them by canonical name and
; static-assert layout fit without source patching.
;
; All four equates are exported as absolute byte/word values. No code
; emitted.
; =============================================================================

.setcpu "6502"

; Pull in Profile-A/B flag visibility so the per-profile
; LIB_CHACHA20_POLY1305_RESIDENT_BYTES selection below picks the
; right value. (Issue #34 F1 retired the POLY1305_REU_BANK default
; from constants_lib.s — sqtab is no longer emitted on Profile A,
; so the library claims no REU banks; see the
; LIB_CHACHA20_POLY1305_REU_BANKS_USED comment below.)
.include "constants_lib.s"

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_REU_BANKS_USED — bitmask of REU banks this library claims.
;
; Per c64-lib-contract SPEC §5. Consumers compose per-library masks at
; assemble time to detect REU collisions:
;
;   .assert (LIB_NISTCURVES_REU_BANKS_USED .and LIB_CHACHA20_POLY1305_REU_BANKS_USED) = 0
;
; As of issue #34 F1 this library claims no REU banks on any profile.
; The pre-F1 Profile-A + POLY1305_REU path stashed the 1 KB quarter-
; square sqtab to REU so consumers that clobbered $8000..$83FF could
; reload it; F1 gated sqtab itself out of Profile A entirely (Step 11
; replaced the mul_8x8 callers in shoup_init with an incremental
; ripple-add), so the stash had no live content to back up.
; LIB_CHACHA20_POLY1305_REU_BANKS_USED therefore always reads $00
; today. The symbol is retained for forward compatibility — a future
; profile that genuinely allocates an REU region can flip this bit
; without consumers having to .ifdef their .assert composition.
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_REU_BANKS_USED = $00

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES
;   Total bytes of zero-page this library owns.
;
;   $02-$03 zp_tmp1/2              (2 B)
;   $04-$09 w32_src1/src2/dst      (6 B)
;   $14-$19 cc20_round..buf_pos    (6 B)
;   $1A-$1F poly_i..ct_sign_mask   (6 B — $1E/$1F are Profile B only)
;   $40-$7F cc20_work hot state    (64 B)
;   $FB-$FE zp_ptr1/2              (4 B)
;   --------------------------------------
;   Total 88 B (counted as union of A+B for a safe consumer upper bound).
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES   = 88

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_RESIDENT_BYTES
;   Resident code+data footprint after build, measured from
;   build/profile-{a,b}/c64_chacha20_poly1305.prg (PRG file size minus the
;   2-byte LOADADDR header).
;
;   Profile-aware as of issue #34 F1, which gated sqtab_lo/hi,
;   sqtab_init, mul_8x8, and the POLY1305_REU stash plumbing out of
;   Profile A — Profile A's resident footprint dropped 256 B and the
;   two profiles diverged enough that a single unified value would
;   over-report Profile A and under-report Profile B for consumer
;   `.assert resident <= N` checks.
;
;   Actual measurements at this commit:
;     Profile A: 16166 B  → padded to 16384 (256-aligned, $4000)
;     Profile B: 17446 B  → padded to 17664 (256-aligned, $4500)
;   Padding provides a small headroom buffer that absorbs incidental
;   growth between releases without forcing consumer `.assert`
;   rewrites. Update on each release.
;
;   Consumers wanting the larger of the two for a profile-agnostic
;   upper bound should use the Profile B value (it is and will remain
;   the larger of the two — Profile B emits both ct_mul_8x8 and the
;   full sqtab apparatus that Profile A no longer needs).
;
;   Variant note (orthogonal to profile, per c64-lib-contract SPEC §5):
;   the aead-only archive (`make lib-aead-only`, #35) drops the
;   test-only chacha20_quarter_round body and pulls no word32_lib.o
;   into a minimal consumer that calls only the AEAD ABI. Measured
;   savings on the consumer-side link: 1024 B (5.96%) vs Profile B
;   full. The variant exposes its own equate below.
;
;     full        archive linked into Profile B min consumer : 17191 B
;     aead-only   archive linked into Profile B min consumer : 16167 B
; ---------------------------------------------------------------------------
.ifdef POLY1305_PROFILE_LONG
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 16384
.else
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 17664
.endif

; aead-only variant exposes its own equate so a consumer that
; specifically pins the trimmed archive can `.import` this name and
; static-assert against a tighter budget. Pattern follows §5's
; "library author refreshes them when a release substantively
; changes any one of them" — added on a MINOR release.
LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES = 16384

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_COLD_BYTES
;   Rough overlay-able cold footprint. No hot/cold split today; reserved
;   for future overlay layout. Reports 0 so consumers using a `.assert
;   cold <= N` check pass trivially today but get a real number once an
;   overlay split lands.
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_COLD_BYTES       = 0

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES
;   Bitmask of shared primitives (c64-lib-contract SPEC v0.2.0 §5
;   addendum + §8.0 bit allocation) that this library claims ownership
;   of in its default standalone build. Consumers OR together every
;   linked library's mask and assert the result has no duplicate bits,
;   catching shared-primitive double-ownership at assemble time.
;
;   SPEC §8.0 bit allocation:
;     $0001 LIB_SHARED_PRIMITIVES_SQTAB — 8×8 quarter-square multiply
;                                          table (defined in §8.1)
;     $0004 LIB_SHARED_PRIMITIVES_CT_MUL_8X8 — constant-time 8×8 multiply
;                                          body (defined in §8.3)
;
;   c64-ChaCha20-Poly1305 ships both the SPEC §8.1 sqtab and the §8.3
;   ct_mul_8x8 body today (it is the canonical owner of the latter), so in
;   its default standalone build this lib claims both bits ($0005). Each
;   bit is conditional on this build NOT deferring that primitive: defining
;   SHARED_SQTAB_INIT or SHARED_CT_MUL_8X8 drops the corresponding bit so a
;   consumer composing two libs that share a primitive sees disjoint masks
;   (issue #21). Future shared-primitive promotions OR in additional bits
;   per their §8.x sub-clause allocation, each gated on the same pattern.
; ---------------------------------------------------------------------------
LIB_SHARED_PRIMITIVES_SQTAB            = $0001   ; SPEC §8.0 / §8.1
LIB_SHARED_PRIMITIVES_CT_MUL_8X8       = $0004   ; SPEC §8.0 / §8.3
; Mask reflects primitives OWNED in THIS build config (SPEC §8.0, issue #21):
; a primitive's bit is included iff this build does NOT defer it via its
; SHARED_*_INIT / SHARED_* switch. A deferring build drops the bit so a
; consumer composing two libs that share a primitive sees disjoint masks.
.ifdef SHARED_SQTAB_INIT
  _OWN_SQTAB    = 0
.else
  _OWN_SQTAB    = LIB_SHARED_PRIMITIVES_SQTAB
.endif
.ifdef SHARED_CT_MUL_8X8
  _OWN_CT_MUL   = 0
.else
  _OWN_CT_MUL   = LIB_SHARED_PRIMITIVES_CT_MUL_8X8
.endif
LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES = _OWN_SQTAB | _OWN_CT_MUL

.export LIB_CHACHA20_POLY1305_REU_BANKS_USED
.export LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES
.export LIB_CHACHA20_POLY1305_RESIDENT_BYTES
.export LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES
.export LIB_CHACHA20_POLY1305_COLD_BYTES
; SPEC §8.0 / §8.1 manifest equates exported with `:abs` so ca65 emits
; them as absolute-address values rather than `zeropage`; integer-equate
; values up to $00ff would otherwise be tagged zeropage and trigger a
; `Range error: '5' out of range [0,0]` at the consumer-side .import.
.export LIB_SHARED_PRIMITIVES_SQTAB:abs
.export LIB_SHARED_PRIMITIVES_CT_MUL_8X8:abs
.export LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES:abs

; ---------------------------------------------------------------------------
; §8.0 catch-loop precalc-table enumeration. Per c64-lib-contract SPEC
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
; Profile A no longer emits sqtab itself (#34 F1) but the SPEC §8.1
; canonical-name back-link is still normative when *any* sibling lib
; in a composed build ships sqtab, so the enumeration row is emitted
; unconditionally to keep the §8.1 shared-primitive declaration
; consistent with this library's LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES
; mask (which also unconditionally claims the SQTAB bit).
LIB_PRECALC_TABLE "sqtab", 1024, PRECALC_REGION_RAM, PRECALC_SHARED_YES

; chacha_nibswap_hi_tab / chacha_nibswap_lo_tab — C4 branchless
; rotl-4 LUTs (commit d0b1d40). 256 B each, page-aligned in the CODE
; segment, hot-loop-read with secret-index `lda abs,x` (8 inlined
; call sites per double-round in chacha20_block). Library-specific:
; bit shape is generic (V<<4&$FF, V>>4) but no other adopter ships a
; rotl-4 fast path today; promote to §8.x only after a second sibling
; converges on bit-identical bytes.
LIB_PRECALC_TABLE "chacha_nibswap_hi_tab", 256, PRECALC_REGION_RAM, PRECALC_SHARED_NO
LIB_PRECALC_TABLE "chacha_nibswap_lo_tab", 256, PRECALC_REGION_RAM, PRECALC_SHARED_NO

; r_tab_lo / r_tab_hi — Profile A Shoup per-r tables at $6000..$7FFF
; (4096 B each, page-aligned per limb). Library-private: the content
; T_j[x] = x * r[j] is keyed off the per-message random Poly1305 `r`
; value, so no sibling lib can converge on the same bytes — there is
; no candidate §8.x shared-primitive promotion path. Profile B does
; not allocate these tables (uses sqtab via ct_mul_8x8 instead).
.ifdef POLY1305_PROFILE_LONG
LIB_PRECALC_TABLE "r_tab_lo", 4096, PRECALC_REGION_RAM, PRECALC_SHARED_NO
LIB_PRECALC_TABLE "r_tab_hi", 4096, PRECALC_REGION_RAM, PRECALC_SHARED_NO
.endif
