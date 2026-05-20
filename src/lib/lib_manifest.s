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
;
;   c64-ChaCha20-Poly1305 ships the SPEC §8.1 sqtab today, so this lib
;   claims only that bit. Future shared-primitive promotions (e.g.
;   ct_mul_8x8 once two adopters confirm bit-identical bodies) will OR
;   in additional bits per their §8.x sub-clause allocation.
; ---------------------------------------------------------------------------
LIB_SHARED_PRIMITIVES_SQTAB            = $0001   ; SPEC §8.0 / §8.1
LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES = LIB_SHARED_PRIMITIVES_SQTAB

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
.export LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES:abs
