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
;   .assert (LIB_NISTCURVES_REU_BANKS_USED & LIB_CHACHA20_POLY1305_REU_BANKS_USED) = 0
;
; Bitwise `&`, not ca65's boolean `.and` (contract v0.4.2, contract #41):
; with `.and` the expression is true whenever both masks are non-zero
; regardless of which bits are set, so a real bank collision passes
; silently. This snippet is copy-paste-facing — it must work as written.
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
;   $02-$03 chacha20poly1305_zp_tmp1/2              (2 B)
;   $04-$09 w32_src1/src2/dst      (6 B)
;   $14-$19 cc20_round..buf_pos    (6 B)
;   $1A-$1F poly_i..ct_sign_mask   (6 B — $1E/$1F are Profile B only)
;   $40-$7F cc20_work hot state    (64 B)
;   $FB-$FE chacha20poly1305_zp_ptr1/2              (4 B)
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
;   MEASUREMENT BASIS (rebased for v0.7.0). These numbers are now the
;   library's OWN segment contribution — the sum of
;   LIB_CHACHA20_POLY1305_CODE + LIB_CHACHA20_POLY1305_DATA across the
;   archive's member objects, via `od65 --dump-segsize`.
;
;   Through v0.6.0 the basis was "PRG file size minus the 2-byte
;   LOADADDR header", measured from build/profile-*/*.prg. That number
;   included things no consumer links — the harness main.s stub, the
;   BASIC stub, and (after the issue #48 segment migration) 255 B of
;   inter-segment pad created by the 1-byte lib_entry stub holding
;   $0900. It also moved when the TEST HARNESS layout changed, which is
;   not a property of the library at all. By v0.7.0 that had made the
;   equates UNDER-report the real consumer-side link — the dangerous
;   direction for a consumer's `.assert resident <= N` fit check.
;
;   The segment-sum basis is consumer-independent: it does not move with
;   anyone's cfg, padding, or entry stub, and it is exactly what SPEC §5
;   asks for ("code+rodata footprint that must remain CPU-resident in
;   any consumer"). Reproduce with:
;
;     make lib && for o in build/lib/objs/*.o; do od65 --dump-segsize $o; done
;
;   Measured (SPEC §14.1 domain-guard re-measure; +96 B CODE in EVERY
;   configuration over the aead_tag numbers — the two guard expansions
;   at each of the two entry points, 47 B per entry point, plus the
;   2-byte `lda #AEAD_OK` that gave aead_encrypt a success return):
;     Profile A full       15 568 B  (CODE 15 273 + DATA 295) -> 15 872
;     Profile A aead-only  15 243 B  (CODE 14 948 + DATA 295) -> 15 360
;     Profile B full       16 841 B  (CODE 16 546 + DATA 295) -> 17 152
;     Profile B aead-only  16 516 B  (CODE 16 221 + DATA 295) -> 16 640
;     Profile B app-owned  16 544 B  (CODE 16 249 + DATA 295) -> 16 896
;
;   THE MEASURED COLUMN DROPPED AT ISSUE #108 AND NO REAL BYTE MOVED.
;   Re-measured against v0.10.0 the five figures fell by 83, 83, 104, 104
;   and 145 B respectively, while all four profile PRGs stayed BYTE-IDENTICAL
;   to the release. Both facts are true because of what this basis does and
;   does not count.
;
;   `od65 --dump-segments` reports each OBJECT's segment size. That includes
;   `.align` fill emitted INSIDE a section and excludes the fill ld65 inserts
;   BETWEEN sections. #108 split poly1305_lib.s into seven TUs, which moved
;   the page-alignment pad for poly_reduce_shl6_tab from the first bucket to
;   the second: on Profile B, poly_ripple used to end at $1C98 inside
;   poly1305_lib.o's section with 104 B of counted `.align` fill following it,
;   and now ends at $1C98 with poly1305_core.o's section starting at $1D00 —
;   the same 104 B, in the same place in the image, uncounted. Same bytes,
;   same addresses, different bucket.
;
;   The declared literals below are UNCHANGED and remain correct: the
;   measurement fell, so each rounded-up literal now over-reports by more,
;   which is the safe direction for a consumer's `.assert resident <= N`.
;   Do not "correct" a literal downward on the strength of this: a consumer
;   linking the archive still pays the inter-section pad, so the literals
;   describe the real link more honestly than the measured column now does.
;
;   THREE OF THESE LITERALS WERE UNDER-REPORTING AND NOTHING CAUGHT IT.
;   The domain guards pushed Profile A full (15 616 -> actual 15 651),
;   Profile B full (16 896 -> 16 945) and Profile B app-owned
;   (16 640 -> 16 689) past their declared values. Under-reporting is the
;   DANGEROUS direction: a consumer's `.assert resident <= N` fit check
;   under-reserves and the overrun is silent.
;
;   These four (now five) literals are hand-maintained with NO automated
;   check — unlike LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES, which
;   tools/verify_zp_usage.py pins against the built objects. Nothing in
;   the build, in `make test`, or in any audit would have flagged the
;   overrun above; it was found only because a footprint measurement was
;   run by hand. A verify-resident-bytes audit on the same pattern as
;   verify_zp_usage.py is the obvious closure and is tracked as wave 3
;   item F. Until it exists, RE-MEASURE THESE BY HAND whenever you add
;   code to a library TU. This one-liner sums the two segments across a
;   variant's objects and prints the total, which should equal the
;   "measured" figure in the table above for whichever variant you built:
;
;     make lib && od65 --dump-segments build/lib/objs/*.o | awk '
;       /Index:/{n=""} /Name:/{n=$2}
;       /Size:/ && n ~ /LIB_CHACHA20_POLY1305_(CODE|DATA)/ {s+=$2; k++}
;       END{ if (k==0) {
;              print "FATAL: matched 0 CODE/DATA segments." > "/dev/stderr"
;              print "  Wrong path, an .a archive, or od65 format changed." > "/dev/stderr"
;              exit 1 }
;            print s }'
;
;   Substitute objs-aead-only / objs-app-owned (after `make lib-aead-only`
;   / `make lib-app-owned`) or build/profile-a for the other rows. Compare
;   the result against the literal THIS build's .ifdef selects, below.
;
;   THE k==0 GUARD AND THE `/Index:/{n=""}` RESET ARE LOAD-BEARING. Do not
;   simplify them away:
;
;     * od65 EXITS 0 on a .a archive, printing only "(no xo65 object
;       file)". Without the k==0 check the pipeline sums nothing, prints a
;       blank line and succeeds — and since the basis note above says
;       "archive's member objects", pointing this at the .a is the natural
;       user error. tools/verify_zp_usage.py:69-81 guards the same trap
;       for the same reason ("audit would be vacuous").
;     * Same silent-blank outcome for a mistyped path or an empty glob.
;     * The sum assumes `Name:` precedes `Size:` inside each segment
;       block. That holds today (verified: 48/48 blocks), but resetting n
;       at each `Index:` means a future od65 that reversed them would
;       match nothing and trip the k==0 check, rather than silently
;       attaching sizes to the wrong names.
;
;   An instruction that reports success when it has measured nothing is
;   the defect this whole note exists to warn about.
;
;   VARIANT-AWARE as of issue #69. Until then this equate was gated on
;   the profile only, so the aead-only archive shipped a manifest
;   describing the FULL build — it reported 16 896 against a measured
;   16 513, i.e. it described a build the consumer had not linked.
;   Contract #62 is the general form of that defect. It over-reported,
;   which is the safe direction for a `.assert resident <= N` fit check,
;   and 383 B on 16 513 is 2.3% — inside §5's "within 5% is fine" — so
;   this is a truthfulness fix rather than a bug fix. Each archive now
;   describes itself.
;
;   Each is rounded UP to the next 256-byte boundary, so the equate is
;   always >= actual (safe direction) and absorbs incidental growth
;   between releases without forcing consumer `.assert` rewrites.
;   Update on each release.
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
;     full        archive linked into Profile B min consumer : 17702 B
;     aead-only   archive linked into Profile B min consumer : 16678 B
;
;   (Those two are whole-PRG figures for test_consumer/ and include its
;   own stub, BASIC header and cfg padding — quoted only to show the
;   variant delta. The equates themselves use the segment-sum basis
;   described above, which is why they are smaller.)
; ---------------------------------------------------------------------------
.ifdef POLY1305_PROFILE_LONG
  ; Profile A: issue #34 F1 already gated sqtab / sqtab_init / mul_8x8 and
  ; the ct_mul_8x8 body out of this profile, so the §8.1/§8.3 deferral
  ; switches remove nothing further — an app-owned Profile A build
  ; measures the same 15 651 B as a full one (was 15 555 before the
  ; §14.1 domain guards; see the table above).
  .ifdef LIB_VARIANT_AEAD_ONLY
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 15360
  .else
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 15872
  .endif
.else
  .ifdef LIB_VARIANT_AEAD_ONLY
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 16640
  .else
    .ifdef SHARED_CT_MUL_8X8
      ; app-owned (issue #74): §8.3 body + §8.1 init deferred to the
      ; consumer. Measured 16 689 B (was 16 593 before the §14.1 domain
      ; guards, which pushed it past the old 16 640 literal — hence the
      ; bump to 16 896 here).
      ;
      ; A build that is BOTH aead-only and app-owned lands in the
      ; aead-only branch above at 16 640, which OVER-reports it — the
      ; safe direction, and no shipped target combines them.
      ;
      ; That holds by construction, not by measurement, and the argument
      ; is worth stating because the figure to compare against is NOT
      ; this 16 689. Both switches are purely subtractive `.ifndef`
      ; gates: LIB_VARIANT_AEAD_ONLY removes the test-only bodies
      ; (chacha20_lib.s, poly1305_lib.s, word32_lib.s) and SHARED_*
      ; removes the §8.1 init and §8.3 ct_mul bodies, replacing each
      ; with an `.import` that emits no segment bytes. A build defining
      ; both therefore removes the UNION and measures at most
      ; min(aead-only, app-owned) = 16 620, which is under the 16 640 it
      ; is declared. Comparing 16 640 against this branch's own 16 689
      ; is the wrong comparison and makes a safe case look dangerous.
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 16896
    .else
LIB_CHACHA20_POLY1305_RESIDENT_BYTES   = 17152
    .endif
  .endif
.endif

; aead-only variant exposes its own equate so a consumer holding the
; FULL archive can see what the trimmed variant would cost before
; switching to it. Pattern follows §5's "library author refreshes them
; when a release substantively changes any one of them" — added on a
; MINOR release.
;
; Profile-aware as of issue #69: it reports the aead-only footprint of
; THIS profile, so it stays meaningful whichever profile is built. In an
; aead-only build it necessarily equals RESIDENT_BYTES above — that
; redundancy is deliberate, since a consumer pinning the trimmed archive
; may import either name.
;
; Note §5 does not define this name, so a consumer following the spec
; alone would not know to import it. That is why RESIDENT_BYTES itself
; had to become variant-aware rather than leaving this as the only
; accurate figure.
.ifdef POLY1305_PROFILE_LONG
LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES = 15360
.else
LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES = 16640
.endif

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_COLD_BYTES
;   Rough overlay-able cold footprint. No hot/cold split today; reserved
;   for future overlay layout. Reports 0 so consumers using a `.assert
;   cold <= N` check pass trivially today but get a real number once an
;   overlay split lands.
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_COLD_BYTES       = 0

; ---------------------------------------------------------------------------
; LIB_CHACHA20_POLY1305_AAD_LEN_MAX
;   Maximum AAD length in bytes, published per c64-lib-contract SPEC §5:
;   "Where a library's real input restriction is a bound a consumer must
;   respect — a maximum length, a ceiling — it SHOULD publish that bound
;   here as a symbol the consumer can reference."
;
;   This one is real and structural rather than a policy choice:
;   `aead_aad_len` is a single byte (`src/lib/data_lib.s`), so 255 is the
;   largest AAD this ABI can express. A consumer with more AAD than this
;   has no way to pass it and must be told at assemble time, not by
;   discovering that byte 256 wrapped.
;
;   Consumers SHOULD reference this symbol rather than re-derive 255 from
;   the field width, which is exactly the re-derivation §5 asks them not
;   to do:
;
;     .import LIB_CHACHA20_POLY1305_AAD_LEN_MAX
;     .assert MY_AAD_LEN <= LIB_CHACHA20_POLY1305_AAD_LEN_MAX, error, "AAD too long for this library"
;
;   NOT published, deliberately: the buffer-domain restriction
;   `ptr + len <= $10000` on the data and AAD buffers. That is a RELATION
;   over two caller-supplied values, not a constant — a 65 535-byte buffer
;   is legal at $0000 and illegal at $0001 — so no scalar expresses it and
;   §5 says to publish nothing rather than something vacuous. It is
;   enforced at both entry points instead, returning AEAD_ERR_DOMAIN.
;   There is likewise no ceiling on `aead_data_len`: it is a full 16-bit
;   count and the library owns neither buffer.
; ---------------------------------------------------------------------------
LIB_CHACHA20_POLY1305_AAD_LEN_MAX      = 255

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
;   ct_mul_8x8 body today (it is the canonical owner of the latter, and
;   as of issue #47 actually EXPORTS `ct_mul_8x8` so a sibling can defer
;   to it — before that the ownership claim here was unsatisfiable), so in
;   its default standalone build this lib claims both bits ($0005). Each
;   bit is conditional on this build NOT deferring that primitive: defining
;   SHARED_SQTAB_INIT or SHARED_CT_MUL_8X8 drops the corresponding bit so a
;   consumer composing two libs that share a primitive sees disjoint masks
;   (issue #21). Future shared-primitive promotions OR in additional bits
;   per their §8.x sub-clause allocation, each gated on the same pattern.
; ---------------------------------------------------------------------------
LIB_SHARED_PRIMITIVES_SQTAB            = $0001   ; SPEC §8.0 / §8.1
LIB_SHARED_PRIMITIVES_CT_MUL_8X8       = $0004   ; SPEC §8.0 / §8.3

; ---------------------------------------------------------------------------
; SPEC §8.0 three-state build-config semantics (contract v0.5.0).
;
; For each §8.x primitive, a build config is in exactly one of three states,
; and the ownership bit alone cannot distinguish the last two — they impose
; OPPOSITE obligations on the composing consumer:
;
;   owner               PRIMITIVES set, CONSUMES set. Exports the body/init
;                       per the primitive's §8.x clause.
;   deferring consumer  PRIMITIVES clear, CONSUMES set. The deferral switch
;                       is defined, but the build still READS the primitive
;                       at runtime: the composed link MUST contain exactly
;                       one owner, and boot MUST initialize it first.
;   non-consumer        both clear. Profile-gated or permanent; the
;                       primitive's surface is absent and there is no
;                       provider obligation at all.
;
; Two independent gates therefore drive the two masks:
;
;   profile gate    drops the bit from BOTH masks (we do not use the
;                   primitive in this profile at all)
;   SHARED_* switch drops the bit from the OWNERSHIP mask only (we still
;                   use it, someone else provides it)
;
; Profile A is a profile-gated NON-CONSUMER of both primitives. Issue #34 F1
; gated sqtab, sqtab_init and mul_8x8 out of Profile A entirely (shoup_init
; builds the per-r Shoup tables via incremental ripple-add and never touches
; sqtab), and the ct_mul_8x8 body lives under .ifndef POLY1305_PROFILE_LONG.
;
; Before issue #51 neither mask had a profile gate, so Profile A advertised
; ownership of $0005 — two primitives it does not emit. Measured on the
; pre-fix tree: profile-a/poly1305_lib.o exports none of sqtab_init /
; ct_mul_8x8 / mul_8x8, while profile-a/lib_manifest.o exported
; LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES = $0005. A consumer composing
; Profile A with c64-x25519 then saw a false double-ownership collision on
; the §8.0 disjointness assert, and the v0.5.0 coverage assert concluded
; sqtab had an owner in the link when this library provides no sqtab_init
; at all — the silent-wrong-result direction (table read with no init).
;
; Resulting matrix:
;
;   build                                    PRIMITIVES  CONSUMES
;   Profile A                                   $0000     $0000
;   Profile B standalone                        $0005     $0005
;   Profile B -D SHARED_CT_MUL_8X8              $0001     $0005
;   Profile B -D SHARED_SQTAB_INIT
;             -D SHARED_CT_MUL_8X8              $0000     $0005
;
; The deferral rows only became meaningful with issue #47, which made
; SHARED_CT_MUL_8X8 gate the body and exports rather than just this mask.
; ---------------------------------------------------------------------------

; Profile gate — consumption. Drops bits from BOTH masks.
.ifdef POLY1305_PROFILE_LONG
  _USE_SQTAB    = 0
  _USE_CT_MUL   = 0
.else
  _USE_SQTAB    = LIB_SHARED_PRIMITIVES_SQTAB
  _USE_CT_MUL   = LIB_SHARED_PRIMITIVES_CT_MUL_8X8
.endif

; Deferral gate — ownership. A primitive is owned iff it is consumed AND
; this build does not defer it (SPEC §8.0 required form, issue #21).
.ifdef SHARED_SQTAB_INIT
  _OWN_SQTAB    = 0
.else
  _OWN_SQTAB    = _USE_SQTAB
.endif
.ifdef SHARED_CT_MUL_8X8
  _OWN_CT_MUL   = 0
.else
  _OWN_CT_MUL   = _USE_CT_MUL
.endif

LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES = _OWN_SQTAB | _OWN_CT_MUL
LIB_CHACHA20_POLY1305_SHARED_CONSUMES   = _USE_SQTAB | _USE_CT_MUL

; SPEC §8.0 adopter-side invariant: ownership bits are a subset of consumes
; bits. Pinned here so a future gate edit that reintroduces the issue-#51
; shape fails at assemble time instead of misleading a consumer.
.assert (LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES & ~LIB_CHACHA20_POLY1305_SHARED_CONSUMES) = 0, error, "a build cannot own a primitive it does not consume"

; All §5 aggregates are exported `:abs` (issue #62). Without the hint
; ca65 infers the address size from the VALUE, so the byte-valued ones
; (REU_BANKS_USED = $00, ZP_USAGE_BYTES = 88, COLD_BYTES = 0) come out
; `zeropage` while a consumer's `.import` defaults to absolute:
;
;   ld65: Warning: Address size mismatch for
;         'LIB_CHACHA20_POLY1305_REU_BANKS_USED': Exported from
;         lib_manifest.o as 'zeropage', import in two.o as 'absolute'
;
; The link succeeds and the asserts evaluate, but the diagnostic tracks
; the value rather than the interface — REU_BANKS_USED would stop
; warning if this library ever claimed a bank above $FF and resume if it
; dropped back — and the obvious consumer workaround
; (`.import ...: zeropage`) pins a manifest constant to an address size
; that is an artifact of its current value. These are 16-bit manifest
; quantities regardless of what they happen to hold today.
.export LIB_CHACHA20_POLY1305_REU_BANKS_USED:abs
.export LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES:abs
.export LIB_CHACHA20_POLY1305_RESIDENT_BYTES:abs
.export LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES:abs
.export LIB_CHACHA20_POLY1305_COLD_BYTES:abs
.export LIB_CHACHA20_POLY1305_AAD_LEN_MAX:abs
; SPEC §8.0 / §8.1 manifest equates exported with `:abs` so ca65 emits
; them as absolute-address values rather than `zeropage`; integer-equate
; values up to $00ff would otherwise be tagged zeropage and trigger a
; `Range error: '5' out of range [0,0]` at the consumer-side .import.
;
; The §8.x BIT CONSTANTS (LIB_SHARED_PRIMITIVES_SQTAB /
; _CT_MUL_8X8) are deliberately NOT exported (issue #57 item 2). They are
; unprefixed names with identical values in every adopter, so exporting
; them collides at link exactly like the deprecated bare §1 names — and
; unlike those, no SPEC clause ever asked for the export:
;
;   ld65: Error: Duplicate external identifier: 'LIB_SHARED_PRIMITIVES_CT_MUL_8X8'
;
; §8.1/§8.2/§8.3 present the bit constants as plain assemble-time equates
; that each adopter declares locally and consumers copy verbatim; the
; v0.6.1 §13.0 clause states the reasoning outright for the analogous
; NET_FAMILY_* bits — both sides of the link carry the header, and only
; exported symbols can collide. They exist to BUILD the two masks below,
; which are the prefixed symbols actually meant to cross the link.
; c64-nist-curves has always kept them local, which is why the collision
; never surfaced against that library.
.export LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES:abs
.export LIB_CHACHA20_POLY1305_SHARED_CONSUMES:abs

; ---------------------------------------------------------------------------
; §8.4 catch-loop precalc-table enumeration — MOVED, deliberately.
;
; The LIB_PRECALC_TABLE invocations and the `.include "precalc_table.inc"`
; that used to close this file now live in src/lib/precalc_manifest.s.
; Do not move them back: each invocation emits a DEPRECATED bare
; LIB_PRECALC_<name>_* triple, which is displaceable under
; `-D LIB_NO_BARE_EXPORTS=1` and is the exact spelling a sibling adopter's
; own §8.4 enumeration exports. c64-lib-contract SPEC §6.1 member isolation
; (v1.2.0; carve-out v1.2.1; both collision directions spelled out at
; v1.2.2) therefore forbids it from sharing a member with the §5 aggregates
; and §8.0 masks above — those are counterparts of nothing displaceable, so
; they are "something else a consumer may import" and their co-residency
; kept the bare triples un-droppable in any composed link. Issue #108 item 1;
; ruled in contract #186, and c64-x25519 v0.14.0 made the same split.
; ---------------------------------------------------------------------------
