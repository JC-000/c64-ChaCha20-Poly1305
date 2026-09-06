; =============================================================================
; lib/shared_sqtab_init.s - c64-lib-contract SPEC §8.1 shared sqtab builder
;
; ONE TRANSLATION UNIT, ONE DISPLACEABLE GROUP. Split out of poly1305_lib.s
; for SPEC §6.1 member isolation (v1.2.0; carve-out v1.2.1; both collision
; directions named at v1.2.2), issue #108 item 2. This file exports the §8.1
; canonical `mul_tables_init` and its historical alias `sqtab_init` — the two
; names a build displaces together with `-D SHARED_SQTAB_INIT=1` — and
; NOTHING else a consumer may import. Everything else it defines (sq_acc,
; sq_sh, sq_ad, sq_i) is scratch for the body below and is referenced by no
; other TU, which is the clause's second conjunct.
;
; WHY THE §8.1 INIT AND THE §8.3 BODY ARE TWO FILES, NOT ONE. They are
; displaced by DIFFERENT switches: `SHARED_SQTAB_INIT` and
; `SHARED_CT_MUL_8X8`. `make lib-verify-shared` builds each deferral
; independently, so a consumer that defers one and owns the other is a
; configuration this library supports — and with the two groups in one
; member, deferring only §8.1 would still drag the §8.3 body into the link
; beside the consumer's own. (c64-x25519's src/mul_8x8.s keeps all eight in
; one TU; that is the arrangement this file deliberately does not copy.)
;
; WHY `mul_tables_init` AND `sqtab_init` MAY SHARE A TU. They are two labels
; on one body at one address, dropped by one switch. §6.1's literal
; per-name reading — "other displaceable names included" — cannot be the
; operative one for a group like this: §8.3's `smc_sum_a_imm` is a label
; INSIDE the ct_mul_8x8 body, so a strict one-name-per-TU rule is
; unsatisfiable by construction. The reading that is satisfiable, and that
; matches what the clause is for (a member is pulled or not as a unit), is
; that names displaced by the SAME switch form one group and belong in one
; TU. That is the shape #108 itself describes as conformant for §8.3.
;
; PROFILE A EMITS NOTHING FROM THIS FILE. Issue #34 F1 gated sqtab out of
; Profile A entirely, so under -DPOLY1305_PROFILE_LONG=1 this TU is empty.
; So is a `-D SHARED_SQTAB_INIT=1` build: an empty member is never pulled,
; which is exactly what the deferral wants.
;
; DO NOT REORDER. This TU's contribution to LIB_CHACHA20_POLY1305_CODE sits
; between poly1305_lib.o's and shared_prod_scratch.o's, and the Makefile
; link lines depend on that order to keep the profile PRGs byte-identical.
; =============================================================================

.setcpu "6502"

; Profile A emits no sqtab at all (issue #34 F1), and a
; `-D SHARED_SQTAB_INIT=1` build hands the primitive to the designated
; owner — in both cases this TU is empty and its member is never pulled.
.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_SQTAB_INIT
.export mul_tables_init         ; SPEC §8.1 canonical entry point
.export sqtab_init              ; historical name for the same address
; The two names MUST resolve to the same address, and this is the only thing
; that checks it. `make lib-verify-shared` cannot: `od65 --dump-exports`
; emits names without addresses, so every grep-based leg there is satisfied
; by mere presence. An owner build that exported `mul_tables_init` as a
; separate stub while leaving the real body on `sqtab_init` passes that
; target, and hands a deferring sibling a routine that builds no table —
; silently, because there is no unresolved external to notice.
;
; It fires at LINK, not at `make lib`. The operands are relocatable, so ca65
; defers the assert to ld65 regardless of the action keyword (the same
; property documented at the head of data_lib.s's segment). `make lib` only
; assembles and archives, so it cannot catch this; the library's own
; `make profile-b` does, and so does every consumer link against the
; archive — both verified against the stub mutation. Do not read a clean
; `make lib` as evidence for this invariant.
;
; Found by adversarial review of #105, as the mutation that survived the
; checks added with it.
.assert mul_tables_init = sqtab_init, lderror, "mul_tables_init and sqtab_init must be the same address: the canonical §8.1 name and its historical alias are one body, not two"
.endif
.endif

.segment "LIB_CHACHA20_POLY1305_CODE"   ; SPEC §4 prefix (issue #48)

.ifndef POLY1305_PROFILE_LONG
; Quarter-square table addresses (page-aligned for speed). Profile B only.
; The default lives in one place (src/include/sqtab_base.inc) so src/main.s's
; §6.7 image guard cannot drift onto a different window than the table
; actually occupies; a multi-lib PRG supplies a single
; `-D LIB_SHARED_SQTAB_BASE=0x<addr>` and every §8.1 adopter agrees.
.include "sqtab_base.inc"
sqtab_lo        = LIB_SHARED_SQTAB_BASE
sqtab_hi        = LIB_SHARED_SQTAB_BASE + $0200
.assert sqtab_hi = sqtab_lo + $0200,        error, "sqtab_hi must follow sqtab_lo by $0200"
.endif


; =============================================================================
; sqtab_init - Build quarter-square lookup table at sqtab_lo/sqtab_hi
;               (default $8000-$83FF; consumer-overridable via
;                LIB_SHARED_SQTAB_BASE per SPEC §8.1).
;
; Profile B only — Profile A's shoup_init populates r_tab_{lo,hi}
; incrementally and does not touch sqtab (issue #34 F1).
;
; Computes floor(i^2/4) for i = 0..511 using recurrence i^2 = (i-1)^2 + 2i - 1
; Ported from c64-aes256-ecdsa fp_init_sqtab.
;
; Clobbers: A, X, Y
;
; SPEC §8.1 migration switch: when a consumer links several §8.1
; adopters into one PRG, exactly one lib (or the consumer itself)
; owns the canonical `mul_tables_init` and defines SHARED_SQTAB_INIT.
; All other adopters gate out their own init body (and its scratch)
; to avoid linker symbol collisions and duplicate ~80 k cy boot work.
; Standalone builds (SHARED_SQTAB_INIT undefined) emit this lib's
; init as before — byte-identical to prior releases.
; =============================================================================
.ifndef POLY1305_PROFILE_LONG
.ifndef SHARED_SQTAB_INIT
mul_tables_init:                ; SPEC §8.1 canonical name
sqtab_init:                     ; historical name, same address
        lda #0
        sta sq_acc              ; accumulator = 0
        sta sq_acc+1
        sta sq_acc+2
        sta sq_i                ; index = 0
        sta sq_i+1

@loop:
        ; Compute f(i) = sq_acc >> 2 (divide by 4)
        lda sq_acc+2
        lsr
        sta sq_sh+2
        lda sq_acc+1
        ror
        sta sq_sh+1
        lda sq_acc
        ror
        sta sq_sh
        lsr sq_sh+2
        ror sq_sh+1
        ror sq_sh

        ; Store in table at index sq_i (0..511)
        ldx sq_i                ; low byte of index
        lda sq_i+1
        beq @pg0
        ; Page 1 (256..511)
        lda sq_sh
        sta sqtab_lo+256,x
        lda sq_sh+1
        sta sqtab_hi+256,x
        jmp @advance
@pg0:
        lda sq_sh
        sta sqtab_lo,x
        lda sq_sh+1
        sta sqtab_hi,x

@advance:
        ; sq_acc += 2*i + 1 (recurrence: (i+1)^2 = i^2 + 2i + 1)
        lda sq_i
        asl
        sta sq_ad
        lda sq_i+1
        rol
        sta sq_ad+1
        inc sq_ad
        bne :+
        inc sq_ad+1
:
        clc
        lda sq_acc
        adc sq_ad
        sta sq_acc
        lda sq_acc+1
        adc sq_ad+1
        sta sq_acc+1
        lda sq_acc+2
        adc #0
        sta sq_acc+2

        inc sq_i
        bne :+
        inc sq_i+1
:       lda sq_i+1
        cmp #2                  ; check if i reached 512 (0x200)
        beq @done
        jmp @loop
@done:  rts

; Temporaries for sqtab_init
sq_acc: .res 3, 0              ; 24-bit accumulator for i^2
sq_sh:  .res 3, 0              ; 24-bit shifted result (i^2 / 4)
sq_ad:  .res 2, 0              ; 16-bit addition term (2i+1)
sq_i:   .res 2, 0              ; 16-bit index counter (0..511)
.endif ; .ifndef SHARED_SQTAB_INIT — see SPEC §8.1
.endif          ; .ifndef POLY1305_PROFILE_LONG (issue #34 F1)
