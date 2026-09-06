; =============================================================================
; chacha20poly1305.inc — public interface for the c64-ChaCha20-Poly1305 library
;
; Assembler: ca65/ld65 (cc65 suite).  Target: Commodore 64, no REU required.
;
; Shipped by `make lib` to build/lib/chacha20poly1305.inc alongside the
; archive. The canonical source is src/chacha20poly1305.inc in the library
; repo; the copy under build/lib/ is a build product — edit the source,
; not the copy.
;
; This header is not required by c64-lib-contract. Its §6.1 briefly did
; require one, and the clause was withdrawn at v1.1.1 for naming neither a
; path nor a symbol (contract#178). It exists because a consumer fetching
; build/lib/ should get an interface rather than an archive to
; reverse-engineer.
;
; -----------------------------------------------------------------------------
; USING IT
; -----------------------------------------------------------------------------
;
;     .include "chacha20poly1305.inc"
;
; That is safe to do unconditionally. Every declaration below is an
; `.import`, and ca65 emits an import record only for a symbol the
; translation unit actually REFERENCES — measured on ca65 V2.18: a TU
; including this file whole and calling only the three AEAD entry points
; emits exactly three import records, and its linked PRG is byte-identical
; to one that imported those three by hand. So including this header does
; not drag unused archive members into your link, and does not break a
; link against a variant archive that omits some of these names.
;
; The file carries its own include guard, so including it more than once
; (directly and via another header) is harmless.
;
; -----------------------------------------------------------------------------
; WHAT IS NOT HERE, AND WHY
; -----------------------------------------------------------------------------
;
; **Zero-page slots.** This library uses the SPEC §6.2 consumer-assembled
; -source model: no archive member defines a ZP slot, so you assemble your
; own copy of the library's src/zp_config.s (or your edited replacement)
; and link it in. Overriding a slot is an edit or a `-D` on THAT assembly,
; never a define forwarded to a `lib*` make target — passing one there
; fails loudly with `Symbol 'chacha20poly1305_zp_tmp1' is already defined`
; rather than silently producing a mismatched archive. Importing the slots
; here would defeat that, so this header declares none of them.
;
; **§8.1 sqtab placement.** `LIB_SHARED_SQTAB_BASE` is consumer *input*
; and §8.1 forbids a library exporting it, or `sqtab_lo`/`sqtab_hi`. Set
; it with `ca65 -D LIB_SHARED_SQTAB_BASE=0x<addr>` ($-free — see the cfg).
;
; See docs/INTEGRATION.md for the full integration guide, docs/API.md for
; per-routine calling conventions, and docs/MEMORY_MAP.md for the regions
; this library claims.
; =============================================================================

.ifndef CHACHA20POLY1305_INC_INCLUDED
CHACHA20POLY1305_INC_INCLUDED = 1

; -----------------------------------------------------------------------------
; §1 version identification — pin the library you built against
; -----------------------------------------------------------------------------
;
; Guard with `.assert` / `lderror`, NEVER `.if` / `.error`: an `.import`ed
; symbol has no value until link, so ca65 rejects an `.if` gate outright
; with `Constant expression expected` and the guard never assembles at all.
; `.assert` + `lderror` defers to ld65, the only stage that knows the value
; — still before anything runs.
;
;     .assert (LIB_CHACHA20_POLY1305_VERSION_MAJOR > 0) .or (LIB_CHACHA20_POLY1305_VERSION_MINOR >= 8), lderror, "needs c64-ChaCha20-Poly1305 v0.8+"
;     .assert LIB_CHACHA20_POLY1305_ABI_VERSION = 4, lderror, "CCP exported-surface generation changed; re-check the integration"
;
; ABI_VERSION is a generation counter for the exported surface, not a
; mirror of MAJOR. It moves on any change that can break a conforming
; consumer — including an entry point's return set gaining a value, which
; is what took it to 4 (contract v1.1.0 §7).

.import LIB_CHACHA20_POLY1305_VERSION_MAJOR
.import LIB_CHACHA20_POLY1305_VERSION_MINOR
.import LIB_CHACHA20_POLY1305_VERSION_PATCH
.import LIB_CHACHA20_POLY1305_ABI_VERSION

; The unprefixed LIB_VERSION_* / LIB_ABI_VERSION forms are also exported,
; but are DEPRECATED: they are identical across every adopter, so linking
; two libraries and importing both manifests gives
; `ld65: Error: Duplicate external identifier`. They are deliberately not
; declared here. If you link two or more of these libraries, build them
; all with `-D LIB_NO_BARE_EXPORTS=1` and use the prefixed names above.

; -----------------------------------------------------------------------------
; §5 aggregate manifest equates — assemble-time fit checks
; -----------------------------------------------------------------------------
;
;     .import LIB_CHACHA20_POLY1305_RESIDENT_BYTES
;     .import __CRYPTO_HOT_SIZE__          ; ld65-published region size
;     .assert LIB_CHACHA20_POLY1305_RESIDENT_BYTES < __CRYPTO_HOT_SIZE__, error, "no room"
;
; RESIDENT and COLD are a pair; a consumer sizing one region budgets for
; both. All footprint equates round UP, so they are safe to bind to a
; budget. AEAD_ONLY_RESIDENT_BYTES is the tighter bound for consumers
; pinning the aead-only archive.

.import LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES
.import LIB_CHACHA20_POLY1305_REU_BANKS_USED
.import LIB_CHACHA20_POLY1305_RESIDENT_BYTES
.import LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES
.import LIB_CHACHA20_POLY1305_COLD_BYTES

; §8 shared-primitive masks. Compose them with a co-linked sibling's to
; check for double ownership and for a consumed primitive with no owner:
;
;     .assert (LIB_A_SHARED_PRIMITIVES & LIB_B_SHARED_PRIMITIVES) = 0, error, "double ownership"
;     .assert ((LIB_A_SHARED_CONSUMES | LIB_B_SHARED_CONSUMES) & ~(LIB_A_SHARED_PRIMITIVES | LIB_B_SHARED_PRIMITIVES | APP_OWNED)) = 0, error, "consumed primitive with no owner"

.import LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES
.import LIB_CHACHA20_POLY1305_SHARED_CONSUMES

; -----------------------------------------------------------------------------
; AEAD — the primary interface (RFC 8439 §2.8)
; -----------------------------------------------------------------------------
;
; Set the input fields, `jsr aead_encrypt` or `aead_decrypt`, read A.
;
;   aead_encrypt   A = AEAD_OK ($00)          ciphertext + aead_tag written
;                  A = AEAD_ERR_DOMAIN ($01)  out of domain, NOTHING written
;
;   aead_decrypt   A = AEAD_OK ($00)          tag valid, plaintext written
;                  A = AEAD_ERR_AUTH ($ff)    tag mismatch, buffer untouched
;                  A = AEAD_ERR_DOMAIN ($01)  out of domain, NOTHING written
;
; Handle all three. `aead_decrypt` gained $01 after v0.9.0, which is why
; ABI_VERSION is 4: exhaustive handling of {$00,$ff} became non-exhaustive.
;
; The domain, enforced at the entry ahead of every jsr, is
;
;     aead_data_ptr + aead_data_len <= $10000
;     aead_aad_ptr  + aead_aad_len  <= $10000
;
; A buffer ending exactly at $FFFF (sum == $10000) is IN domain. There is
; no length ceiling on the data buffer — the restriction is a relation
; over two caller-supplied values, so no single number expresses it and
; none is published. `aead_aad_len` is 8-bit, so AAD does carry a real
; ceiling; it is published as LIB_CHACHA20_POLY1305_AAD_LEN_MAX below.
;
; NOT checked, and the caller's precondition: whether your buffers overlap
; the regions this library claims. See docs/MEMORY_MAP.md §4.

.import aead_encrypt
.import aead_decrypt

; AEAD status codes. Assemble-time equates rather than imports — they are
; values, not addresses, and a consumer comparing against them needs them
; at assembly time. Keep in step with src/lib/chacha20poly1305_lib.s.
;
; Each is `.ifndef`-guarded so including this header cannot collide with a
; consumer that already defines the name — and each guard has an `.else`
; that ASSERTS the consumer's value matches. Without that assert the guard
; is a silent-wrong-answer machine: a consumer carrying its own
; `AEAD_OK = $42` from some other library would assemble clean here and
; then compare `aead_decrypt`'s return against $42, treating every
; successful decrypt as a failure and, worse, every authentication
; failure as something other than what it is. The guard exists to avoid a
; redefinition error, not to let two different meanings of the same name
; coexist.
.ifndef AEAD_OK
AEAD_OK         = $00
.else
.assert AEAD_OK = $00, error, "AEAD_OK is already defined with a different value than this library returns ($00)"
.endif
.ifndef AEAD_ERR_DOMAIN
AEAD_ERR_DOMAIN = $01
.else
.assert AEAD_ERR_DOMAIN = $01, error, "AEAD_ERR_DOMAIN is already defined with a different value than this library returns ($01)"
.endif
.ifndef AEAD_ERR_AUTH
AEAD_ERR_AUTH   = $ff
.else
.assert AEAD_ERR_AUTH = $ff, error, "AEAD_ERR_AUTH is already defined with a different value than this library returns ($ff)"
.endif

; Published input bound (§5): the AAD length field is one byte.
.import LIB_CHACHA20_POLY1305_AAD_LEN_MAX

; AEAD input/output fields (all in LIB_CHACHA20_POLY1305_DATA).
.import aead_key            ; 32 B  key
.import aead_nonce          ; 12 B  nonce
.import aead_aad_ptr        ;  2 B  pointer to AAD
.import aead_aad_len        ;  1 B  AAD length, 0..LIB_CHACHA20_POLY1305_AAD_LEN_MAX
.import aead_data_ptr       ;  2 B  pointer to plaintext/ciphertext, in place
.import aead_data_len       ;  2 B  length, 16-bit, no cap
.import aead_tag            ; 16 B  output tag (encrypt) / expected tag (decrypt)

; -----------------------------------------------------------------------------
; Initialisation — required before first use
; -----------------------------------------------------------------------------
;
; `poly1305_lib_init` is the one-call entry a consumer needs; it builds
; whatever tables the linked profile requires. Idempotent.

.import poly1305_lib_init

; -----------------------------------------------------------------------------
; ChaCha20 stream cipher — for consumers wanting the cipher without the AEAD
; -----------------------------------------------------------------------------
;
; INCOMPLETE INPUT SURFACE, deliberately. `chacha20_encrypt` also reads
; `cc20_data_ptr` (2 B) and `cc20_remain` (1 B), which are ZERO-PAGE slots
; and so are not declared here — per §6.2 this library ships no ZP-defining
; archive member, and you supply those addresses by assembling your own
; copy of the library's src/zp_config.s (see "WHAT IS NOT HERE" above).
; `cc20_remain_hi` below is the DATA-resident high byte and IS importable.
; The same applies to the Poly1305 subset, which uses
; `chacha20poly1305_zp_ptr1`. If you are calling anything in these two
; sections rather than the AEAD entry points, read src/zp_config.s and
; docs/API.md alongside this header — the AEAD surface is the one that is
; complete here.

.import chacha20_init
.import chacha20_block
.import chacha20_encrypt
.import cc20_key            ; 32 B
.import cc20_nonce          ; 12 B
.import cc20_counter        ;  4 B  block counter
.import cc20_state          ; 64 B  working state
.import cc20_remain_hi

; -----------------------------------------------------------------------------
; Poly1305 MAC — for consumers wanting the MAC alone
; -----------------------------------------------------------------------------

.import poly1305_init
.import poly1305_clamp
.import poly1305_block
.import poly1305_update
.import poly1305_final
.import poly1305_tag        ; 16 B  output tag
.import poly_r              ; key r, clamped
.import poly_s              ; key s
.import poly_h              ; accumulator

; -----------------------------------------------------------------------------
; §8.1 / §8.3 shared primitives — only if you compose this with a sibling
; -----------------------------------------------------------------------------
;
; In the DEFAULT Profile B build this library OWNS both, and exports them
; for a sibling to defer to (SHARED_PRIMITIVES = $0005):
;
;   §8.1  mul_tables_init   canonical quarter-square table init, idempotent.
;                           sqtab_init is the historical name for the same
;                           address, kept for back-compat.
;   §8.3  ct_mul_8x8        canonical constant-time 8x8->16 body, with its
;                           product scratch and the two SMC operand sites
;                           the caller bakes `a` into before the inner loop.
;
; In the `lib-app-owned` archive both are DEFERRED: none of these names is
; exported and the consumer must supply them. In Profile A neither is
; owned nor consumed (SHARED_CONSUMES = $0000) and none is exported.
;
; So these are commented out rather than declared: which of them exists
; depends on the archive you linked, and an unconditional import here
; would be a name this header promises and some archives do not keep.
;
;     .import mul_tables_init
;     .import sqtab_init
;     .import ct_mul_8x8
;     .import poly_prod_lo, poly_prod_hi
;     .import smc_sum_a_imm, smc_diff_a_imm

.endif  ; CHACHA20POLY1305_INC_INCLUDED
