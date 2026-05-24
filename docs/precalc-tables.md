# Precalculated tables — c64-ChaCha20-Poly1305

Per c64-lib-contract SPEC v0.3.1 §8.0 catch-loop. Lists every
precomputed table in this library that clears the §8.0 floor
(>= 256 B AND one of: REU-resident, hot-loop-read, page-aligned for
fetch alignment).

The enumeration is emitted in `src/lib/lib_manifest.s` via the
canonical `LIB_PRECALC_TABLE` macro from `src/precalc_table.inc`
(copied byte-for-byte from c64-lib-contract@b039ab9). Each
invocation exports three equates per table:
`LIB_PRECALC_<name>_{SIZE,REGION,SHARED}`. Consumer-side audits
grep on these to detect bit-identical precalc shapes across sibling
libs that should be promoted to a §8.x shared-primitive clause.

## Enumerated tables

| Name | Size | Region | Source | Classification | Rationale |
|---|---|---|---|---|---|
| `sqtab` | 1024 B | main RAM | `src/lib/poly1305_lib.s` (sqtab_lo at `LIB_SHARED_SQTAB_BASE`; sqtab_hi at base+`$0200`) | **Shared via §8.1** | Quarter-square table for 8x8 multiply: `tab[a+b] - tab[a-b]`, bit-identical shape across nist-curves, x25519, ChaCha20-Poly1305. Already pinned by SPEC §8.1 (`LIB_SHARED_SQTAB_BASE` equate; consumer overrides via `--asm-define`). This library claims the §8.1 bit in `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES`. |
| `chacha_nibswap_hi_tab` | 256 B | main RAM (CODE segment, `.align 256`) | `src/lib/data_lib.s` | **Library-specific** | C4 branchless rotl-4: `tab[V] = (V << 4) & $FF`. Page-aligned to keep `lda abs,x` strictly constant-time with a secret-derived index (CT posture). Read 8x per ChaCha20 double-round across the looped `chacha20_block` body. Bit shape is generic but no other adopter ships a rotl-4 fast path today; promote to §8.x only after a second sibling converges on bit-identical bytes. |
| `chacha_nibswap_lo_tab` | 256 B | main RAM (CODE segment, `.align 256`) | `src/lib/data_lib.s` | **Library-specific** | Companion to `chacha_nibswap_hi_tab`: `tab[V] = V >> 4`. Same alignment / CT posture / hot-loop-read profile. Same library-private classification rationale. |
| `r_tab_lo` | 4096 B | main RAM (`$6000..$6FFF`) | `src/lib/poly1305_lib.s` (Profile A `shoup_init`, allocated via equate in `src/lib/constants_lib.s`) | **Library-specific** | Poly1305 Shoup precomputation, low byte: `T_j[x] = (x * r[j]) & $FF` for `j` in `[0..15]`, `x` in `[0..255]`. The table content is keyed off the per-message random Poly1305 `r` value, so no sibling lib can converge on the same bytes — no candidate §8.x promotion path. Profile A only; Profile B uses sqtab via `ct_mul_8x8` instead. |
| `r_tab_hi` | 4096 B | main RAM (`$7000..$7FFF`) | `src/lib/poly1305_lib.s` (Profile A `shoup_init`) | **Library-specific** | Hi byte of the same Shoup precomputation: `T_j[x] = (x * r[j]) >> 8`. Same library-private classification rationale as `r_tab_lo`. Profile A only. |

## Below the §8.0 floor (exempt)

These items appear in the library but do not meet the §8.0 floor
(either < 256 B, or not hot-loop-read / page-aligned / REU-resident),
so they are intentionally NOT enumerated via `LIB_PRECALC_TABLE`:

- **ChaCha20 "expand 32-byte k" constants** — 16 B inline literals in
  the initial state setup. Hot-loop-read in `chacha20_block` but
  trivially below the 256 B floor. Will never be a §8.x candidate.
- **Poly1305 padding / clamp masks** — small (< 32 B) inline byte
  constants in `poly1305_init`. Below the floor.
- **`sqtab_ready` flag** (1 B in `src/lib/data_lib.s`) — runtime
  boot-once gate, not a precomputed lookup. Below the floor.
- **`cc20_work` / `aead_scratch` / `buf` scratch regions** — runtime
  state buffers, not precomputed lookup tables. Out of scope for §8.0
  (the clause covers tables whose content is a pure function of
  compile-time constants or a one-time boot precomputation, not
  per-call working storage).

## Profile gating

Profile A (`POLY1305_PROFILE_LONG=1` build) emits all five rows:
`sqtab` + the two `chacha_nibswap_*` tables + the two `r_tab_*` tables.
Profile B emits three rows: `sqtab` + the two `chacha_nibswap_*` tables.
The two `r_tab_*` rows are gated behind `.ifdef POLY1305_PROFILE_LONG`
because Profile B does not allocate the Shoup r-tables (it falls back
to sqtab via `ct_mul_8x8`).

Verify post-build:

```
od65 --dump-exports build/profile-a/lib_manifest.o | grep LIB_PRECALC_ | wc -l
# expect 15 (5 tables * 3 equates)

od65 --dump-exports build/profile-b/lib_manifest.o | grep LIB_PRECALC_ | wc -l
# expect 9 (3 tables * 3 equates)
```

Spot-check the `sqtab` size equate:

```
od65 --dump-exports build/profile-a/lib_manifest.o | grep -A1 LIB_PRECALC_sqtab_SIZE
# Value: 0x00000400  (1024)
```

## Note on the `sqtab` row being unconditional

The `sqtab` enumeration row is emitted on both profiles even though
Profile A no longer allocates the table itself (issue #34 F1 gated
`sqtab_lo`/`sqtab_hi`/`sqtab_init`/`mul_8x8` out of Profile A). This
matches the unconditional `LIB_SHARED_PRIMITIVES_SQTAB` bit claim in
`LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES` and the SPEC §8.1
canonical-name back-link: when a composed build links this library
alongside a sibling that *does* ship sqtab, the §8.1 contract still
governs the shared sqtab placement, and the §8.0 enumeration row is
the catch-loop entry that points to that §8.1 clause.
