# c64-ChaCha20-Poly1305 — Consumer Memory Map (v0.6.0)

Static audit of the merged-main library state as of 2026-07-28
(v0.6.0 release). Sources: `src/c64.cfg`, `src/zp_config.s`,
`src/lib/constants_lib.s`, `src/lib/data_lib.s`,
`build/profile-{a,b}/labels.txt` (v0.6.0 build artifacts).

> **Scope note.** This document enumerates every address the library
> currently *claims*. As of v0.6.0 most claims are relocatable at
> assembly time: every ZP slot is an overridable default in
> `src/zp_config.s` (PR #32), and the sqtab base is configurable via
> `-DLIB_SHARED_SQTAB_BASE=<addr>` (default `$8000`; SPEC §8.1,
> PR #39). Only the Profile A Shoup `r_tab_lo`/`r_tab_hi` pages
> remain fixed-address (see "Relocation support" at the bottom). A
> consumer that co-locates this library with its own code must treat
> every non-overridden address in the collision-risk table as
> reserved.

---

## 1. Zero-page claims

Source-of-truth: `src/zp_config.s` (PR #32) — every slot is an
`.ifndef`-guarded default address, `.exportzp`-ed from that module;
`src/lib/constants_lib.s` now only `.importzp`s the slots. A host
project can pre-define any slot before `zp_config.s` is assembled
(or replace the file entirely) to relocate it. The `c64.cfg` `ZP`
memory region spans `$02..$9F` (158 bytes), which bounds the claim.

| range      | symbol            | size | owner module          | notes                                                         |
|------------|-------------------|-----:|-----------------------|---------------------------------------------------------------|
| `$02`      | `zp_tmp1`         | 1    | word32 / chacha20     | nibble-rotate scratch; used by `rotl32_4_zp` / `rotr32_4`      |
| `$03`      | `zp_tmp2`         | 1    | word32 / chacha20     | nibble-rotate scratch; paired with `zp_tmp1`                   |
| `$04..$05` | `w32_src1`        | 2    | word32                | 16-bit pointer, src operand for add32/xor32/copy32/rot helpers |
| `$06..$07` | `w32_src2`        | 2    | word32                | 16-bit pointer, second src operand                             |
| `$08..$09` | `w32_dst`         | 2    | word32                | 16-bit pointer, destination                                    |
| `$14`      | `cc20_round`      | 1    | chacha20              | double-round counter (0..10) for `chacha20_block`              |
| `$15`      | `cc20_qr_idx`     | 1    | chacha20 (test-only)  | quarter-round parameter index (test entry `chacha20_quarter_round`) |
| `$16..$17` | `cc20_data_ptr`   | 2    | chacha20 / aead       | 16-bit data pointer for `chacha20_encrypt`                    |
| `$18`      | `cc20_remain`     | 1    | chacha20 / aead       | bytes remaining (low byte); reused as a generic byte counter by `poly1305_update` |
| `$19`      | `cc20_buf_pos`    | 1    | chacha20              | XOR loop in-block position                                    |
| `$1a`      | `poly_i`          | 1    | poly1305              | outer loop counter; also used as the ov*5 hi scratch in `poly1305_reduce` (P4 fold) |
| `$1b`      | `poly_j`          | 1    | poly1305              | inner loop counter; reused by `shoup_init` as j-counter       |
| `$1c`      | `poly_carry`      | 1    | poly1305 / aead       | carry byte for multi-precision arith; AEAD `aead_verify_tag` CT OR-accumulator |
| `$1d`      | `poly_tmp`        | 1    | poly1305              | temp for multiply / `poly1305_reduce`                          |
| `$1e`      | `ct_diff_raw`     | 1    | poly1305 (Profile B)  | `ct_mul_8x8` scratch: raw `b - a` before sign-mask (v0.3.0 CT fix) |
| `$1f`      | `ct_sign_mask`    | 1    | poly1305 (Profile B)  | `ct_mul_8x8` scratch: `$00` if `b>=a` else `$FF` (v0.3.0 CT fix) |
| `$40..$7f` | `cc20_work`       | 64   | chacha20              | ZP-resident ChaCha20 working state; aliased as `cc20_keystream` |
| `$fb..$fc` | `zp_ptr1`         | 2    | poly1305 / aead       | 16-bit pointer for `poly1305_update` and `aead_process_padded` |
| `$fd..$fe` | `zp_ptr2`         | 2    | poly1305 / aead       | 16-bit pointer; currently unused by library code but reserved |

### Unclaimed ZP windows (default layout)

- `$0a..$13` (10 bytes) — free for consumer use.
- `$20..$3f` (32 bytes) — free for consumer use (v0.3.0 CT fix freed `$20..$21` — the old `lmul1` slot went away when `mult66` was replaced with the `ct_mul_8x8` primitive; `ct_diff_raw`/`ct_sign_mask` at `$1e..$1f` occupy the old `lmul0` slot).
- `$80..$fa` (123 bytes) — free for consumer use (but `$fb..$fe` are reserved, see above).
- `$ff` (1 byte) — outside the c64.cfg ZP window ($02..$9F), reserved by the KERNAL.

### Consistency check: c64.cfg ↔ zp_config.s

`c64.cfg`'s `ZP` MEMORY region is `start = $0002, size = $009E`,
so the library's legal ZP window is `$02..$9F`. **BUT** the two
`zp_ptr1` / `zp_ptr2` equates sit at `$fb..$fe`, which is OUTSIDE
that `ZP` region. That's fine — these slots are unsegmented equates
(not claimed via the `ZEROPAGE` segment), used only as `.ifndef`
guards. The `.s` code emits `lda zp_ptr1` etc. as raw ZP addresses;
ld65 is not asked to allocate them, so the `c64.cfg` `ZP` region
bound ($9F) is not violated by the equates themselves. The ZP
region in the linker config governs only symbols emitted into the
`ZEROPAGE` segment — currently none — so the two windows do not
interact. **No discrepancy**, but worth documenting because it
looks inconsistent at first read.

---

## 2. Fixed-address tables (page-aligned RAM, outside ZP)

Pages of main RAM claimed at assembly time. The Shoup `r_tab_*`
pages are hard-coded in `src/lib/constants_lib.s`; the sqtab base
defaults to `$8000` via the `LIB_SHARED_SQTAB_BASE` equate and is
relocatable with `-DLIB_SHARED_SQTAB_BASE=<addr>` (SPEC §8.1,
PR #39).

| range          | symbol              | size  | profile    | build-time vs runtime       | notes |
|----------------|---------------------|------:|------------|-----------------------------|-------|
| `$6000..$6FFF` | `r_tab_lo`          |  4 KB | A only     | runtime, built in `shoup_init` (P3, S6+S11) | 16 × 256 bytes: `r_tab_lo + j*256 + x` = low byte of `x * r[j]` |
| `$7000..$7FFF` | `r_tab_hi`          |  4 KB | A only     | runtime, built in `shoup_init` | 16 × 256 bytes: `r_tab_hi + j*256 + x` = high byte of `x * r[j]` |
| `$8000..$81FF` | `sqtab_lo`          | 512 B | B only     | runtime, built in `sqtab_init` (S10 one-time gate) | low byte of `floor(n²/4)` for n=0..511; 2 pages; base relocatable via `LIB_SHARED_SQTAB_BASE` (SPEC §8.1) |
| `$8200..$83FF` | `sqtab_hi`          | 512 B | B only     | runtime, built in `sqtab_init` | high byte of `floor(n²/4)` for n=0..511 |

> **Profile A no longer emits sqtab** (issue #34 F1, PR #38):
> `shoup_init` populates `r_tab_lo/hi` by incremental ripple-add, so
> `sqtab_init`, `mul_8x8`, and the `POLY1305_REU` stash/restore path
> are gated out of Profile A entirely. `$8000..$83FF` is
> consumer-reclaimable on Profile A builds.

**v0.3.0 CT-fix RAM delta (Profile B)**: the Step-12 `sqtab2_lo` /
`sqtab2_hi` companion tables at `$8400..$87FF` (512 B) have been
**removed** along with the `mult66` primitive they served. Profile B
now uses the `ct_mul_8x8` branchless quarter-square primitive
(see `docs/design/ct_mul_8x8.md`), which reuses the existing 1 KB
`sqtab_lo`/`sqtab_hi` at `$8000..$83FF` via SMC-patched `abs,x`
loads. Profile B runtime RAM is back to **~1 KB** (sqtab only), a
**−512 B** net delta vs the pre-CT-fix S13 state.

### REU usage: none (former Profile A backup removed)

The library issues **no REU DMA on any code path in any profile**,
and touches no I/O registers. Up through v0.5.x, Profile A +
`POLY1305_REU=1` stashed sqtab to REU and exposed
`poly1305_reu_restore` (touching `$DF01..$DF08`, `$DF0A`); the
issue #34 F1 slimming (PR #38) removed sqtab from Profile A and the
whole REU path with it. `LIB_CHACHA20_POLY1305_REU_BANKS_USED`
reads `$00` unconditionally.

---

## 3. PRG layout

```
$0000..$0001    LOADADDR segment (2-byte PRG header = $0801)
$0801..$08FF    STUB    segment (BASIC SYS 2304 launcher, fill=yes)
$0900..?????    MAIN    segment: CODE (align=$100) + DATA + BSS
```

`c64.cfg` MEMORY:
- `MAIN: start = $0900, size = $9700` (bound: $0900..$9FFF).

**v0.6.0 build artifact sizes** (measured from `ls -la
build/profile-*/*.prg` after `make clean && make profile-a
profile-b` on the v0.6.0 release branch, 2026-07-28):

| profile | PRG file                                     | bytes | md5 |
|---------|----------------------------------------------|------:|-----|
| A       | `build/profile-a/c64_chacha20_poly1305.prg`  | 16 168 | `79deb98c0028488f84278aa2ec645c9d` |
| B       | `build/profile-b/c64_chacha20_poly1305.prg`  | 17 448 | `4afe54d466ad92ca38b91c94a2ea2b36` |

Both profiles load at `$0801`. (The v0.3.0 reference-build sizes
and md5s are preserved in `AUDIT.md` "Release fingerprints".)

**Unused MAIN gap (Profile A)**: approximately $4730..$5FFF
(~6.2 KB) free between BSS tail (`__BSS_RUN__` = $4727 in the
v0.6.0 `build/profile-a/labels.txt`) and Shoup table base. This is the
region the benchmark harness uses for `pt_addr = $5000` so plaintext
lives in the gap. Consumers in non-bench deployments have ~6 KB free
in this window.

**Unused MAIN gap (Profile B)**: approximately $4C30..$7FFF (~13 KB)
free between BSS tail and sqtab base. Profile B does not use the
$6000..$7FFF Shoup region and (post-CT-fix) does not use
$8400..$87FF either, so that whole window is consumer-available.

---

## 4. Consumer collision-risk summary

**Addresses a consumer MUST NOT touch without overriding the
library's `.ifndef` equates**:

### Both profiles
- **ZP `$02..$09`** — word32 scratch + pointers.
- **ZP `$14..$1d`** — chacha20 and poly1305 counters/scratch.
- **ZP `$40..$7f`** — `cc20_work` ChaCha20 working state (ZP hot path).
- **ZP `$fb..$fe`** — `zp_ptr1` / `zp_ptr2` 16-bit pointers.
- **$0801..$08FF** — BASIC SYS stub.
- **$0900..~$4726** — library CODE+DATA+BSS (Profile A, v0.6.0
  build; Profile B extends to ~$4C26).

### Profile A only (POLY1305_PROFILE_LONG=1)
- **$6000..$7FFF** — Shoup per-r tables (4 KB lo + 4 KB hi).
  ($8000..$83FF is *not* claimed on Profile A as of issue #34 F1 /
  PR #38 — the window is consumer-reclaimable.)

### Profile B only (no POLY1305_PROFILE_LONG flag)
- **$8000..$83FF** — `sqtab_lo/hi`, 1 KB quarter-square table
  (default placement; relocatable via `LIB_SHARED_SQTAB_BASE`).
- **ZP `$1e..$1f`** — `ct_diff_raw` / `ct_sign_mask` scratch bytes
  used by the `ct_mul_8x8` primitive.

### Relocation support (v0.6.0)

- All ZP slots are `.ifndef`-guarded defaults in `src/zp_config.s`
  (PR #32): a consumer can pre-define any slot (e.g.
  `cc20_work = $80`) before `zp_config.s` is assembled, or replace
  the file entirely, to relocate it.
- `sqtab_lo/hi` are relocatable via
  `-DLIB_SHARED_SQTAB_BASE=<addr>` (default `$8000`; SPEC §8.1,
  PR #39); `sqtab_hi` sits at base+`$0200`.
- `r_tab_lo` / `r_tab_hi` (Profile A Shoup pages at
  `$6000`/`$7000`) remain **fixed-address** hard-coded equates in
  `src/lib/constants_lib.s`. Overriding these still requires
  editing the library source.

---

## 5. Incomplete documentation

No symbol in the current export surface lacks a calling-convention
comment header. All `.export`ed entries in `word32_lib.s`,
`chacha20_lib.s`, `poly1305_lib.s`, and `chacha20poly1305_lib.s`
have `; =====`-framed headers above them. See `API.md` for the
per-symbol calling conventions.
