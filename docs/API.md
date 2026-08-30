# c64-ChaCha20-Poly1305 — Public API (v0.6.0)

Audit of the `.export` surface across `src/main.s` and `src/lib/*.s`.
Calling conventions are taken from the block-comment headers above
each entry. Cycle counts cited are the current measured numbers from
`docs/BENCH_REPORT.md` / `docs/BENCH_GRANULAR.md` (VICE backend,
Profile B build, min of 3 samples) unless otherwise noted.

> **Naming note.** The Poly1305 finalization entry is `poly1305_final`
> (in `poly1305_lib.s`). No symbol named `poly1305_tag_finalize` exists
> in the source tree. See §Poly1305 below.

---

## 0. Initialization protocol

Required call order for any consumer:

```
1. (once at startup)     poly1305_lib_init       ; build sqtab (Profile B; no-op on A)
2. (once per AEAD call)  populate aead_*          ; key, nonce, aad, data ptrs/lens
3. (once per AEAD call)  aead_encrypt or aead_decrypt
```

**`poly1305_lib_init` is the only prerequisite for the high-level
AEAD entries.** `aead_encrypt` / `aead_decrypt` internally call
`aead_derive_otk` → `aead_setup_chacha` → `chacha20_init` →
`chacha20_block` → `poly1305_init`, so a consumer that goes through
the AEAD entries does not need to invoke the lower-level primitives.

**`poly1305_lib_init` is idempotent**: a `sqtab_ready` flag byte
short-circuits it after the first call. Calling it more than once
costs only a `lda / bne` (~7 cy). Calling it zero times leaves
`sqtab_ready = 0` (loaded from the `LIB_CHACHA20_POLY1305_DATA`
segment at PRG load time, which is why `data_lib.s` deliberately places
state reservations in a `type = rw` data segment and not `BSS` — see
`data_lib.s:12-25`, and the cfg requirement in `INTEGRATION.md`).

**No REU usage**: as of the issue #34 F1 slimming (PR #38), the
library issues no REU DMA on any path in any profile.
`poly1305_lib_init` collapses to a bare `rts` on Profile A, and the
former `POLY1305_REU=1` stash/restore API (`poly1305_reu_restore`,
`poly1305_reu_sqtab_bank` / `poly1305_reu_sqtab_offset`) plus the
`POLY1305_REU_BANK` / `POLY1305_REU_OFFSET` assemble-time defines
were removed with it. Profile B never had an REU path. See §3
"poly1305_reu_* (removed)" for the upgrade note.

### Consumer data buffers to populate before `aead_encrypt`

All live in the library's `LIB_CHACHA20_POLY1305_DATA` segment (see
`data_lib.s` and `MEMORY_MAP.md`):

| symbol           | size | purpose                                   |
|------------------|-----:|-------------------------------------------|
| `aead_key`       | 32   | 256-bit symmetric key (secret)            |
| `aead_nonce`     | 12   | 96-bit nonce (public, per-message unique) |
| `aead_aad_ptr`   | 2    | pointer to AAD bytes in RAM               |
| `aead_aad_len`   | 1    | AAD length (0..255)                       |
| `aead_data_ptr`  | 2    | pointer to plaintext/ciphertext in RAM    |
| `aead_data_len`  | 2    | data length LE 16-bit (see domain note)   |
| `aead_tag`       | 16   | output tag (encrypt) or expected tag (decrypt) |

#### Domain of the AEAD input pointers

Both AEAD entry points require **both** of these:

```
aead_data_ptr + aead_data_len <= $10000
aead_aad_ptr  + aead_aad_len  <= $10000
```

i.e. neither caller-supplied buffer may run off the top of the 6502
address space. Each is a **relation over two caller-supplied values, not
a length ceiling**: the library owns no buffer and never allocates one,
so `aead_data_len` alone has no maximum — it is exact over the whole
`0..65535` range, and all of it is in domain for a low enough
`aead_data_ptr`. (Numbers such as 1500, 3840 or ~6.2 KB that appear in
this repo's harnesses and in consumer projects are *those* callers'
buffer sizes. The 1500 in particular was an MTU inherited from the
c64-wireguard origin; nothing in this library knows it.)

A buffer ending exactly at `$FFFF` — sum `== $10000` — is **in domain**:
the walkers advance their pointer past the last byte but re-test the
remaining count before dereferencing it. A zero length is in domain for
any pointer (`aead_aad_len == 0` short-circuits before the AAD pointer
is read at all).

Out-of-domain calls are **rejected at entry** (`chacha20poly1305_lib.s`,
`AEAD_DOMAIN_GUARD`) with `A = $01`, **before anything is written** — no
ciphertext/plaintext, no `aead_tag`, no `poly1305_tag`, no
`aead_scratch`, and none of the `cc20_*` / `poly_*` working state. The
guards are the first instructions of both entry points, ahead of every
`jsr`. `aead_key` and `aead_nonce` are inputs and are never modified by
either entry point.

One status code covers both relations. A caller that violates either has
the same bug class and the same remedy, and can evaluate both relations
itself in a few instructions, so the ABI does not spend a second code
point on telling them apart.

**What the guards prevent.** Both data walkers advance a 16-bit pointer
with no carry-out check — the ChaCha20 XOR loop
(`chacha20_lib.s:909-915`, `adc cc20_data_ptr` / `adc #0`) and the
Poly1305 block loop in `aead_process_padded`, the same shape on
`chacha20poly1305_zp_ptr1`. Unguarded, a data buffer running past
`$FFFF` wraps to `$0000` and the library reads **and writes** from page
zero upward: `$01` (the banking register, re-banking RAM/ROM mid-loop),
the stack, and I/O at `$D000-$DFFF`. The AAD path is milder in two ways
that are worth stating precisely, because they bound it rather than
excuse it — it only ever *reads* through the pointer (into
`aead_scratch` and `poly1305_block`), and `aead_aad_len` is 8-bit, so
the overrun cannot exceed 254 bytes and cannot reach past `$00FE`. Its
consequence is a wrong tag computed partly over zero page, not memory
corruption. Both are guarded regardless: the published domain is one
statement, and a reader should not have to track which half is enforced.

**A separate restriction, still unchecked.** Where the buffers may *sit*
— they must not overlap the regions the library itself claims (its
CODE/DATA/BSS, the Profile A Shoup tables, the Profile B `sqtab`, and
the reserved zero-page slots) — is **not** runtime-checkable and is not
checked. That one remains the caller's precondition; see
`docs/MEMORY_MAP.md` §4, "Consumer collision-risk summary".

#### AEAD status codes

`aead_encrypt` and `aead_decrypt` both return a status in **A**. The
library has no carry-based error return on any entry point.

| A     | meaning | written on this path |
|-------|---------|----------------------|
| `$00` | success | ciphertext/plaintext + `aead_tag` (encrypt); plaintext (decrypt) |
| `$01` | domain rejection — a pointer + length exceeds `$10000` | nothing |
| `$ff` | authentication failure (`aead_decrypt` only) | nothing |

`bne` after either call still fails closed. A caller that must tell an
authentication failure from a domain rejection — they are different
conditions, one about the message and one about the call — tests
`cmp #$ff`.

---

## 1. chacha20_lib.s

### chacha20_init

- **Module**: `chacha20_lib.s:548`
- **Purpose**: Seed `cc20_state` (64 bytes in DATA) from `cc20_constants`
  (row 0), `cc20_key` (rows 1–2), `cc20_counter` (word 12), and
  `cc20_nonce` (words 13–15).
- **Signature**: takes no register args. Reads `cc20_key`,
  `cc20_nonce`, `cc20_counter` (all in DATA). Writes `cc20_state`.
- **Preconditions**: `cc20_key`, `cc20_nonce`, `cc20_counter` must
  already be populated by caller. `aead_setup_chacha` does this
  copy from `aead_key` / `aead_nonce` when the AEAD path is used.
- **Postconditions**: `cc20_state` contains the initial ChaCha20
  state. `cc20_work` is *not* touched.
- **Clobbers**: A, X, Y. X/Y carry no return value.
- **CT contract**: inputs `cc20_key` are SECRET; inputs `cc20_nonce`
  and `cc20_counter` are PUBLIC. The init routine is straight-line
  copies through `ldx #n / lda src,x / sta dst,x / dex / bpl` —
  constant-time.
- **Example**:
  ```ca65
  ; 32-byte key / 12-byte nonce / 4-byte counter already in RAM
  jsr chacha20_init
  jsr chacha20_block        ; first keystream block in cc20_work
  ```

### chacha20_block

- **Module**: `chacha20_lib.s:592`
- **Purpose**: Generate one 64-byte keystream block into `cc20_work`
  (aliased as `cc20_keystream`) and increment `cc20_state+48..51`.
- **Signature**: no register args. Reads/writes `cc20_state`;
  writes `cc20_work` (ZP `$40..$7f`); increments counter word.
- **Preconditions**: `chacha20_init` (or a prior `chacha20_block`
  that set up state) must have run.
- **Postconditions**: `cc20_work[0..63]` holds the 64-byte keystream.
  `cc20_state+48..51` has been incremented as a 32-bit LE counter.
- **Clobbers**: A, X, Y.
- **CT contract**: input secret is the ChaCha state (derived from
  `cc20_key`). **Constant-time.** The former secret-dependent timing
  variance from the rotl/r 1-bit rotate carry-wrap branches
  (`CT_ANALYSIS.md` finding F2) was resolved in the v0.3.0 CT fix
  (PR #14): the rotates are now branchless ASL/ROL chains, and the
  nibble-swap LUT loads are `abs,x` on page-aligned bases. See the
  Resolution section of `CT_ANALYSIS.md`; aggregate audit verdict is
  **GREEN** (`AUDIT.md`).
- **Performance**: 39 318 cy/block (`docs/BENCH_REPORT.md`, VICE,
  Profile B build, min of 3 samples).
- **Example**:
  ```ca65
  jsr chacha20_block        ; cc20_work[0..63] = keystream
  ldy #0
  lda (data_ptr),y
  eor cc20_work,y            ; XOR byte 0
  ```

### chacha20_encrypt

- **Module**: `chacha20_lib.s:774`
- **Purpose**: Generate keystream blocks and XOR into the buffer at
  `cc20_data_ptr` in place, covering `cc20_remain | cc20_remain_hi`
  bytes (16-bit length).
- **Signature**:
  - Inputs (ZP): `cc20_data_ptr` ($16-$17), `cc20_remain` ($18),
    `cc20_remain_hi` (DATA byte).
  - No return value.
- **Preconditions**: `cc20_state` already initialized (`chacha20_init`
  or a prior AEAD call's chained setup). Counter typically at 1 when
  called from the AEAD path (A5/A6 optimization).
- **Postconditions**: buffer XOR'd in place; `cc20_data_ptr` advanced;
  `cc20_remain` / `cc20_remain_hi` = 0; `cc20_state+48..51` advanced
  by `ceil(nbytes/64)` blocks.
- **Clobbers**: A, X, Y.
- **CT contract**: data bytes are SECRET (plaintext or ciphertext);
  `cc20_remain` / `cc20_remain_hi` are PUBLIC (message length is not
  secret per RFC 7539). Branches in this entry are all on the
  public length — see CT_ANALYSIS.md §A. The XOR loop itself goes
  through `(cc20_data_ptr),y` which page-crosses on the PUBLIC
  `data_ptr_low + y`, not on secret data.
- **Example**: (used by `aead_encrypt` / `aead_decrypt`)

### chacha20_quarter_round

- **Module**: `chacha20_lib.s:502`
- **Purpose**: **Test-only entry**. Performs one ChaCha20 quarter
  round by patching `cc20_qr_idx` into `cc20_qr_table` and calling
  the word32 helpers. Retained so
  `tools/test_chacha20_poly1305.py:346` can exercise RFC 7539
  §2.1.1's single-QR test vector.
- **Signature**: Input ZP `cc20_qr_idx` = offset into `cc20_qr_table`
  (0, 4, 8, …, 28). Reads/writes `cc20_work`.
- **Preconditions**: `cc20_work` must contain whatever state the
  test wants to feed to the QR.
- **Postconditions**: one QR applied in place.
- **Clobbers**: A, X, Y, `w32_dst`, `w32_src1`.
- **CT contract**: **test-only** — not on any production path.
  Goes through `rotl32_7` (word32_lib subroutine), branchless since
  the v0.3.0 F2 fix. Do not call from deployed code.
- **Availability**: Not exported when `LIB_VARIANT_AEAD_ONLY=1`
  (the function body is assembled out of the aead-only variant,
  which also removes the library's only `jsr rotl32_7`).

### Data symbols exported from chacha20_lib.s

- **`cc20_constants`** (`chacha20_lib.s:33`): 16-byte "expand
  32-byte k" constant as LE uint32 words. Read-only.
- **`cc20_qr_table`** (`chacha20_lib.s:45`): 32-byte QR index
  table for the test-only `chacha20_quarter_round` entry.
  Production `chacha20_block` does not touch it.

---

## 2. word32_lib.s

### add32 / add32_to_dst / xor32 / xor32_in_place / copy32 / zero32

- **Module**: `word32_lib.s` (various)
- **Purpose**: 32-bit LE primitives. `add32`: `(dst) = (src1) + (src2)`.
  `add32_to_dst`: `(dst) += (src1)`. `xor32`, `xor32_in_place` similar.
  `copy32`: 4-byte copy. `zero32`: 4-byte zero.
- **Signature**: operands addressed via ZP pointers `w32_src1`,
  `w32_src2`, `w32_dst` (4 bytes each, accessed as `(zp),y`).
- **Preconditions**: caller sets `w32_src1` / `w32_src2` / `w32_dst`
  to 16-bit RAM pointers.
- **Postconditions**: target word updated in place.
- **Clobbers**: A, Y. **Preserves X.**
- **CT contract**: straight-line. Data bytes are SECRET if caller
  passes ChaCha state; timing depends only on pointer values
  (public addresses), not on loaded bytes. Constant-time *when
  called from the production hot path* — but note: in the default
  build the production hot path (`chacha20_block`) does **not** use
  these — it inlines macros in `chacha20_lib.s`, and these
  subroutines are reachable only via `chacha20_quarter_round`
  (test-only). In `CHACHA20_USE_WORD32` pointer-mode builds (see
  §7) the inline macros are replaced with `jsr`s into these
  subroutines, putting them on the production path.

### rotl32_4 / rotl32_8 / rotl32_12 / rotr32_4 / rotr32_8 / rotr32_12 / rotr32_16

- **Module**: `word32_lib.s`
- **Purpose**: 32-bit rotations by 4, 8, 12, 16 — straight-line
  byte/nibble shuffles with no carry-wrap branch.
- **Signature**: operand addressed via `w32_dst`.
- **Clobbers**: A, Y. Preserves X.
- **CT contract**: **constant-time**. No conditional branches.

### rotl32_1 / rotl32_7 / rotr32_1 / rotr32_7

- **Module**: `word32_lib.s:317, 509, 480, 299`
- **Purpose**: 1-bit and 7-bit rotations.
  `rotl32_7` = `rotl32_8` then `rotr32_1`.
  `rotr32_7` = `rotr32_8` then `rotl32_1`.
- **Signature**: via `w32_dst`.
- **Clobbers**: A, Y. Preserves X.
- **CT contract**: **constant-time** since v0.3.0. The former
  `bcc` carry-wrap branch on bit 31 / bit 0 of the rotated word
  (`CT_ANALYSIS.md` finding **F2**) was rewritten as a branchless
  ASL/ROL chain in the v0.3.0 CT fix (PR #14); no conditional
  branch remains. See the Resolution section of `CT_ANALYSIS.md`;
  audit verdict **GREEN** (`AUDIT.md`).
- **Reachability**: `rotr32_7` falls through into `rotl32_1`, and
  `rotl32_7` tail-calls `rotr32_1` (`jmp`), so the four routines
  form two linked pairs. In the default build they are reached
  only via the test-only `chacha20_quarter_round` entry; in
  `CHACHA20_USE_WORD32` pointer-mode builds (see §7) `rotr32_1`
  is on the `chacha20_block` hot path. All four are exported from
  the full archive because the Python test harness resolves them
  by name for unit-test coverage.
- **Availability**: `rotl32_1`, `rotl32_7`, and `rotr32_7` are not
  exported when `LIB_VARIANT_AEAD_ONLY=1` (bodies remain in the
  `.o`; only the symbol-table footprint shrinks). `rotr32_1`
  remains exported in both variants so a pointer-mode
  `chacha20_lib.o` import resolves at consumer link time.

---

## 3. poly1305_lib.s

### poly1305_lib_init

- **Module**: `poly1305_lib.s:143`
- **Purpose**: One-time library initialization. **Profile B**: builds
  the 1 KB quarter-square table at `sqtab_lo/hi` and sets
  `sqtab_ready`. (The v0.3.0 CT fix removed the former `sqtab2_lo/hi`
  build and `lmul0+1` / `lmul1+1` pointer caching — `ct_mul_8x8`
  uses only `sqtab_lo/hi` via SMC-patched `abs,x` loads.)
  **Profile A**: no sqtab to build (issue #34 F1) — the body is a
  bare `rts`, retained as an exported entry point so consumers
  calling it once at startup keep working on both profiles.
- **Signature**: no register args.
- **Preconditions**: on Profile B, **must be called at least once
  before any `aead_encrypt` / `aead_decrypt` / `poly1305_init`**
  (or accept the auto-build cost on first `poly1305_init`).
  Idempotent via `sqtab_ready` flag. No-op but safe on Profile A.
- **Postconditions**: Profile B: `sqtab_ready != 0`, `sqtab_lo/hi`
  populated. Profile A: none.
- **Clobbers**: A, X, Y.
- **CT contract**: PUBLIC inputs only (none — the table values
  are pure functions of the platform, i.e. `floor(n²/4)`). No CT
  concern.
- **Example**:
  ```ca65
  ; At application startup, once:
  jsr poly1305_lib_init
  ```

### poly1305_reu_restore / poly1305_reu_sqtab_bank / poly1305_reu_sqtab_offset (removed)

Removed by the issue #34 F1 Profile A slimming (PR #38). Profile A
no longer emits or consumes the quarter-square table — `shoup_init`
populates `r_tab_lo/hi` by incremental ripple-add — so the REU
stash had nothing left to stash, and the whole `POLY1305_REU` path
(shipped v0.4.0–v0.5.x, including the issue #19 runtime relocation
cells) was deleted. Upgrade notes for consumers of the removed API:

- On Profile A, `$8000..$83FF` is no longer library-owned — code
  that clobbered it and called `poly1305_reu_restore` can simply
  stop doing either (see `MEMORY_MAP.md`).
- On Profile B (which never had the REU path), a clobbered sqtab is
  rebuilt in ~87 k cy by clearing `sqtab_ready` and calling
  `poly1305_lib_init`.
- REU bank coordination with siblings (e.g. `c64-x25519` banks 0-1)
  is moot for this library: `LIB_CHACHA20_POLY1305_REU_BANKS_USED`
  is unconditionally `$00`.

### poly1305_init

- **Module**: `poly1305_lib.s:172`
- **Purpose**: Per-MAC initialization. Clamps `poly_r`, zeros
  `poly_h`, (re)builds sqtab if `sqtab_ready == 0` (first call),
  and on Profile A builds the 8 KB Shoup per-r tables.
- **Signature**: no register args. Reads/writes `poly_r` (clamp),
  `poly_h` (zero). Writes Shoup tables on Profile A.
- **Preconditions**: caller has written the 32-byte one-time key:
  first 16 bytes to `poly_r`, next 16 bytes to `poly_s`. Typically
  done by `aead_derive_otk`.
- **Postconditions**: `poly_r` clamped per RFC 7539 §2.5; `poly_h`
  zeroed; Shoup tables built on Profile A (`r_tab_lo/hi`).
- **Clobbers**: A, X, Y.
- **CT contract**: `poly_r` is SECRET. `poly1305_clamp` is
  straight-line `and #imm / sta`. sqtab build is PUBLIC. Shoup
  build: see `CT_ANALYSIS.md` §B for the S11 incremental-ripple
  analysis — its branches are PUBLIC (loop counters only), and
  the `adc #rj` SMC immediate is a secret immediate but does not
  affect branch direction.

### poly1305_block

- **Module**: `poly1305_lib.s:853`
- **Purpose**: Process one 16-byte block. `h += block`, then
  `h *= r mod p`.
- **Signature**:
  - `chacha20poly1305_zp_ptr1` ($fb-$fc) = pointer to 16-byte block.
  - A = high bit value (1 for normal blocks, 0 for the final
    length-block / partial-padded form).
- **Preconditions**: `poly1305_init` run; `sqtab_ready != 0`.
- **Postconditions**: `poly_h` updated; `poly_product` scratch
  dirty.
- **Clobbers**: A, X, Y.
- **CT contract**: inputs SECRET (block bytes, `poly_h`, `poly_r`).
  See `CT_ANALYSIS.md` §C for branch classification. Profile B goes
  through `ct_mul_8x8`, the branchless quarter-square multiply that
  replaced `mult66` in the v0.3.0 CT fix — finding **F3 resolved**.
  All its table loads are `abs,x` on page-aligned bases, so no
  secret-dependent addressing-mode timing remains. Audit verdict
  **GREEN** (`AUDIT.md`).
- **Performance**: Profile B 38 002 cy (`docs/BENCH_REPORT.md`,
  VICE, min of 3 samples; the current granular report covers the
  Profile B build).
- **Example**:
  ```ca65
  lda #<my_block
  sta chacha20poly1305_zp_ptr1
  lda #>my_block
  sta chacha20poly1305_zp_ptr1+1
  lda #1                ; hibit = 1 for full-message block
  jsr poly1305_block
  ```

### poly1305_update

- **Module**: `poly1305_lib.s:917`
- **Purpose**: Process a multi-byte message as 16-byte blocks,
  zero-padding the final partial block per RFC 7539.
- **Signature**:
  - `chacha20poly1305_zp_ptr1` = data pointer.
  - `cc20_remain` = length (byte; repurposed as a generic byte counter).
- **Preconditions**: `poly1305_init` run.
- **Postconditions**: `poly_h` advanced over all input bytes;
  `cc20_remain` = 0.
- **CT contract**: SECRET message bytes, PUBLIC length.
  Branches in the outer loop (length comparison) are PUBLIC.
  Delegates to `poly1305_block` for the arithmetic.

### poly1305_final

- **Module**: `poly1305_lib.s:997`
- **Purpose**: Finalize MAC: full reduction of `poly_h` mod p,
  add `poly_s`, write 16-byte tag to `poly1305_tag`.
- **Signature**: no register args.
- **Preconditions**: `poly1305_init` run; any number of
  `poly1305_block` / `poly1305_update` calls have occurred.
- **Postconditions**: `poly1305_tag[0..15]` holds the final MAC.
  `poly_h` is clobbered (holds the post-reduction value pre-add-s).
- **Clobbers**: A, X, Y.
- **CT contract**: **constant-time** since v0.3.0. The former
  secret-dependent branch on bit 130 of `h + 5` (`CT_ANALYSIS.md`
  finding **F1**) was replaced in the v0.3.0 CT fix (PR #14) with a
  branchless mask-blend: both candidate outputs (`h` and `h − p`)
  are computed in a fixed-length sequence and blended byte-by-byte
  via a borrow-derived sign mask, so control flow is identical for
  all secret inputs. See the Resolution section of
  `CT_ANALYSIS.md`; audit verdict **GREEN** (`AUDIT.md`).
- **Example**:
  ```ca65
  jsr poly1305_final         ; MAC now in poly1305_tag
  ```

### Low-level Poly1305 entries (also exported)

These are not part of the recommended consumer surface — they are
exposed for the test harness and for composable re-use.

- **`poly1305_clamp`** (`poly1305_lib.s:311`): RFC 7539 §2.5
  clamping of `poly_r` in place. No inputs/outputs beyond `poly_r`.
- **`poly1305_multiply`** (`poly1305_lib.s:700`): 17×16 schoolbook
  multiply `h *= r`, falls through into `poly1305_reduce`. Called
  from `poly1305_block`. Profile-gated: Profile A uses Shoup
  tables (`poly_pp_shoup`); Profile B inlines `ct_mul_8x8` partial
  products (`poly_pp_ct_mul`), or runtime-rolled forms under
  `POLY1305_MULTIPLY_ROLLED` / `POLY1305_MULTIPLY_ROLLED_OUTER`
  (see §7).
- **`poly1305_reduce`** (`poly1305_lib.s:765`): Fused Donna-style
  wrap reduction of `poly_product` into `poly_h`.
- **`sqtab_init`** (`poly1305_lib.s:359`, Profile B only): Build
  sqtab_lo/hi from scratch via the `i² = (i-1)² + 2i − 1`
  recurrence. `poly1305_lib_init` calls this gated on
  `sqtab_ready`. Not exported when `SHARED_SQTAB_INIT` is defined
  — the consumer's canonical `mul_tables_init` takes over per
  c64-lib-contract SPEC §8.1 (see §7).
- **`mul_8x8`** (`poly1305_lib.s:454`, Profile B only): Legacy
  8×8→16 multiply via sqtab. Replaced by `ct_mul_8x8` (the
  constant-time, page-cross-safe variant) on every hot path in the
  v0.3.0 CT fix; nothing inside the library calls it anymore — the
  only callers are the external Python tests, and it is retained
  for test-vector compatibility. Inputs: A, X. Outputs:
  `poly_prod_lo/hi`. Not exported when `LIB_VARIANT_AEAD_ONLY=1`
  (body remains in the `.o`; only the symbol-table entry shrinks).
- **`shoup_init`** (Profile A only, `poly1305_lib.s:246`):
  incremental-ripple builder for the 8 KB Shoup `r_tab_lo/hi`.
  SMC-heavy: per outer-j iteration, patches six RAM addresses and
  one `adc #imm` immediate.
- **`poly_prod_lo`, `poly_prod_hi`** (`poly1305_lib.s:452-453`):
  output bytes of `mul_8x8` / `ct_mul_8x8`.
- **`poly_ripple`** (`poly1305_lib.s:605`): propagate a carry
  upward through `poly_product` starting at index X. Called from
  the unrolled schoolbook's `poly_pp_shoup` / `poly_pp_ct_mul`
  when an add leaves carry set.

---

## 4. chacha20poly1305_lib.s

### aead_encrypt

- **Module**: `chacha20poly1305_lib.s:53`
- **Purpose**: Full RFC 7539 §2.8 AEAD encrypt.
- **Signature**: no register args. All inputs and outputs via
  `LIB_CHACHA20_POLY1305_DATA` `aead_*` fields (see §0 above).
- **Preconditions**:
  1. `poly1305_lib_init` called at least once.
  2. `aead_key`, `aead_nonce`, `aead_aad_ptr`, `aead_aad_len`,
     `aead_data_ptr`, `aead_data_len` populated.
  3. `aead_data_ptr + aead_data_len <= $10000` **and**
     `aead_aad_ptr + aead_aad_len <= $10000` (§0 "Domain of the AEAD
     input pointers"). Violations are **rejected**, not undefined
     behaviour: the walkers use 16-bit pointer arithmetic with no
     carry-out check, so before the §14.1 guards a buffer crossing
     `$FFFF` wrapped to `$0000` and the routine read and wrote from
     page zero upward.
- **Return**: A = `$00` success, A = `$01` domain rejection.
  Before the §14.1 guards this entry point had no failure path and
  left A undefined; `A = $00` on success is new with them.
- **Postconditions**:
  - On success (A=0): ciphertext written in place at `aead_data_ptr`;
    `aead_tag[0..15]` holds the 16-byte authentication tag.
  - On domain rejection (A=$01): **nothing is written** — not the
    buffer at `aead_data_ptr`, not `aead_tag`, not `poly1305_tag`,
    not `aead_scratch`, and none of the `cc20_*` / `poly_*` working
    state. The guard is the entry point's first instruction, ahead of
    every `jsr`. `aead_key` and `aead_nonce` are unchanged.
- **Clobbers**: A, X, Y, most of `cc20_*` and `poly_*` state (on the
  domain-rejection path, A and X only).
- **CT contract**: `aead_key` and plaintext are SECRET;
  `aead_nonce`, `aead_aad_*`, and lengths are PUBLIC.
  **Aggregate CT verdict: GREEN** — findings F1/F2/F3 were all
  resolved in the v0.3.0 CT fix (PR #14); no known secret-dependent
  branches or secret-dependent addressing-mode timing remain on the
  production AEAD hot path on either profile. See the `AUDIT.md`
  verdict and the Resolution section of `CT_ANALYSIS.md`.
- **Performance** (`docs/BENCH_REPORT.md`, VICE, Profile B build,
  min of 3 samples): 3 195 600 cy at n=1024; 274 794 cy at n=64;
  80 513 cy at n=0.
- **Example**:
  ```ca65
  jsr poly1305_lib_init      ; once at startup
  ; ... populate aead_key / aead_nonce / aead_*_ptr / aead_*_len ...
  jsr aead_encrypt           ; ciphertext in-place, tag in aead_tag
  ```

### aead_decrypt

- **Module**: `chacha20poly1305_lib.s:91`
- **Purpose**: Full RFC 7539 §2.8 AEAD decrypt with tag verify.
- **Signature**: same input convention as `aead_encrypt`. Caller
  must populate `aead_tag` with the received tag before the call.
- **Return**: A = `$00` tag valid, A = `$ff` tag mismatch,
  A = `$01` domain rejection.
- **Preconditions**: same as `aead_encrypt` (including both `$10000`
  domain relations), plus `aead_tag` holds the received tag.
  Historically the two legs wrapped differently, which is why the guard
  is at the entry rather than in front of the decrypt step: tag
  computation only *reads* through the wrapped pointer, so an
  out-of-domain call normally just computed a wrong tag and returned
  `A = $ff`, but one whose tag nevertheless verified went on to
  overwrite page zero upward through the step-4 decrypt. Both legs are
  now unreachable for out-of-domain input.
- **Postconditions**:
  - On success (A=0): plaintext written in place at `aead_data_ptr`.
  - On authentication failure (A=$ff): `aead_data_ptr` buffer is
    unchanged (decrypt step is skipped); `poly1305_tag` holds the
    computed tag (differs from the provided `aead_tag`).
  - On domain rejection (A=$01): **nothing is written** — the buffer,
    `aead_tag`, `poly1305_tag`, `aead_scratch` and the `cc20_*` /
    `poly_*` state are all untouched, and **no tag was computed or
    checked**. This is deliberately distinct from `$ff`: `$ff` says
    the message failed to authenticate, `$01` says the call was never
    made. Conflating them would report an authentication failure for
    a caller bug.
- **Clobbers**: A, X, Y (on the domain-rejection path, A and X only).
- **CT contract**: the decrypt→verify→decrypt-on-success chain
  does leak whether the tag was valid (the `bne @auth_fail` at
  line 100). However, the branch input is the *output* of
  `aead_verify_tag`, which folds 16 byte-compares into a single
  OR-accumulator *before* the branch. The accumulator is a
  deterministic function of "tag match vs mismatch" and is
  **public by definition** (the API contract is to reveal that
  bit). This is the canonical CT tag-compare pattern. ✓
  The rest of the AEAD chain is GREEN as of the v0.3.0 F1/F2/F3
  resolutions (see `AUDIT.md`).
- **Example**:
  ```ca65
  jsr aead_decrypt
  bne @fail                  ; A != 0 = did not decrypt (fails closed)
  ; A == 0: plaintext in aead_data_ptr buffer
  ...
@fail:
  cmp #$ff
  beq @auth_fail             ; $ff = tag mismatch
  ; $01 = caller bug: aead_data_ptr + aead_data_len > $10000
  ```

---

## 5. data_lib.s

Exports data reservations only — no executable code:

`cc20_state`, `cc20_key`, `cc20_nonce`, `cc20_counter`,
`cc20_remain_hi`, `poly_h`, `poly_r`, `poly_s`, `poly_product`,
`poly1305_tag`, `aead_key`, `aead_nonce`, `aead_aad_ptr`,
`aead_aad_len`, `aead_data_ptr`, `aead_data_len`, `aead_tag`,
`aead_scratch`, `sqtab_ready`.

See `data_lib.s` for sizes and `MEMORY_MAP.md` for the collision
surface. All reservations live in the `LIB_CHACHA20_POLY1305_DATA`
segment, which the consumer cfg MUST declare `type = rw` in a
file-emitting area (never `bss`), so they PRG-load as zero — `sqtab_ready` must read zero at startup or
`poly1305_init`'s `bne @sqtab_done` gate would skip sqtab_init
on an uninitialized machine.

---

## 6. main.s

### lib_entry

- **Module**: `main.s:28`
- **Purpose**: RTS-only entry stub at `$0900`. The BASIC SYS 2304
  stub jumps here after RUN; the stub just returns control to
  BASIC. Python test harnesses `jsr()` into library routines by
  label rather than via this entry.
- **Signature**: none.
- **Clobbers**: nothing.
- **CT contract**: none — no data touched.

The `.exportzp` declarations for the library's zero-page layout
live in `src/zp_config.s` (moved out of `constants_lib.s`, which
now `.importzp`s them — PR #32). Every ZP slot there is an
`.ifndef`-guarded equate carrying its historical default address,
`.exportzp`-ed so it appears in the linker symbol map (and VICE
label files) and resolves cleanly across translation units.
Consumers pin the layout to their own memory map by pre-defining
any slot symbol before `zp_config.s` is assembled (a `-D name=$xx`
ca65 command-line define), or by replacing the file entirely; the
library source refers to these locations only by symbolic name, so
moving an address there is sufficient to relocate a slot. These
are not callable entries, they are addresses in the ZP layout.

---

## 7. Build-time defines

All defines are passed at ca65 time (`-Dname` / `-Dname=value`).
Every one of them defaults to *off* (undefined) except the value
equate `LIB_SHARED_SQTAB_BASE`; the default build is therefore
Profile B with the full export surface and unchanged codegen.

| Define | Default | Effect | Added in |
|--------|---------|--------|----------|
| `POLY1305_PROFILE_LONG` | off (= Profile B) | Selects **Profile A** (long-message): `poly1305_init` builds the 8 KB Shoup per-r tables `r_tab_lo/hi` at `$6000..$7FFF` via `shoup_init`; the quarter-square sqtab, `sqtab_init`, and `mul_8x8` are not emitted at all (issue #34 F1). Undefined = **Profile B**: sqtab + `ct_mul_8x8`. `make profile-a` passes it. | v0.2 |
| `LIB_VARIANT_AEAD_ONLY` | off | Builds the trimmed `make lib-aead-only` archive (`build/lib/chacha20poly1305-aead-only.a`): strips the test-only exports — `chacha20_quarter_round` (export and body), `rotl32_1` / `rotl32_7` / `rotr32_7`, and `mul_8x8` — while leaving the crypto code paths untouched. `rotr32_1` stays exported in both variants. | v0.6.0 (PR #35) |
| `POLY1305_MULTIPLY_ROLLED` | off | Profile B only: `poly1305_multiply` becomes a runtime nested J/I loop instead of the 17×16 unrolled macro expansion — smallest code, largest cycle cost. `make profile-b-rolled`. | v0.6.0 (PR #36) |
| `POLY1305_MULTIPLY_ROLLED_OUTER` | off | Profile B only: outer j loop rolled, the 17 inner partial products still inlined — the size↔cycles midpoint. Takes precedence over `POLY1305_MULTIPLY_ROLLED` when both are defined. Measured "config D": combined with the aead-only archive it yields an 8,230 B linked consumer footprint at +4.08% cycles on `aead_encrypt` n=1024. `make profile-b-rolled-outer`. | v0.6.0 (PR #36) |
| `CHACHA20_USE_WORD32` | off | Opt-in pointer-mode: the ChaCha20 `*_zp` rotate/add/xor macros expand to `jsr`s into the shared `word32_lib.s` subroutines (via the `w32_dst` pointer convention) instead of inline ZP code — for consumers that already link a word32 module. Default off preserves the existing (faster, inline) codegen. | v0.6.0 (PR #31) |
| `LIB_SHARED_SQTAB_BASE` | `$8000` | Value equate, Profile B only: relocates the 1 KB quarter-square table (`sqtab_lo` = base, `sqtab_hi` = base + `$0200`). Must be page-aligned (assemble-time `.assert`). This is the c64-lib-contract SPEC §8.1 canonical placement equate: a multi-lib PRG passes one shared `-D LIB_SHARED_SQTAB_BASE=0x<addr>` so all §8.1 adopters agree on a single table. | v0.6.0 (PR #39) |
| `SHARED_SQTAB_INIT` | off | c64-lib-contract SPEC §8.1 deferral: the library stops exporting `sqtab_init` and instead imports the consumer's canonical `mul_tables_init` (aliased locally so internal callers keep working), and drops the `$0001` sqtab bit from `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES`. | v0.6.0 (PRs #39/#43) |
| `SHARED_CT_MUL_8X8` | off | c64-lib-contract SPEC §8.3 deferral (Profile B only). Gates out this library's `ct_mul_8x8` body, the legacy `mul_8x8` body, and the `poly_prod_lo`/`poly_prod_hi` scratch, and imports all of them — plus the `smc_sum_a_imm`/`smc_diff_a_imm` operand-bake sites — from the designated owner in the link. Also drops the `$0004` ownership bit from `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES` so two composed libs sharing the primitive present disjoint masks (issue #21). **Before issue #47 this switch was manifest-only**: it flipped the bit but left the body and all three exports in place, so a two-archive link against c64-x25519 v0.8.0 failed with `Duplicate external identifier: 'poly_prod_hi'`. | v0.6.0 (PR #43), fixed in #47 |

### Shared-primitive masks (SPEC §5 / §8.0)

The library exports **two** masks. `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES`
says what this build *owns*; `LIB_CHACHA20_POLY1305_SHARED_CONSUMES` (added
in issue #52, required by contract v0.5.0) says what it *uses*. The pair
distinguishes a **deferring consumer** — which still reads the primitive at
runtime and so needs exactly one owner in the link — from a **non-consumer**,
which needs no provider at all. The ownership bit alone cannot tell those
apart, and they impose opposite obligations on the consumer.

Two independent gates drive them: the **profile** gate drops a bit from
*both* masks; a `SHARED_*` deferral switch drops it from the *ownership*
mask only.

| build | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` |
|---|---|---|
| Profile A | `$0000` | `$0000` |
| Profile B standalone | `$0005` | `$0005` |
| Profile B `-D SHARED_CT_MUL_8X8=1` | `$0001` | `$0005` |
| Profile B `-D SHARED_SQTAB_INIT=1` | `$0004` | `$0005` |
| Profile B, both switches | `$0000` | `$0005` |

Profile A reads `$0000`/`$0000` because issue #34 F1 gated sqtab,
`sqtab_init` and `mul_8x8` out of that profile entirely and `ct_mul_8x8` is
Profile B only — it is a profile-gated non-consumer of both primitives.
Before issue #51 both bits were claimed unconditionally, so Profile A
advertised ownership of two primitives it does not emit; a consumer
composing Profile A with c64-x25519 saw a false double-ownership collision,
and the coverage assert wrongly concluded sqtab had an owner in the link.

Consumer-side composition uses both masks together:

```asm
; no primitive owned twice
.assert (LIB_A_SHARED_PRIMITIVES & LIB_B_SHARED_PRIMITIVES) = 0, error, "shared-primitive double-ownership"
; no consumed primitive left without an owner
.assert ((LIB_A_SHARED_CONSUMES | LIB_B_SHARED_CONSUMES) & ~(LIB_A_SHARED_PRIMITIVES | LIB_B_SHARED_PRIMITIVES)) = 0, error, "consumed shared primitive with no owner in the link"
```

See `src/lib/lib_manifest.s` for the gate construction and the
adopter-side subset assert that pins ownership ⊆ consumes.

---

## 8. Version and ABI constants

`src/lib_version.s` exports each version constant in **two** forms
(c64-lib-contract SPEC §1, contract v0.7.0 — issues #53/#57):

| Prefixed symbol (use this) | Deprecated bare alias | Value (this release) |
|---|---|---|
| `LIB_CHACHA20_POLY1305_VERSION_MAJOR` | `LIB_VERSION_MAJOR` | 0 |
| `LIB_CHACHA20_POLY1305_VERSION_MINOR` | `LIB_VERSION_MINOR` | 9 |
| `LIB_CHACHA20_POLY1305_VERSION_PATCH` | `LIB_VERSION_PATCH` | 0 |
| `LIB_CHACHA20_POLY1305_ABI_VERSION`   | `LIB_ABI_VERSION`   | 4 |

The bare names are identical across every adopter library, so a consumer
linking two libraries and importing both manifests gets `ld65: Error:
Duplicate external identifier`. They remain exported by default (required
through contract v0.x, removed at v1.0), and a composing consumer
suppresses them across **every** library in the link with:

```
ca65 -D LIB_NO_BARE_EXPORTS=1 ...
```

The bare names alias the prefixed ones, so the two forms cannot drift.

The semver triple tracks the released `CHANGELOG.md` version.
Consumers guard against unsupported versions by importing the constants
and asserting on them:

```ca65
.import LIB_CHACHA20_POLY1305_VERSION_MAJOR
.import LIB_CHACHA20_POLY1305_VERSION_MINOR
.assert (LIB_CHACHA20_POLY1305_VERSION_MAJOR > 0) .or (LIB_CHACHA20_POLY1305_VERSION_MINOR >= 7), lderror, "needs c64-ChaCha20-Poly1305 v0.7+"
```

**It must be `.assert` / `lderror`, not `.if` / `.error`** (SPEC §1,
contract v0.8.1). `.if` requires an assemble-time constant, and an
`.import`ed symbol has no value until link — ca65 rejects an `.if`-based
gate with `Constant expression expected`, so it never assembles at all
rather than silently passing. `.assert` with the `lderror` action defers
evaluation to ld65, the only stage that knows the imported value. The
trade is that the guard fires at link rather than assemble time; it
still fires before anything runs.

This documentation shipped the broken `.if` form through v0.7.0
(issue #68).

The prefixed guard names which library is out of date, instead of
reporting one anonymous version.

`LIB_ABI_VERSION` is a **monotonic generation counter** for the
exported symbol surface (SPEC §1/§7, contract v0.7.5) — deliberately
*not* a mirror of MAJOR. It starts at 1 and increments on any breaking
export change: a removed or renamed symbol, a changed calling
convention, a changed memory model.

It cannot track MAJOR, because §7 permits breaking changes on MINOR
bumps while a library is pre-1.0 — MAJOR stays `0` across breakage, so a
consumer gating on it would never fire for exactly the changes the gate
exists to catch.

| generation | since | what broke |
|---|---|---|
| 1 | v0.6.0 | first published ABI surface |
| 2 | v0.7.0 | removed the exported §8.x bit constants (#57); renamed all library segments (#48) |
| 3 | v0.8.0 | renamed the general-purpose ZP slots to `chacha20poly1305_zp_*` (#76); put the deprecated bare aliases behind `LIB_NO_BARE_EXPORTS` |
| 4 | unreleased | **changed the AEAD calling convention** — the SPEC §14.1 domain guards give `aead_encrypt` a status in A where it previously left A undefined, and give `aead_decrypt` a third return value `$01` |

Generation 2 is the correct value for v0.7.0's surface. The v0.7.0 tag
itself still reports 1: it was cut under §1's then-current "matches the
MAJOR bump" wording, which contract v0.7.5 repudiated. Corrected in
issue #67; published tags are not retagged.

Generation 3 is **published**: `v0.8.0` and `v0.9.0` both ship
`ABI_VERSION = 3`. A consumer can therefore hold a build whose surface is
"generation 3 without the domain guards", and distinguishing exactly that
is what the counter is for — so the §14.1 change increments to 4 rather
than extending 3.

Generation 2 is not a counter-example. `v0.7.0` ships `ABI_VERSION = 1`
and `v0.8.0` jumps straight to `3`, so the value 2 has never appeared in
any release; issue #67 corrected the counter onto a value no consumer was
holding, which is the opposite situation.

`src/lib_version.s`'s generation history labelled generation 3
"unreleased" and shipped that way in both `v0.8.0` and `v0.9.0`, 28 lines
above the constant that set it to 3 (line 64 versus line 92). The label was wrong, not the
constant; it is corrected here. Check the tag rather than the comment:
`git show v0.8.0:src/lib_version.s | grep ABI_VERSION`.
