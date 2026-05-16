# c64-ChaCha20-Poly1305 — Public API (v0.3.0 draft)

Audit of the `.export` surface across `src/main.s` and `src/lib/*.s`.
Calling conventions are taken from the block-comment headers above
each entry. Cycle counts cited are the S13-era Profile A numbers
from `s13_results.md` unless otherwise noted.

> **Naming note.** The task brief mentioned a symbol `poly1305_tag_finalize`.
> **That symbol does not exist in the source tree.** The actual finalization
> entry is `poly1305_final` (in `poly1305_lib.s`). See §Poly1305 below.

---

## 0. Initialization protocol

Required call order for any consumer:

```
1. (once at startup)     poly1305_lib_init       ; build sqtab (+ sqtab2 on Profile B)
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
`sqtab_ready = 0` (loaded from the DATA segment at PRG load time,
which is why `data_lib.s` deliberately places state reservations in
`DATA` not `BSS` — see `data_lib.s:12-18`).

**Profile A + REU optional**: if assembled with
`-DPOLY1305_REU=1`, `poly1305_lib_init` also backs sqtab to REU
(default bank 0 offset $0000), and `poly1305_reu_restore` can
reload it in ~1.1 k cy if the $8000..$83FF window is externally
clobbered. The REU destination bank and offset are now exposed as
three public RAM-backed bytes (`poly1305_reu_sqtab_bank`,
`poly1305_reu_sqtab_offset`) so a consumer linking this library
alongside another REU consumer (e.g. `c64-x25519`, which itself
claims banks 0-1) can relocate the stash to a non-conflicting
region without re-assembling. See §3 `poly1305_reu_sqtab_bank /
poly1305_reu_sqtab_offset` for the runtime override protocol.

### Consumer data buffers to populate before `aead_encrypt`

All live in the library's DATA segment (see `data_lib.s` and
`MEMORY_MAP.md`):

| symbol           | size | purpose                                   |
|------------------|-----:|-------------------------------------------|
| `aead_key`       | 32   | 256-bit symmetric key (secret)            |
| `aead_nonce`     | 12   | 96-bit nonce (public, per-message unique) |
| `aead_aad_ptr`   | 2    | pointer to AAD bytes in RAM               |
| `aead_aad_len`   | 1    | AAD length (0..255)                       |
| `aead_data_ptr`  | 2    | pointer to plaintext/ciphertext in RAM    |
| `aead_data_len`  | 2    | data length LE 16-bit                     |
| `aead_tag`       | 16   | output tag (encrypt) or expected tag (decrypt) |

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
  `cc20_key`). Block is nominally straight-line but **contains
  secret-dependent timing variance** from the rotl/r 1-bit rotate
  carry-wrap branches — see `CT_ANALYSIS.md` finding F2.
- **Performance (S13, Profile A)**: 44 480 cy/block.
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
  Goes through `rotl32_7` (word32_lib subroutine) which has the
  same secret-dep carry-wrap branch as the production ZP macros.
  Do not call from deployed code.

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
  called from the production hot path* — but note: the production
  hot path (`chacha20_block`) does **not** use these — it inlines
  macros in `chacha20_lib.s`. These subroutines are reachable
  only via `chacha20_quarter_round` (test-only).

### rotl32_4 / rotl32_8 / rotl32_12 / rotr32_4 / rotr32_8 / rotr32_12 / rotr32_16

- **Module**: `word32_lib.s`
- **Purpose**: 32-bit rotations by 4, 8, 12, 16 — straight-line
  byte/nibble shuffles with no carry-wrap branch.
- **Signature**: operand addressed via `w32_dst`.
- **Clobbers**: A, Y. Preserves X.
- **CT contract**: **constant-time**. No conditional branches.

### rotl32_1 / rotl32_7 / rotr32_1 / rotr32_7

- **Module**: `word32_lib.s:286, 479, 447, 281`
- **Purpose**: 1-bit and 7-bit rotations.
  `rotl32_7` = `rotl32_8` then `rotr32_1`.
  `rotr32_7` = `rotr32_8` then `rotl32_1`.
- **Signature**: via `w32_dst`.
- **Clobbers**: A, Y. Preserves X.
- **CT contract**: **NOT constant-time.** `rotl32_1` and
  `rotr32_1` contain a `bcc @done` that skips the carry-wrap OR
  depending on bit 31 / bit 0 of the rotated word. See
  `CT_ANALYSIS.md` finding **F2**. Only reachable from production
  via the test-only `chacha20_quarter_round` entry — dead from the
  real AEAD path. They are still exported because the Python test
  harness resolves them by name for unit-test coverage.
- **Dead-code status (answer to team-lead Q1)**:
  - `rotl32_1` (line 286): fall-through from `rotr32_7:` (line 281).
    Nothing in the library imports `rotr32_7` directly. **Dead
    from production; reachable from tests only.**
  - `rotr32_1` (line 447): tail-call target from `rotl32_7:` (line
    479 `jmp rotr32_1`). `rotl32_7` is `.import`ed by
    `chacha20_lib.s:21` and called at `chacha20_lib.s:537`, inside
    `chacha20_quarter_round` — the test-only entry. **Dead from
    `chacha20_block`; reachable from tests only.**
  - Fix agent can freely delete the 1-bit-rotate subroutines if
    the test coverage for `chacha20_quarter_round` can be dropped
    or migrated to a pure-Python reference. Alternative: fix the
    branch in place and keep the test.

---

## 3. poly1305_lib.s

### poly1305_lib_init

- **Module**: `poly1305_lib.s:82`
- **Purpose**: One-time library initialization. Builds the 1 KB
  quarter-square table at `sqtab_lo/hi`. On Profile B also builds
  `sqtab2_lo/hi` and pre-sets `lmul0+1` / `lmul1+1`. On Profile A
  with `POLY1305_REU=1` also DMA-backs sqtab to REU at the
  bank/offset held by `poly1305_reu_sqtab_bank` /
  `poly1305_reu_sqtab_offset` (defaults bank 0 / offset $0000).
- **Signature**: no register args.
- **Preconditions**: **must be called at least once before any
  `aead_encrypt` / `aead_decrypt` / `poly1305_init`.** Idempotent
  via `sqtab_ready` flag.
- **Postconditions**: `sqtab_ready != 0`; `sqtab_lo/hi` populated;
  on Profile B, `sqtab2_lo/hi` populated and `lmul0+1` / `lmul1+1`
  set to `>sqtab_lo` / `>sqtab_hi`.
- **Clobbers**: A, X, Y.
- **CT contract**: PUBLIC inputs only (none — the table values
  are pure functions of the platform, i.e. `floor(n²/4)`). No CT
  concern.
- **Example**:
  ```ca65
  ; At application startup, once:
  jsr poly1305_lib_init
  ```

### poly1305_reu_restore (Profile A + POLY1305_REU=1 only)

- **Module**: `poly1305_lib.s:137`
- **Purpose**: DMA sqtab back from REU to $8000..$83FF using the
  bank/offset held by `poly1305_reu_sqtab_bank` /
  `poly1305_reu_sqtab_offset` (defaults bank 0 / offset $0000).
  Useful if external code clobbers the sqtab window.
- **Signature**: no register args. Emits REU DMA command $91.
- **Preconditions**: `poly1305_lib_init` must have previously run
  (that's what seeded REU with the table data) **with the same
  bank/offset values currently in the RAM cells**. If a consumer
  patches `poly1305_reu_sqtab_bank` / `poly1305_reu_sqtab_offset`
  after the initial stash, they must re-stash before calling
  `poly1305_reu_restore` — otherwise restore will load whatever
  bytes happen to live at the new REU location.
- **Postconditions**: `sqtab_lo/hi` restored; REU state preserved.
- **Clobbers**: A.
- **Cost**: ~1.1 k cy (50 cy setup + 1024 cy DMA burst, plus ~6
  cy of RAM loads over the pre-v0.5.x immediate-operand path).

### poly1305_reu_sqtab_bank / poly1305_reu_sqtab_offset (Profile A + POLY1305_REU=1 only)

- **Module**: `poly1305_lib.s` (DATA segment, exported)
- **Purpose**: Public RAM-backed configuration of the REU stash
  destination. Three bytes total — bank (1 byte) and offset
  (2 bytes, little-endian, lo at `+0` then hi at `+1`) — read by
  the DMA setup paths in `poly1305_lib_init` and
  `poly1305_reu_restore`.
- **Default values**: bank `$00`, offset `$0000`. Defaults are
  baked into the PRG at link time from the assemble-time defines
  `POLY1305_REU_BANK` / `POLY1305_REU_OFFSET`, so a consumer who
  never touches the cells gets pre-v0.5.x behavior verbatim.
- **Override at assemble time** (preferred when the consumer
  controls the build):
  ```sh
  ca65 -DPOLY1305_PROFILE_LONG=1 -DPOLY1305_REU=1 \
       -DPOLY1305_REU_BANK=3 '-DPOLY1305_REU_OFFSET=$1000' ...
  ```
  The RAM cells will come up at $03 / $00 / $10 at PRG load.
- **Override at runtime** (preferred when linking a pre-built
  library, or when several REU consumers must coexist):
  ```ca65
  ; Before calling poly1305_lib_init:
  lda #3
  sta poly1305_reu_sqtab_bank
  lda #<$1000
  sta poly1305_reu_sqtab_offset
  lda #>$1000
  sta poly1305_reu_sqtab_offset+1
  jsr poly1305_lib_init       ; stashes to bank 3 / $1000
  ```
  **The runtime poke must happen before the call to
  `poly1305_lib_init` that performs the initial stash.** If
  patched afterwards, the consumer is responsible for re-stashing
  (the DMA stash inside `poly1305_lib_init` is gated by
  `sqtab_ready` and will not re-execute on subsequent calls).
- **CT contract**: PUBLIC. The bank/offset are configuration
  bytes, not secrets. The DMA setup reads them via straight-line
  `lda abs / sta abs` to the REU control ports — no
  secret-dependent branches, no page-cross addressing modes, no
  timing variability beyond the fixed ~6 cy of additional RAM
  loads vs the pre-v0.5.x immediate-operand path.
- **Motivating use case**: `c64-x25519` claims REU banks 0-1 for
  its own state. A host project linking both libraries can set
  `poly1305_reu_sqtab_bank = 2` (or higher) before
  `poly1305_lib_init` to keep the sqtab backup out of the X25519
  region.

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
  - `zp_ptr1` ($fb-$fc) = pointer to 16-byte block.
  - A = high bit value (1 for normal blocks, 0 for the final
    length-block / partial-padded form).
- **Preconditions**: `poly1305_init` run; `sqtab_ready != 0`.
- **Postconditions**: `poly_h` updated; `poly_product` scratch
  dirty.
- **Clobbers**: A, X, Y.
- **CT contract**: inputs SECRET (block bytes, `poly_h`, `poly_r`).
  See `CT_ANALYSIS.md` §C for branch classification. **Profile B
  goes through `mult66` which has a known secret-dependent branch
  and a secret-dependent `(lmul0),y` page-cross cycle (F3).**
- **Performance (S13)**: Profile A 11 950 cy; Profile B 27 073 cy.
- **Example**:
  ```ca65
  lda #<my_block
  sta zp_ptr1
  lda #>my_block
  sta zp_ptr1+1
  lda #1                ; hibit = 1 for full-message block
  jsr poly1305_block
  ```

### poly1305_update

- **Module**: `poly1305_lib.s:917`
- **Purpose**: Process a multi-byte message as 16-byte blocks,
  zero-padding the final partial block per RFC 7539.
- **Signature**:
  - `zp_ptr1` = data pointer.
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
- **CT contract**: ⚠ **CONTAINS A KNOWN SECRET-DEPENDENT BRANCH
  ON `h + 5` OVERFLOW** — `beq @no_reduce` at line 1021.
  See `CT_ANALYSIS.md` finding **F1**. This is the module entry
  that the task brief called "`poly1305_tag_finalize`"; the actual
  name in the source tree is `poly1305_final`.
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
  tables (`poly_pp_shoup`); Profile B uses mult66
  (`poly_pp_mult66`).
- **`poly1305_reduce`** (`poly1305_lib.s:765`): Fused Donna-style
  wrap reduction of `poly_product` into `poly_h`.
- **`sqtab_init`** (`poly1305_lib.s:346`): Build sqtab_lo/hi from
  scratch via the `i² = (i-1)² + 2i − 1` recurrence.
  `poly1305_lib_init` calls this gated on `sqtab_ready`.
- **`mul_8x8`** (`poly1305_lib.s:473`): Legacy 8×8→16 multiply via
  sqtab. Used by `sqtab2_init` implicitly (via earlier sqtab
  access) and retained for test-vector compatibility. Inputs:
  A, X. Outputs: `poly_prod_lo/hi`. Profile A hot path does not
  call this — it's kept alive because Profile B mult66 uses
  sqtab as its primary table and because `shoup_init`'s S11
  incremental form was derived from (and must stay consistent with)
  the mul_8x8 result for test vectors.
- **`shoup_init`** (Profile A only, `poly1305_lib.s:246`):
  incremental-ripple builder for the 8 KB Shoup `r_tab_lo/hi`.
  SMC-heavy: per outer-j iteration, patches six RAM addresses and
  one `adc #imm` immediate.
- **`poly_prod_lo`, `poly_prod_hi`** (`poly1305_lib.s:470-471`):
  output bytes of `mul_8x8` / `mult66`.
- **`poly_ripple`** (`poly1305_lib.s:600`): propagate a carry
  upward through `poly_product` starting at index X. Called from
  the unrolled schoolbook's `poly_pp_shoup` / `poly_pp_mult66`
  when an add leaves carry set.

---

## 4. chacha20poly1305_lib.s

### aead_encrypt

- **Module**: `chacha20poly1305_lib.s:53`
- **Purpose**: Full RFC 7539 §2.8 AEAD encrypt.
- **Signature**: no register args. All inputs and outputs via
  DATA-segment `aead_*` fields (see §0 above).
- **Preconditions**:
  1. `poly1305_lib_init` called at least once.
  2. `aead_key`, `aead_nonce`, `aead_aad_ptr`, `aead_aad_len`,
     `aead_data_ptr`, `aead_data_len` populated.
- **Postconditions**:
  - Ciphertext written in place at `aead_data_ptr`.
  - `aead_tag[0..15]` holds the 16-byte authentication tag.
- **Clobbers**: A, X, Y, most of `cc20_*` and `poly_*` state.
- **CT contract**: `aead_key` and plaintext are SECRET;
  `aead_nonce`, `aead_aad_*`, and lengths are PUBLIC.
  **Aggregate CT verdict: RED** pending the F1/F2/F3 fixes in
  `CT_ANALYSIS.md`.
- **Performance (S13, Profile A)**: 1 709 171 cy at n=1024;
  187 063 cy at n=0.
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
- **Return**: A = 0 on tag valid, A = $ff on tag mismatch.
- **Preconditions**: same as `aead_encrypt`, plus `aead_tag` holds
  the received tag.
- **Postconditions**:
  - On success (A=0): plaintext written in place at `aead_data_ptr`.
  - On failure (A=$ff): `aead_data_ptr` buffer is unchanged
    (decrypt step is skipped); `poly1305_tag` holds the computed
    tag (differs from the provided `aead_tag`).
- **Clobbers**: A, X, Y.
- **CT contract**: the decrypt→verify→decrypt-on-success chain
  does leak whether the tag was valid (the `bne @auth_fail` at
  line 100). However, the branch input is the *output* of
  `aead_verify_tag`, which folds 16 byte-compares into a single
  OR-accumulator *before* the branch. The accumulator is a
  deterministic function of "tag match vs mismatch" and is
  **public by definition** (the API contract is to reveal that
  bit). This is the canonical CT tag-compare pattern. ✓
  The rest of the AEAD chain inherits RED from the F1/F2 findings.
- **Example**:
  ```ca65
  jsr aead_decrypt
  bne @auth_fail             ; A != 0 = tag mismatch
  ; A == 0: plaintext in aead_data_ptr buffer
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
surface. All reservations live in the DATA segment (not BSS) so
they PRG-load as zero — `sqtab_ready` must read zero at startup or
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

The `.exportzp` declarations in `main.s:43-48` publish every ZP
equate in `constants_lib.s` as a label-file symbol so VICE can
resolve them. These are not callable entries, they are addresses
in the ZP layout.
