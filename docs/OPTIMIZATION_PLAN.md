# ChaCha20-Poly1305 on the C64 — Optimization Plan

Author notes:
- Baseline commit: `923d34d` on `main` (benchmark infra added; no asm changes).
- Numbers in Section 1 are **measured** via `tools/benchmark_chacha20_poly1305.py`.
  Everything else labelled "estimated" or "~" is a guess grounded in the cited
  exemplars — it needs to be re-measured step-by-step.
- **Representation caveat (learned in Step 7)**: several plan estimates —
  most visibly Step 7's −8 000 cy P4 target — are borrowed from
  Andrew Moon's `poly1305-donna` C reference, which uses a
  **radix-2^26 limb** representation. In that form `2^130 ≡ 5 (mod p)`
  lands on a limb boundary, so the fused wrap fold (`*5 at i+j-17`)
  is a clean per-partial-product operation. This library uses a
  **byte (radix-2^8)** representation, where the equivalent
  congruence is `2^136 ≡ 320 (mod p)` — a 6-bit sub-byte misalignment.
  Per-PP folding at byte granularity costs more to realign than the
  fold saves, so the byte-layout achievable form of a Donna-style
  optimization is usually "fold into the reduction step" (where the
  shift amortizes across 17 bytes as straight-line code), not "fold
  into the multiply". Step 7 captured ~13% of its plan-estimated
  savings for exactly this reason. **Any remaining plan item whose
  estimate was transcribed from Moon-style limb code should be
  re-examined before implementation** — the achievable ceiling on
  byte-layout is typically bounded by the pre-optimization reduce
  cost, not by the theoretical limb-form savings. Porting to a
  radix-2^26 internal representation is a much larger rewrite than
  any single step in this plan and is explicitly out of scope.
- Target-app priority per project memory: WireGuard, TLS 1.3, DTLS.
  Packet-size profile is **bimodal**, not uniformly long:
  - **Large**: WireGuard data packets (~1280 B MTU), TLS 1.3 bulk records
    (up to 16 KB, typically chunked at ~1400 B per MTU). These amortize
    per-packet setup over many Poly1305 blocks.
  - **Small**: WireGuard handshake (32/48 B), keepalives (32 B), TLS 1.3
    handshake records and alerts (tens of bytes). These are dominated by
    per-packet setup — any optimization that trades init cost for
    per-block cost is a net loss on these.

  Consequence: per-packet init cost (`aead_encrypt n=0`) and per-block
  cost (`poly1305_block`) must be tracked **separately** in the
  progression table and considered on their own merits. A step that
  wins big on n=1024 but regresses n=0 may require a small-packet
  profile variant (see Project decision #5).

---

## Project decisions (locked)

1. **Target apps**: WireGuard + TLS 1.3. Long messages dominant. No
   GCM-SIV-style short-key churn expected.
2. **Build profiles**: both ship.
   - **Profile A** = REU-assisted + fast path (primary optimization target).
   - **Profile B** = stock C64, no REU, portable baseline with all the
     portable optimizations (ZP state, inlined QRs, rot-rename, P1 unroll,
     SMC). REU-only tricks (REU-DMA quarter-square, REU row fetch) are
     Profile-A-only.
3. **Constant-time by contract**: no `USE_CT=0` escape hatch. The
   `beq @skip_h_zero` / `beq @skip_r_zero` early-exits in
   `poly1305_multiply` are to be removed as part of the P1 unroll step
   (they become straight-line zero-multiplies that always run). CT is a
   correctness contract for this library going forward. See Section 4.
4. **Cadence**: one commit per optimization step. Benchmark gate after
   every step: rebuild, run the full 214-test suite, run the benchmark,
   append a row to the progression table below. Any regression in cycle
   count must be explained in the commit body or the step reverted.
5. **Packet-size awareness**: every optimization step must report
   `aead_encrypt n=0` (pure fixed-cost per packet) **and** `aead_encrypt
   n=1024` in its commit body. A step that improves n=1024 but regresses
   n=0 is not automatically accepted — it must be justified by where on
   the packet-size curve the break-even sits and whether the target
   workloads (WireGuard MTU traffic, TLS 1.3 bulk records, WireGuard
   handshakes, TLS 1.3 handshake records) cluster above or below that
   point. If a win on large packets would visibly hurt handshake
   throughput, the optimization goes behind a **small-packet profile
   variant** — a third build profile, or a runtime `aead_encrypt_short`
   entry point, depending on which is cheaper. The Profile A / Profile B
   scaffold from Step 5 is the place this would land.

### Progression table

Columns: commit, chacha20_block (cy), poly1305_block (cy),
aead_encrypt n=1024 (cy), delta vs baseline (aead_encrypt n=1024).

| step                                    | commit    | chacha20_block | poly1305_block | aead_encrypt n=1024 | Δ vs baseline |
|-----------------------------------------|-----------|---------------:|---------------:|--------------------:|--------------:|
| S0 baseline (benchmark infra)           | `923d34d` |        149 987 |         53 270 |           5 974 048 |          0.0% |
| S1 C1 ZP-resident cc20_work             | `380ae42` |        149 898 |         53 609 |           6 004 218 |         +0.5% |
| S2 C2 inline 8 QRs per double-round     | `7a62737` |         50 228 |         53 552 |           4 290 622 |        -28.2% |
| S3 C3 rot-8/16 offset rename            | `71fabf3` |         45 954 |         53 381 |           4 220 923 |        -29.3% |
| S4 P1 unroll poly1305_multiply + CT     | `7e6589f` |         45 957 |         39 797 |           3 497 234 |        -41.5% |
| S5 profile dispatch scaffold (no-op)    | `fd9323b` |         45 957 |         39 675 |           3 497 228 |        -41.5% |
| S6 P3 Shoup per-r table (Profile A)     | `09b93f7` |         45 940 |         12 987 |           2 282 955 |        -61.8% |
| S7 P4 Donna fused wrap (both profiles)  | `1889efd` |         45 946 |         11 949 |           2 216 477 |        -62.9% |
| S8 A3-A6 + C7 AEAD/ChaCha glue (both)  | `202d0b3` |         44 922 |         12 122 |           2 197 974 |        -63.2% |

**Note on S1**: the `chacha20_block` delta is only −89 cy (vs plan
estimate −20 000 cy). C1 in isolation does not eliminate much: the QR
hot path still goes through `(w32_dst),y` ZP-indirect indexed loads
(5 cy), and only the two 64-byte copy loops (`state→work` and
`work→keystream`) and the final `work += state` addressing get the
`abs,x → zp,x` savings. ACME correctly emits `zp,x` for
`lda/sta cc20_work,x` (verified: chacha20_lib is now 2 bytes shorter),
but there are only ~128 such ops per block. **The −20 000 cy estimate
implicitly assumed C2 (QR inlining) was bundled — it isn't realized
until Step 2.** The +0.5% aead_encrypt regression and +339 cy
poly1305_block drift are code-layout artifacts: moving cc20_work out
of `data_lib.asm` shifted `poly1305_block` from $0eb8 to $0eb6, which
changes the page-boundary alignment of inner branches in the 272-iter
multiply loop (≈1.25 cy × 272 iters = +339). This will disappear once
Step 4 unrolls the multiply. S1 stands because C1 is a correctness
prerequisite for Steps 2 and 3; the real win lands there.

**Note on S5**: scaffolding-only step. Adds `POLY1305_PROFILE_LONG`
flag in `constants_lib.asm` (default ON) and `make profile-a` /
`make profile-b` dispatch. No runtime code consumes the flag yet —
Steps 6 and 7 will gate their new paths on `!ifdef POLY1305_PROFILE_LONG`.
Profile A and Profile B PRGs are **byte-identical** at this step
(verified via `cmp`), and the test suite passes 214/214 under both
profiles. The row above shows Profile A bench numbers; the
`poly1305_block` −122 cy drift vs S4 (39 675 vs 39 797) is pure bench
noise (S4's own reported spread was already on this order; no code
or layout changed between S4 and S5). `Δ est. = 0` confirmed.

**Note on S6**: P3 Shoup per-r table, Profile A only. Replaces the
272-iter sqtab-backed `mul_8x8` schoolbook in `poly1305_multiply` with
two page-indexed `lda tab,x` loads per partial product against
precomputed `T_j[x] = x * r[j]` tables at `$6000..$7FFF` (16 × 2 ×
256 B = 8 KB, page-aligned per limb). X is also hoisted out of the
inner j-loop since h[i] is constant across one i-row. Tables are
built by `shoup_init` inside `poly1305_init` using the existing
`mul_8x8` primitive (so sqtab is retained). Measured
`poly1305_block` = 12 987 cy, **Δ = −26 688 cy** vs S5 — beats the
plan's −25 000 cy estimate and the 18 000 cy gate by ~5 k. The
`poly1305_init`/per-packet fixed cost went up by ~420 k cy (250 k ->
670 k in n=0 aead_encrypt), dominated by 4096 calls to `mul_8x8`
during table build; the plan's +50 000 cy estimate was too low by
~8×, because each `mul_8x8` call is ~100 cy including jsr/wrapper,
not ~12 cy. Amortization break-even is ~16 blocks (256 B of message)
instead of the estimated ~2; for n=1024 the net saving is
~1 214 k cy per packet, which still dominates the penalty. Profile B
is byte-identical to pre-S6 Profile B (verified via md5sum after
`git stash` / rebuild / diff — see commit body). The `!ifndef
POLY1305_PROFILE_LONG { POLY1305_PROFILE_LONG = 1 }` auto-default
from S5 was *removed* in this step: leaving it in would silently
force Profile A on any caller that just `!source`s the library, so
absence of the symbol now correctly selects Profile B.

**Note on S7**: P4 Donna-style fused wrap reduction (both profiles).
The 17×16 schoolbook still emits a 33-byte intermediate `poly_product`,
but `poly1305_reduce` is rewritten as a single fully-unrolled fused
pass that merges the two old 1-bit `ror` shifts and the 17-byte
running-carry `*5` add into straight-line per-byte code. A 256-byte
LUT (`poly_reduce_shl6_tab`) supplies `(y & 3) << 6` so the inter-byte
2-bit boundary doesn't need 6 inline `asl`s. The product-zeroing
prologue is also unrolled to 33 straight-line `sta`s. Profile A
measured `poly1305_block` = **11 949 cy**, **Δ = −1 038 cy** vs S6
(beats the < 12 000 cy gate by 51 cy); the plan's −8 000 cy estimate
assumed the multiply itself would shrink (true Donna fusion), but the
Shoup hot path is already at the inner-loop floor for byte-aligned
schoolbook on 6502 — the realisable savings are bounded by the cost
of the *reduction*, not the multiply, which is what was actually
attacked. Profile B `poly1305_block` = 38 666 cy (was 39 675, **Δ =
−1 009 cy**), confirming that — unlike S6 — Step 7 helps both profiles
without conditional code. The clean-byte Donna fold (`*5` at position
`i+j-17`) is **not** literally byte-aligned for a 16-bit Poly1305 byte
representation: `2^136 ≡ 320 mod p`, not `5`, so the fold has a 6-bit
sub-byte misalignment that defeats per-PP fusion in the multiply's
inner loop. Folding into the reduction (where the 2-bit shift can be
amortised across 17 bytes) is the achievable form of P4 in this byte
representation. n=0 aead_encrypt: 670 919 cy (was 671 332, ≈ flat as
expected — the rewrite touches `poly1305_multiply` runtime, not
`poly1305_init` setup). 10 000 random Poly1305 vectors cross-checked
against pyca/cryptography pass on both profiles (seed `20260411`).

**Note on S8**: A3-A6 + C7 AEAD/ChaCha glue cleanups (both profiles).
Five sub-items implemented; C6 (counter-increment fold) retained in
place as its relocation is net-zero cycles and conflicts with A5's
free counter-prime. **A5 (fold OTK into encrypt)** is the biggest
per-packet win: `aead_derive_otk`'s `chacha20_block` tail-inc already
primes `cc20_state+48` = 1, so both encrypt and decrypt skip a
redundant `aead_setup_chacha` + `chacha20_init` (saves ~2 600 cy
per packet). **C7 (keystream alias)** eliminates the 64-byte
`work → keystream` copy in `chacha20_block` by aliasing
`cc20_keystream = cc20_work` — saves ~1 000 cy per block, ~16 000 cy
at n=1024. **A3 (unrolled lengths zero)** and **A6 (skip decrypt
re-init)** contribute small per-packet savings folded into the n=0
delta. **A4 (SMC tail-block dispatch)** replaces the zero+copy loop
for partial Poly1305 blocks with a jump-into-chain dispatch on n (a
public length — CT-safe); affects only non-16-multiple message lengths
(bench uses n=1024 = 0 mod 16 so A4 is invisible in the progression
table, but passes 214/214 including lengths 1, 63, 65, 127, 129, 255,
511). Profile A `aead_encrypt n=0` = 668 308 cy (gate 248 000 not met
— dominated by Shoup `poly1305_init` ~420 k cy; see S6 note). Profile
B `aead_encrypt n=0` = 176 200 cy (**gate met**). `poly1305_block`
+173 cy drift is bench noise (no Poly1305 code touched).

Subsequent steps append a row here with their measured cycle counts and
commit hash.

---

## Section 1 — Baseline

### Measured baseline (`benchmark_chacha20_poly1305.py`, 3 samples, `min`)

| routine                           |      cycles |  spread |
|-----------------------------------|------------:|--------:|
| `chacha20_block` (64 B keystream) |    **149 987** |     516 |
| `poly1305_block` (16 B add+mul+reduce) | **53 270** |      32 |
| `aead_encrypt` n=0                |     251 330 |     342 |
| `aead_encrypt` n=64               |     643 118 |   5 276 |
| `aead_encrypt` n=128              |     998 801 |   5 256 |
| `aead_encrypt` n=512              |   3 130 996 |   6 327 |
| `aead_encrypt` n=1024             |   5 974 048 |   6 825 |
| `aead_decrypt` n=0                |     251 698 |     336 |
| `aead_decrypt` n=64               |     643 363 |     231 |
| `aead_decrypt` n=128              |     999 150 |     218 |
| `aead_decrypt` n=512              |   3 131 531 |      79 |
| `aead_decrypt` n=1024             |   5 974 339 |     415 |

Derived cycles-per-byte (`aead_encrypt`):

| n    | total cycles | cy/byte |
|------|-------------:|--------:|
|   64 |      643 118 | 10048.7 |
|  128 |      998 801 |  7803.1 |
|  512 |    3 130 996 |  6115.2 |
| 1024 |    5 974 048 |  5834.0 |

The n=0 AEAD cost (~251 k cy) is the per-packet fixed overhead: derive OTK
(one `chacha20_block` at counter=0 + copy to r/s) + `poly1305_init` (which
builds the 1 KB quarter-square sqtab at `$8000..$83FF` — ~80–90 k cy) +
one final lengths-block mul + tag finalize. The sqtab build and the OTK
chacha20_block dominate the fixed cost today.

### Hot-path accounting at n=1024 (16 chacha blocks + 64 poly blocks)

```
chacha20_block   × 16 ≈ 2 400 k cy   (~40 %)
poly1305_block   × 64 ≈ 3 410 k cy   (~57 %)
fixed (OTK+init) × 1  ≈   165 k cy   (~ 3 %)
                      ---------
                       ~5 974 k cy
```

**Conclusion: Poly1305 is the larger tent pole at long messages (57 %),
ChaCha20 is the second (40 %). Both deserve work; Poly1305 has more headroom.**

### Comparison anchors

- **AVR Salsa20**: 18 166 cy / 64-byte block = 284 cy/B (NaCl-on-AVR paper,
  Hutter & Schwabe 2013, §4.1). We're at ~2 343 cy/B on chacha20_block —
  i.e. roughly 8× slower than AVR Salsa20. The AVR wins come almost
  entirely from (a) 32 registers vs 3, and (b) `MUL` / enough registers
  to keep the whole 64-byte state register-resident. Neither ports. The
  portable wins are register-rename rotations and fully inlined QRs —
  those we haven't applied yet.
- **AVR Poly1305**: 211 cy/B (Hutter & Schwabe 2013, §5.1; 17×17-byte mul
  = 1 967 cy on AVR with hardware `MUL`). We're at ~3 329 cy/B per
  `poly1305_block` standalone, i.e. ~16× slower than AVR Poly1305. AVR has
  hardware mul; we do schoolbook with a quarter-square lookup (~40–50 cy
  per 8×8 including JSR/RTS and page branch). So the ~16× gap is what
  "no hardware MUL" looks like. Realistic target after optimization: ~2–3×
  our current, i.e. ~700–1 500 cy/B.
- **No published 6502 ChaCha20 or Poly1305 was found.** Baseline is
  state-of-the-art on the platform. Negative result verified via web
  search for `"poly1305" "6502" OR "C64" OR "commodore"`.

---

## Section 2 — ChaCha20 optimization strategy

Current design (`src/lib/chacha20_lib.asm` + `word32_lib.asm`):

- `cc20_state` / `cc20_work` / `cc20_keystream` in absolute RAM (`data_lib.asm`).
- Every 32-bit operation is a subroutine (`add32_to_dst`, `xor32_in_place`,
  `rotl32_*`) that takes `w32_dst` / `w32_src1` as ZP-indirect pointers.
- `chacha20_quarter_round` does 12 `jsr`s per QR, each re-patching the
  pointer macros, each re-entering a 4-iteration `(ptr),y` loop body.
- `chacha20_block` calls `chacha20_quarter_round` 80× per block (8 × 10
  double-rounds) through a QR-index table and a JSR.
- **Rotations are executed**: even `rotl32_8` does a 13-byte PLA/PHA
  byte-reshuffle via `(w32_dst),y` loads — i.e. every rot-8/rot-16 is
  ~50–70 cycles of actual work rather than the zero-cost byte-rename it
  ought to be.

Measured: 149 987 cy per block = ~1 875 cy per QR (baseline includes the
state→work copy and the final state add and keystream copy). That's **~11×
the AVR figure** (174 cy/QR on AVR per Hutter & Schwabe §4.1), so there is
a lot of fat.

### ChaCha20 ranked optimizations

| # | Optimization | Δ / 64 B block (est.) | Code size | Risk | Dep. | Profile |
|---|---|---:|---:|---|---|---|
| C1 | **Put `cc20_work` in zero page** (64 B in ZP, reclaim from BLAKE2/x25519 slots not used here) | -20 000 cy | neutral | low | — | A+B |
| C2 | **Fully inline the 8 QRs per double-round** and inline the 32-bit add/xor/rot bodies: kill 80 `jsr`s + 80 `rts`s per block, kill pointer-patching macros | -30 000 cy | +~600 B | med | C1 | A+B |
| C3 | **Rot-16 / rot-8 as "address rename"**: when QR bodies are inlined, each word's 4 bytes live at known ZP offsets; rot-16 becomes "swap operand pairs in subsequent adds", rot-8 becomes a +1 offset shift into the operand list. Zero runtime cost per mjosaarinen/chacha-avr pattern (github.com/mjosaarinen/chacha-avr/blob/master/chacha_core_avr.S, Saarinen 2018). | -8 000 cy (16 rotations × ~500 cy saved) | ~0 | med | C2 | A+B |
| C4 | **Rot-12 as rot-8 + rot-4**, rot-7 as rot-8 − rot-1: we already do this, but with `jsr` linkage. After C2 these become inline; rot-8 is free (C3); rot-4 is the dominant remaining cost. Implement rot-4 as one unrolled pass of `asl/rol` ×4 (or `lsr/ror` ×4) with wrap, ~30 cy instead of current ~140 cy. | -3 500 cy | +200 B | low | C2,C3 | A+B |
| C5 | **Fixed first row**: state[0..3] = `"expand 32-byte k"` never change (before the final `work += state` add). After the add, they're input-dependent again. Skip the row-0 copy in the `state→work` prelude and the four `cc20_set_dst 0` recomputes in QR0..QR3 column rounds by baking the constants as immediate values into the first-round-only add. | -~1 200 cy | +100 B | low | C2 | A+B |
| C6 | **Counter-increment fold**: `chacha20_block` ends with a 4-byte `inc; bne; inc;…` counter step. When invoked from `chacha20_encrypt` in a tight loop, fold the counter increment into the state init instead of the end-of-block tail. | -~30 cy/block | 0 | low | — | A+B |
| C7 | **Keystream XOR inline with copy**: `chacha20_block` copies work→keystream (64 bytes) and `chacha20_encrypt` then re-reads keystream to XOR with data. Merge: write final `work+state` byte straight into `*data ^=` in the encrypt loop. Saves a 64-byte copy + a 64-byte re-read per block. | -~700 cy | +100 B | med | C2 | A+B |
| C8 | **SMC operand baking in the `state→work` copy and `work += state` tail**: ldy-indexed loops become straight-line `lda cc20_state+n / sta cc20_work+n` pairs. Already trivial if inlined. | -~400 cy | +200 B | low | C1 | A+B |

**Projected `chacha20_block` after C1–C5: ~80–90 k cy** (~45 % improvement).
That drops the 1024-byte AEAD ChaCha contribution from 2.4 M → ~1.4 M, i.e.
a ~17 % wall-clock win on the full AEAD.

### Discussion

- **ZP-resident state (C1)**: the entire `cc20_work` (64 B) is the hot
  working set of ChaCha20. Keeping it in ZP turns `(ptr),y` indirects
  (5 cy) into `zp,x` / bare `zp` (3 cy) and, more importantly, kills
  the pointer-setup overhead entirely. We have the ZP budget: the
  library's current footprint is `$02..$1d + $fb..$fe` ≈ 32 bytes. We
  need 64 more bytes of ZP for `cc20_work`. Feasible: C64 free ZP
  locations `$fb..$fe` and much of `$02..$8f` can be claimed during
  the AEAD call window (BASIC/KERNAL do not run inside our JSR).
- **Full unrolling (C2)**: 80 QRs × ~12 opcodes inlined per QR ≈ 960
  inlined operations = ~3 KB of code if naïve, probably ~1.5–2 KB with
  shared byte accesses. Well within the C64's RAM budget. The polyval
  project's inlined 16-byte sweeps (`c64-polyval/src/lib/polyval_long.asm`
  lines 22–106) are the template; the win there was 25 945 → 18 699 cy
  (~28 %) for a single polyval block, i.e. the same structural change
  with similar expected delta magnitude.
- **Rot-by-8/16 as rename (C3)**: this is the single highest-leverage
  optimization in the paper literature (mjosaarinen/chacha-avr header:
  rot-16 is "register pair reorder", rot-8 is "byte permutation"). For
  us it manifests differently: the state words don't live in registers,
  they live at fixed ZP offsets. After a rot-8, the "logical byte 0"
  of a word is at the physical byte-1 offset. If all subsequent reads
  of that word in the QR are indexed through macro arguments, we can
  shift the argument list by one byte offset instead of physically
  copying. The complication is that after a later add or XOR the
  bytes get re-aligned. Doable by tracking two rotation states per
  word through the QR ("even" and "rot8") and emitting the correct
  operand offsets per instruction. Prototype on a single QR first
  (see Section 7, experiment E1).
- **Rot-4 / rot-7 / rot-12**: rot-12 = rot-8 + rot-4, rot-7 = rot-8 − rot-1.
  After C3, rot-8 is free, so the total cost per QR is rot-4 (b<<<12)
  + rot-1 (b<<<7). Both are unavoidable multi-cycle shifts; the key is
  to do them in-register rather than through ZP indirect stores.

---

## Section 3 — Poly1305 optimization strategy

Current design (`src/lib/poly1305_lib.asm`):

- 17×16 schoolbook multiply via `mul_8x8` quarter-square table (1 KB at
  `$8000..$83ff`, built at runtime by `sqtab_init` per `poly1305_init`).
- `mul_8x8`: ~40–50 cy per 8×8 including the sum-page branch.
- Outer/inner loop is `ldx poly_i / lda poly_h,x` with a `beq @skip_h_zero`
  early-out. Inner loop re-loads `h[i]` on every iteration (there's a
  `pha`/`pla` pair per inner iteration to thread it through `mul_8x8`'s
  register convention). That's 17 × 16 = 272 inner iterations per block.
- Reduction: 2× pass of 17-byte `ror` chains, then 17-byte inline `*5`
  into `h`.
- `poly1305_block` adds the block (with hibit) via `(zp_ptr1),y` then
  calls `poly1305_multiply`.

Measured: 53 270 cy per block. For a random-looking accumulator and `r`,
272 mul_8x8 calls + shuffle ≈ 272 × ~45 + ~15 000 reduce/adc overhead
≈ 27 000 cy. Observed is ~2× that — indicates the per-call glue
(`poly_i`/`poly_j` loading, `pha`/`pla`, carry propagation) is as
expensive as the multiply itself.

### Poly1305 ranked optimizations

| # | Optimization | Δ / 16 B block (est.) | Code size | Risk | Dep. | Profile |
|---|---|---:|---:|---|---|---|
| P1 | **Fully unroll the 17×16 schoolbook** into straight-line code; eliminate `poly_i`/`poly_j` loop state, eliminate `pha`/`pla`, eliminate carry-propagate branch loop. Also removes the data-dependent `beq @skip_h_zero` / `beq @skip_r_zero` early-exits (constant-time contract — see Section 4). | -12 000 cy | +~1.5 KB | med | — | A+B |
| P2 | **Bake `r` into the multiply body (SMC)**: `r` is fixed for an entire packet (derived once per AEAD call). Instead of `lda poly_r,y`, use `lda #$??` immediates patched at `poly1305_init` time. Removes one ZP load per inner iteration (272 × 3 cy = ~800 cy) and opens the door to P3. | -800 cy (alone) | +~700 B | med | P1 | A+B |
| P3 | **Shoup-style per-r table (16 × 256 bytes = 4 KB)**: for each `r[j]`, precompute `r[j] * 0..255` as a pair of 256-byte tables (lo/hi). Inner multiply becomes two `lda tab,x` + `adc` — ~8 cy instead of ~45 cy. Precompute cost: 16 × 256 × ~12 cy ≈ 50 k cy per packet. Break-even: ~2 blocks. Worth it for ≥4-block messages (≥64 B). | -25 000 cy | +4 KB tables + ~500 B code | med | — | A only |
| P4 | **Donna-style fused wrap**: in the schoolbook, for `j > i` directly accumulate `h[j] * r[i+17-j] * 320` (i.e. `*(5<<6)`) into position `i+j-17`, per floodyberry/poly1305-donna-8.h. Fuses the `*5` reduction into the multiply so we never form the 33-byte intermediate. Avoids the 2-pass 17-byte `ror` reduction entirely. | -8 000 cy | ~0 | high | P1 | A+B |
| P5 | **Skip multiplications involving clamped `r` bits**: after clamping, `r[3]`, `r[7]`, `r[11]`, `r[15]` have their top 4 bits zero (so those bytes are ≤ 15, but still multi-bit), and `r[4]`, `r[8]`, `r[12]` have their bottom 2 bits zero. This does NOT give us skippable partial products — those r bytes can still be fully nonzero, just constrained. **Do not pursue.** Documenting the negative result so we don't revisit. | 0 | 0 | — | — | n/a |
| P6 | **`aead_scratch` -> ZP for partial-block fast path**: current code copies last partial block into `aead_scratch` in RAM and re-points `zp_ptr1`. If instead the scratch lives in ZP and `poly1305_block` reads from it via `zp,y`, we save ~60 cy on every message with a partial tail. | -60 cy/packet | neutral | low | — | A+B |
| P7 | **Merge `poly1305_block` add + first multiply partial-product pass**: the add loop writes `h[i]`, the next multiply loop immediately reads `h[i]`. Fuse so each iteration adds `block[i]` and kicks off the `h[i] * r[*]` pass without re-loading. | -700 cy | ~0 | med | P1 | A+B |
| P8 | **Move sqtab build from `poly1305_init` to one-time library init** — the sqtab is a pure function of the platform, not of `r`. Saves ~80 k cy of per-packet setup. Applies to Profile B unconditionally (Profile A replaces sqtab with Shoup tables and may drop sqtab entirely). | -80 000 cy/packet (one-time) | 0 | low | — | B primary; A if sqtab retained |

**Projected `poly1305_block` after P1+P4+P7 (no Shoup table): ~28–32 k cy**
(~42 % improvement).
**With P3 (Shoup table): ~12–18 k cy per block**, amortizing 50 k cy
precompute over N ≥ 4 blocks. For a 1024 B packet (64 poly1305 blocks):
64 × 15 k + 50 k ≈ 1.01 M cy, i.e. **3.4× faster than current** on the
poly side alone.

### Discussion

- **17 × 8-bit limbs is the right layout for 6502.** 26-bit limbs require
  64-bit-wide accumulator registers (loup-vaillant.fr/tutorials/poly1305-design);
  no 8-bit CPU can use them efficiently. Confirmed: donna-8.h stays at 17
  bytes, Hutter/Schwabe (§5.1) treat Poly1305 as a 17×17-byte mul on AVR.
- **Quarter-square vs mult66 vs Shoup-8**: three realistic primitive
  choices.
  - *Quarter-square* (current): 1 KB runtime table, ~45 cy / 8×8. Uses
    `sqtab[a+b] - sqtab[|a-b|]`. Table built in `poly1305_init`.
  - *mult66 indirect* (c64-x25519/src/fe25519.asm:829): caches one operand
    into a ZP pointer low byte, eliminates the sum-page branch. ~30–35 cy
    / 8×8. Smaller table bytes, but still ~256×2 = 512 B.
  - *Shoup per-r*: for this specific call site, the multiplier `r` is
    fixed for the whole packet. We can build 16 pairs of 256-byte
    tables (lo/hi of `r[j] * 0..255`) at `poly1305_init` time. Inner
    multiply is then `lda rjlo,x / adc ... / lda rjhi,x / adc ...`
    ~8 cy. This is what `c64-nist-curves` and the REU-DMA'd row
    strategy in `c64-x25519/src/fe25519.asm:326` reduce to when the
    multiplier is fixed.
- **Per-r Shoup table amortization**: 16 × 512 B = 8 KB RAM (lo/hi
  pair per r byte). Precompute cost estimate: 16 r-bytes × 256 products
  × ~12 cy each ≈ 50 k cy. **Break-even at ~2 blocks, solid win at ≥4.**
  For WireGuard's 88-block typical packet, amortized cost per block is
  ~12 k cy + 780 cy setup amortization ≈ **16 k cy per block, down from
  53 k**. This is the biggest single Poly1305 optimization available.
- **Reduction fused into multiply (donna-8 style)**: for `j > i`, the
  product `h[j] * r[i-j+17]` belongs at position `i-j+17` in the
  unreduced product. Multiplying by `2^130` (position wrap) and
  reducing yields a factor of `5 << (i-j+17 - 16 - 1)` = varies per
  position. The donna-8 approach hard-codes these factors. Complex
  to derive but eliminates the entire 2-pass `ror` reduction and
  the `*5 + carry` loop. Worth ~8 k cy per block post-P1.
- **Don't ignore REU**: c64-nist-curves (per project survey) cites REU
  DMA'd multiplication rows as the top optimization in `fp256.asm`.
  For Poly1305, REU DMA is equivalent to the Shoup table (preload 4 KB
  from REU at `poly1305_init` instead of computing it). Same speed,
  smaller perceived "precompute cost" (~5 k cy for a DMA burst vs
  ~50 k cy for code-based precompute). **Only useful if we're willing
  to make REU required for Profile A.**
- **SMC + Shoup together**: once the Shoup table exists, the inner loop
  is `lda rjlo,x / adc addr,y / sta addr,y / lda rjhi,x / adc addr+1,y`.
  The `addr,y` addresses can be SMC-patched per outer-loop iteration
  (bake `i+j` base into each unrolled row), exactly like `fe25519.asm:344`
  bakes `fe_wide+i`.

---

## Section 4 — AEAD glue optimizations

**Constant-time contract**: this library is constant-time by contract.
No optimization in Section 4 (or anywhere else) may introduce a
data-dependent branch on secret data (`key`, `r`, `s`, `h`, plaintext,
ciphertext, tag). `aead_verify_tag`'s OR-accumulator pattern is the
canonical CT tag compare — do not regress it. The `poly1305_multiply`
early-exit branches on `h[i]==0` and `r[j]==0` are removed as part of
P1. There is no `USE_CT=0` escape hatch.

Current: `aead_compute_tag` processes AAD, then ciphertext, then a 16-byte
lengths block. Each transition calls `aead_process_padded` which does a
byte-loop partial copy into `aead_scratch`. Tag compare uses an OR-accumulator
constant-time pattern.

| # | Optimization | Δ | Risk |
|---|---|---:|---|
| A1 | **Keep `aead_compute_tag` constant-time as-is** — current `poly_carry` OR-accumulate in `aead_verify_tag` is already CT-safe. No change. | 0 | — |
| A2 | **Elide AAD padding block when aad_len == 0**: current code correctly skips (`@skip_aad`), but lengths block is still processed unconditionally. No change needed. | 0 | — |
| A3 | **Zero the lengths scratch with `stx` not a loop** (the scratch is 16 bytes; unroll and store `#0` 16 times). | -80 cy | low |
| A4 | **Merge partial-block zero-fill with copy**: instead of zero-fill then overwrite, write bytes 0..n-1 from source and bytes n..15 as `#0` in a single unrolled sequence (one per remainder value). SMC the jump offset into the fill tail based on `n`. | -~200 cy/packet | med |
| A5 | **Fold OTK derivation into encrypt**: currently `aead_derive_otk` generates a 64-byte keystream block at counter=0, copies first 32 bytes to `poly_r`/`poly_s`, then `aead_encrypt` re-initializes ChaCha20 with counter=1 and regenerates keystream. The state setup is identical — cache it. Save one `chacha20_init` + one `aead_setup_chacha` per packet. | -~2 000 cy/packet | low |
| A6 | **Skip `aead_setup_chacha` on decrypt-after-tag-ok**: decrypt computes tag first (reading ciphertext), then re-does the whole ChaCha20 setup for the real decrypt pass. The key/nonce are unchanged; only the counter differs. Just write `cc20_counter`=1 and call `chacha20_init`. Already done, but the inner `copy_key`/`copy_nonce` memcpy is redundant after the first call. Skip via a flag. | -~500 cy/packet | low |

Total AEAD-glue win: ~3 k cy / packet. Minor relative to Section 2 and 3,
but they're cheap and safe — do them as a cleanup step.

---

## Section 5 — Build profiles

**Both profiles ship.** Profile A is the primary optimization target;
Profile B is the portable baseline that must work on stock hardware.
Any optimization that does not require REU is applied to *both*
profiles. REU-DMA tricks are Profile-A-only.

### Profile A — REU-assisted / fast path (primary target)

- **Hardware assumption**: REU available.
- **ChaCha20**: full C1–C8 (ZP state, inlined QRs, rot-rename, rot-4
  inline, SMC, keystream-XOR merge, counter-fold, fixed-row skip).
- **Poly1305**: P1 (unroll), P2 (SMC `r`), P3 (Shoup per-r table,
  16×512 B = 8 KB), P4 (donna fused wrap), P6 (ZP scratch), P7 (add+mul
  merge). P8: either retain sqtab as one-time build or drop it once P3
  lands; decide at P3 commit time.
- **REU-only tricks** (target applications for this profile): REU-DMA
  prefetch of Shoup tables or quarter-square table from REU RAM instead
  of in-RAM compute (~5 k cy DMA burst vs ~50 k cy runtime build).
  Optional Step 10.
- **RAM budget**: ~14 KB (~4 KB code extra + 8 KB Shoup tables + 1 KB
  retained sqtab if kept).

**Typical use**: WireGuard data (~88 blocks), TLS 1.3 records (~64
blocks), long DTLS. Messages ≥ 64 B where the per-packet ~50 k cy
Shoup-table build amortizes.

### Profile B — stock-C64 portable baseline

- **Hardware assumption**: truly original stock C64. No REU. Must work
  everywhere.
- **ChaCha20**: full C1–C8 (all portable). Same inlined hot path as
  Profile A. ChaCha20 does not benefit from per-packet precompute, so
  Profile A and Profile B have identical chacha20_block code.
- **Poly1305**: P1 (unroll), P2 (SMC `r`), P4 (donna fused wrap),
  P6 (ZP scratch), P7 (add+mul merge), P8 (one-time sqtab build).
  **No Shoup table (P3)** — avoids the 8 KB RAM claim and the 50 k
  per-packet precompute.
- **RAM budget**: +~4 KB code, 1 KB shared sqtab. Total library
  footprint ~6 KB, comfortable on a stock machine.

**Typical use**: any deployment that cannot assume REU. Slower by the
P3 delta (~25 k cy per poly1305_block) but correct and portable.

### Profile gating

- Implemented via ACME `!ifdef POLY1305_PROFILE_LONG` (Profile A) / else
  (Profile B). Default build is Profile A (`make` with
  `POLY1305_PROFILE_LONG` defined in `constants_lib.asm` or via a
  `make profile-a` / `make profile-b` dispatch target — added as a
  dedicated sprint step the first time a profile-specific change lands).
- Both profiles must pass 214/214 tests. Benchmark runs against Profile A
  unless otherwise noted; Profile B is re-benchmarked at Step 9 for the
  final summary.

### Target-app decision matrix

| target app        | typical msg | blocks | profile |
|-------------------|-------------|--------|---------|
| WireGuard data    | up to ~1420 | ~88    | **A**   |
| TLS 1.3 record    | up to ~1024 | ~64    | **A**   |
| WireGuard handshake | ~148       | ~9     | **A**   |
| DTLS small        | ~32–128     | ~2–8   | **A** (falls back to B if no REU) |
| isolated tag      | ~16         | ~1     | **B** (also works in A) |
| stock-C64 end users without REU | any  | any    | **B**   |

---

## Section 6 — Sprint plan

Each step is **exactly one commit**. Every step has:
(a) one-sentence change description
(b) files touched
(c) expected cycle delta
(d) test gate: `C64_SKIP_BUILD=1 python3 tools/test_chacha20_poly1305.py
    --seed 7539 --verbose` must report 214/214 passing
(e) benchmark gate: rerun `python3 tools/benchmark_chacha20_poly1305.py`,
    append a row to the progression table at the top of this document
    with `chacha20_block`, `poly1305_block`, `aead_encrypt n=1024`, and
    the new commit hash.

Any regression in cycle count must be explained in the commit body or
the step reverted.

### Step 0 — Baseline snapshot (done)
- **Commit**: `923d34d` (benchmark infra + baseline measurements).
- No code changes; seeds the progression table. Referenced in Section 1.

### Step 1 — ZP-resident `cc20_work` (C1)
- **What**: move `cc20_work` (64 B) from RAM to a ZP claim at `$40..$7f`
  so `(w32_dst),y` indirects into ZP and the direct `sta cc20_work,x`
  loops become ZP,x addressing.
- **Files**: `src/lib/constants_lib.asm` (add `cc20_work` equate),
  `src/lib/data_lib.asm` (drop the 64-byte RAM reservation),
  `src/lib/chacha20_lib.asm` (no logical changes; references auto-rewire
  via the label).
- **Δ est.**: −20 000 cy per `chacha20_block`; scales linearly into
  `aead_encrypt n=1024` (16 blocks → −320 000 cy).
- **Test gate**: 214/214 via
  `C64_SKIP_BUILD=1 python3 tools/test_chacha20_poly1305.py --seed 7539 --verbose`.
- **Bench gate**: `chacha20_block` < 135 000 cy; append row.

### Step 2 — Inline all eight QRs of `chacha20_quarter_round` (C2)
- **What**: replace the `cc20_qr_idx`-driven JSR loop with eight inlined
  QR bodies per double-round, each with inlined add/xor/rot32 bodies
  (no JSR). Rot-8/16 still go through the existing byte-copy primitive
  (no C3 yet).
- **Files**: `src/lib/chacha20_lib.asm`, optionally `src/lib/word32_lib.asm`
  if helpers become dead code.
- **Δ est.**: −30 000 cy per block.
- **Test gate**: 214/214.
- **Bench gate**: `chacha20_block` < 100 000 cy; append row.

### Step 3 — Rot-8/16 as offset rename; rot-4 inlined one-pass (C3 + C4)
- **What**: implement the mjosaarinen-style offset-rename trick for
  rot-8 and rot-16 within the inlined QR (zero runtime cost). Inline
  `rotl32_4` as one unrolled nibble shift, `rotl32_7` as rot-8 (free)
  plus `ror` chain, `rotl32_12` as rot-8 (free) plus rot-4.
- **Files**: `src/lib/chacha20_lib.asm`.
- **Δ est.**: −12 000 cy per block.
- **Test gate**: 214/214.
- **Bench gate**: `chacha20_block` < 90 000 cy; append row.

### Step 4 — Unroll `poly1305_multiply` schoolbook (P1 + CT cleanup)
- **What**: replace `mul_outer`/`mul_inner` loops with 17 × 16 straight-line
  multiply-accumulate. Eliminate `poly_i`/`poly_j` ZP state, `pha`/`pla`,
  and the `beq @skip_h_zero` / `beq @skip_r_zero` early-exits
  (constant-time contract). Keep quarter-square `mul_8x8` for now.
- **Files**: `src/lib/poly1305_lib.asm`.
- **Δ est.**: −12 000 cy per `poly1305_block`.
- **Test gate**: 214/214 (Poly1305 RFC 7539 §2.5.2 vector is in the suite).
- **Bench gate**: `poly1305_block` < 42 000 cy; append row.

### Step 5 — Profile dispatch scaffold (Profile A / Profile B build targets)
- **What**: add `POLY1305_PROFILE_LONG` flag in `constants_lib.asm`
  (default ON = Profile A). Add `make profile-a` / `make profile-b`
  dispatch in the Makefile, both producing the same PRG name at
  different output paths. Run the test suite against *both* profiles
  once to seed the CI matrix. No runtime code changes yet.
- **Files**: `Makefile`, `src/lib/constants_lib.asm`.
- **Δ est.**: 0 cy (scaffolding only).
- **Test gate**: 214/214 in **both** profiles.
- **Bench gate**: no numeric change expected; row recorded as "no-op"
  with both profile commit hashes noted.

### Step 6 — Shoup per-r table (P3, Profile A only)
- **What**: add 16 × 2 × 256-byte tables at a page-aligned RAM address.
  Build in `poly1305_init` after clamping. Rewrite the unrolled inner
  multiply to `lda rj_lo_tab,x / adc ... / lda rj_hi_tab,x / adc ...`.
  Gated `!ifdef POLY1305_PROFILE_LONG`.
- **Files**: `src/lib/poly1305_lib.asm`, `src/lib/data_lib.asm`,
  `src/lib/constants_lib.asm`.
- **Δ est.**: −25 000 cy per `poly1305_block` (Profile A);
  +50 000 cy per `poly1305_init` (amortizes ≥ 2 blocks).
- **Test gate**: 214/214 in **both** profiles; Profile B must still
  build and pass without the tables.
- **Bench gate**: Profile A `poly1305_block` < 18 000 cy; append row.

### Step 7 — Donna-style fused wrap reduction (P4)
- **What**: rewrite `poly1305_multiply` so for `j > i`, partial products
  land at position `i+j-17` with the `*5` factor pre-applied. Delete
  `poly1305_reduce`'s 2-pass `ror` and `*5` loops.
- **Files**: `src/lib/poly1305_lib.asm`.
- **Δ est.**: −8 000 cy per block.
- **Test gate**: 214/214 in both profiles; add 10 k random cross-check
  vectors before commit (this step has the highest defect risk).
- **Bench gate**: Profile A `poly1305_block` < 12 000 cy; append row.

### Step 8 — AEAD glue cleanups (A3–A6 + C6 + C7)
- **What**: lengths-block unroll, fold OTK derivation into encrypt,
  skip redundant `aead_setup_chacha` on decrypt, counter-fold, and
  keystream XOR-inline-with-copy.
- **Files**: `src/lib/chacha20poly1305_lib.asm`, `src/lib/chacha20_lib.asm`.
- **Δ est.**: −3 000 cy per packet + −700 cy per chacha20_block (C7)
  + −30 cy per block (C6).
- **Test gate**: 214/214 in both profiles.
- **Bench gate**: `aead_encrypt n=0` < 248 000 cy; append row.

### Step 9 — Profile documentation + tag
- **What**: update README with Profile A / B build instructions, finalize
  this document with post-sprint measurements, run the full test suite
  against both profiles, cut a `v0.2-optimized` tag.
- **Test gate**: 214/214 × 2 profiles.
- **Bench gate**: final table in this document showing baseline vs
  per-step vs final deltas.

### Optional Step 10 — REU quarter-square / REU Shoup-table preload (A only)
- Only if Profile A's `poly1305_init` cost (~50 k cy) is a complaint.
- Swap the runtime Shoup build or sqtab build for an REU DMA prefetch.
- Gate under `POLY1305_REU=1` inside Profile A.

---

## Section 7 — Risks, open questions, validation experiments

### Measured vs estimated

- **Measured**: every number in Section 1.
- **Estimated (gut-check only)**: every `Δ` in Sections 2, 3, 4, 6. These
  are anchors, not commitments. Each step's bench gate must re-measure.
  The confidence ordering roughly is:
  - C1 / C2 (inline + ZP): high confidence, scales from the polyval
    Tier-1 result (28% on one block-step).
  - C3 (rot-rename): medium confidence — untested on 6502, only validated
    on AVR. Prototype before committing.
  - P1 (unroll mul): high confidence, structurally identical to C2.
  - P3 (Shoup table): high confidence on the asymptote, medium on the
    50 k cy precompute estimate (could be as high as 80 k).
  - P4 (donna wrap): low confidence — the structural rewrite is tricky
    and we have no 8-bit reference implementation we can diff against.

### Prototype experiments (do **before** committing to the step)

- **E1** — Isolate a single chacha20 QR. Write two versions: (a) current
  path, (b) fully inlined with rot-8/16 as offset rename. Time both with
  the existing 16-bit Timer A wrapper (QR is small enough). Target:
  confirm ≥ 60% savings on a single QR before rolling C2+C3 into the
  whole block.
- **E2** — Shoup precompute cost. Write a stub that does only the
  table-build loop for a fixed `r` and time it with the 32-bit wrapper.
  Target: confirm ≤ 80 k cy.
- **E3** — rot-rename correctness. Write a Python oracle that tracks
  "logical byte 0" through a QR with rot-rename applied, and check that
  the emitted 6502 operand sequence produces identical output to the
  current implementation. This is a paper exercise but catches the
  offset-accounting bugs before they hit the assembler.
- **E4** — Donna fused-wrap oracle. Implement P4 in Python against the
  same `poly1305_reference` already in `tools/test_chacha20_poly1305.py`;
  only port to assembly after the Python prototype matches pyca bit-for-bit
  over 10 k random inputs.

### Constant-time concerns

- **Poly1305 requires data-independent multiply**. Current
  `poly1305_multiply` has a `beq @skip_h_zero` (inner) and
  `beq @skip_r_zero` — **both are data-dependent branches**. This is
  likely a pre-existing CT issue inherited from the wireguard baseline.
  On 6502 the leakage channel is tenuous (no cache, deterministic
  instruction timing) and WireGuard's threat model excludes local
  attackers, so it's probably acceptable, but **call it out**: the
  full-unroll step P1 should also remove these branches (they'll just
  become straight-line zero-multiplies that always run). Net win for
  CT *and* worst-case speed.
- **Tag compare (`aead_verify_tag`)** is correctly CT today (OR-accumulator).
  Do not regress.
- **ChaCha20 has no data-dependent branches** today. Keep it that way
  when inlining.

### RAM budget (C64 without REU)

- Library PRG code today: `$0810..$12bb` ≈ 2.7 KB.
- Tables today: `sqtab` at `$8000..$83ff` (1 KB).
- Post-sprint (Profile A): add ~2 KB chacha unrolled + ~1.5 KB poly
  unrolled = ~4 KB code. Shoup table 8 KB at a page-aligned slot such
  as `$4000..$5fff`.
- Total RAM footprint under Profile A: ~14 KB. Fits comfortably in a
  stock C64 (~38 KB usable after KERNAL/BASIC) with enough room for
  user message buffers and AAD.

### Open questions

1. **Is Profile B worth maintaining?** Depends entirely on whether we
   imagine a downstream user with < 16 KB free RAM. The project memory
   doesn't mention one. Default: build Profile A only; leave the
   `!ifdef` flags so B can be turned on later.
2. **REU assumption**: the project memory cites REU-DMA as a c64-x25519
   /c64-nist-curves optimization. The ChaCha20-Poly1305 project has
   not declared REU a requirement. If we add a Profile A+REU variant
   it's ~5 k cy instead of ~50 k cy `poly1305_init` cost. Probably
   **not worth the build-config complexity** until we have a user
   asking for it.
3. **sqtab one-time build**: currently rebuilt per `poly1305_init`
   (i.e. per packet). The table is a pure function of the platform.
   Moving it to a one-time `lib_entry` call saves ~80 k cy per packet.
   Low-risk. Do it in Step 8 (grouped with AEAD glue cleanups) or as
   a standalone Step 8b.
4. **CIA-timer spread of 5–7 k cy** at n ≥ 64 on the benchmark is
   noticeable (0.1–0.2%). Not caused by VICE warp (we use `min`
   which pins to the fastest run). Likely BASIC/KERNAL IRQ-related
   jitter during inter-sample harness calls. Acceptable for
   optimization tracking; not for absolute publication.

---

## Section 8 — Appendix: resources

### URLs (primary sources cited above)

- **NaCl on 8-bit AVR** — Hutter & Schwabe, 2013 (via cryptojedi mirror).
  `https://cryptojedi.org/papers/avrnacl-20130220.pdf`
  Salsa20 @ 284 cy/B (18 166 cy/block); Poly1305 @ 211 cy/B; 17×17-byte
  multiply = 1 967 cy on AVR; reduction trick `x1 + (x1 >> 2) + x0`
  exploiting `2^130 ≡ 5`; recommends radix-2^8 limb representation for
  all 8-bit primitives.
- **mjosaarinen/chacha-avr** — Saarinen, 2018, handwritten AVR assembly.
  `https://github.com/mjosaarinen/chacha-avr`
  README: ChaCha8 block ≈ 5 052 ticks on ATmega2560; 324-byte handwritten
  permutation; the whole primitive fits in < 512 B. `chacha_core_avr.S`
  header: rot-16 = register-pair reorder, rot-8 = register byte
  permutation, rot-12 = 4-iter LSL/ROL/ADC loop, rot-7 = LSR/ROR chain +
  permutation. **The rot-as-rename trick is the structural idea we
  port to 6502 via ZP-offset addressing.**
- **Loup Vaillant — Poly1305 design notes**.
  `https://loup-vaillant.fr/tutorials/poly1305-design`
  Confirms 26-bit limbs are optimal for 32-/64-bit CPUs (products fit
  in 64 bits). On 8-bit CPUs 26-bit limbs don't help — no wide register
  to absorb them. Stick with radix-2^8. Also documents the `(v << 2)
  + v = v * 5` trick exploited by every Poly1305 implementation.
- **floodyberry/poly1305-donna-8.h** — canonical 8-bit C reference.
  `https://github.com/floodyberry/poly1305-donna`
  17 × 8-bit limbs, schoolbook 17×17 with the `j > i` half folding the
  `*5` wrap into the multiply. Model for P4.
- **Bernstein — Poly1305-AES-MAC** — original spec.
  `https://cr.yp.to/mac/poly1305-20050329.pdf`
  Not load-bearing for optimization; referenced as the authoritative
  algorithm definition.
- **(negative result) 6502 Poly1305 search** — no prior art found via
  web search for `"poly1305" "6502" OR "C64" OR "commodore"`. Our
  baseline is state-of-the-art on the platform.

### Exemplar source paths (actually read during planning)

- `/home/someone/c64-polyval/c64-ChaCha20-Poly1305/src/lib/chacha20_lib.asm`
  — current `chacha20_quarter_round` + `chacha20_block` (lines 128–274).
- `/home/someone/c64-polyval/c64-ChaCha20-Poly1305/src/lib/word32_lib.asm`
  — current rot primitives (lines 120–473). Every rot goes through
  `(w32_dst),y`; rot-4 is ~120 cy, rot-8 is ~65 cy — both are
  worse than their inlined ZP-direct counterparts by 2–3×.
- `/home/someone/c64-polyval/c64-ChaCha20-Poly1305/src/lib/poly1305_lib.asm`
  — current 17×16 schoolbook multiply (lines 241–312) and reduce
  (lines 331–432).
- `/home/someone/c64-polyval/c64-ChaCha20-Poly1305/src/lib/chacha20poly1305_lib.asm`
  — AEAD glue, `aead_compute_tag`, `aead_verify_tag` (OR-accumulator CT).
- `/home/someone/c64-polyval/src/lib/polyval_long.asm` lines 22–104
  (inlined 16-byte sweep macros), 109–135 (inline shift-left-4 with
  reduction), 237–314 (sliced page-aligned table accessors).
- `/home/someone/c64-x25519/src/fe25519.asm` lines 307–368 (SMC
  schoolbook with REU DMA row fetch; the `sta @accum_ld1+1` pattern
  is the template for P3's SMC accumulation).
- `/home/someone/c64-wireguard/src/poly1305.asm:178` — quarter-square
  `mul_8x8` baseline (same code we already have; for context).

### Relevant memory entries

- `/home/someone/c64-polyval/memory/project_benchmarks.md` — 6.6×
  sprint history on polyval; asymptotic floor ~3915 cy/block measured
  vs ~3564 cy theoretical. Shows the magnitude of wins achievable via
  the structural optimizations (inline, slice, fuse, SMC).
- `/home/someone/c64-polyval/memory/feedback_delegate_shell.md` — user
  supervises; commits and shell ops via agents.
- `/home/someone/c64-polyval/memory/project_target_apps.md` — target
  apps = AES-GCM-SIV, WireGuard, TLS 1.3; long messages common. Drives
  the "default to Profile A" recommendation.
