# Integration guide

## Overview

`c64-ChaCha20-Poly1305` is a ca65-assembled 6502 library providing
authenticated encryption per RFC 8439 (née 7539). It is consumed in
"library mode": downstream projects link its per-module `.o` files
into their own PRG at their own load address and call the library's
public symbols (`aead_encrypt`, `aead_decrypt`, `poly1305_lib_init`)
directly via `jsr`.

The library still does not ship a dynamic loader or an entry vector
in low memory, but since v0.6.0 it **does** ship prebuilt static
archives: `make lib` and `make lib-aead-only` produce ar65 `.a`
archives (c64-lib-contract SPEC §6) that a consumer's `ld65` link
line consumes directly. That is now the primary consumption path.
Pulling the `src/lib/*.s` sources into your own ca65 invocation
(tarball or submodule vendoring, below) remains fully supported.

This document describes how to wire the library into a consumer
project. The canonical worked example is
[`examples/smoke_test/`](../examples/smoke_test), which builds and
passes the RFC 7539 §2.8.2 AEAD known-answer vector on both profiles
from an entirely consumer-owned build tree (consumer `Makefile`,
consumer `smoke_test.cfg`, consumer `smoke_test.s`).

## Primary import mechanism: prebuilt archive (v0.6.0+)

In the library repo (or your vendored copy of it):

```
make lib              # build/lib/c64-chacha20-poly1305.a
make lib-aead-only    # build/lib/c64-chacha20-poly1305-aead-only.a
```

Both are ar65 archives per c64-lib-contract SPEC §6, assembled as
Profile B (`POLY1305_PROFILE_LONG` undefined; the aead-only variant
additionally passes `-DLIB_VARIANT_AEAD_ONLY=1`). Profile A
consumers keep using source vendoring below. `ld65` pulls only the
archive modules that are actually referenced, so unreferenced
modules cost the consumer PRG nothing.

A consumer supplies two objects of its own: its program, and a
`zp_config.o` assembled from the library's `src/zp_config.s` (or
from its own edited copy — the ZP slot table deliberately lives
outside the archive so consumers can rebind slots without touching
the library objects). Then link against your own linker config:

```
ca65 -t c64 -g -I <lib>/src/include -I <lib>/src/lib \
    my_consumer.s -o build/my_consumer.o
ca65 -t c64 -g -I <lib>/src/include -I <lib>/src/lib \
    <lib>/src/zp_config.s -o build/zp_config.o
ld65 -C my_consumer.cfg -m build/my_consumer.map \
    build/my_consumer.o build/zp_config.o \
    <lib>/build/lib/c64-chacha20-poly1305.a -o my_consumer.prg
```

The worked, buildable example is [`test_consumer/`](../test_consumer)
in the repo root: `min_aead_consumer.s` and `aead_smoke.s` linked
against both archives through a consumer-owned `min_consumer.cfg`,
with `.map` files emitted for the size-delta measurement.

## Secondary import mechanism: release-tarball vendoring

This remains fully supported, and is the path to take if you build
Profile A or want the sources in-tree. Downstream builds stay
hermetic — no submodule footguns, no network access at build time,
one commit per upstream bump.

1. Download the release tarball from the GitHub releases page:

   ```
   wget https://github.com/JC-000/c64-ChaCha20-Poly1305/releases/download/v0.7.0/c64-ChaCha20-Poly1305-v0.7.0.tar.gz
   ```

2. Unpack under `third_party/` in your consumer repo:

   ```
   mkdir -p third_party
   tar xzf c64-ChaCha20-Poly1305-v0.7.0.tar.gz -C third_party/
   # Result: third_party/c64-ChaCha20-Poly1305-v0.7.0/src/{lib,include,c64.cfg}
   ```

3. Point your consumer's ca65 invocation at the vendored `src/lib`
   and `src/include` directories via `-I` flags:

   ```
   CA65FLAGS = -t c64 -g \
       -I third_party/c64-ChaCha20-Poly1305-v0.7.0/src/lib \
       -I third_party/c64-ChaCha20-Poly1305-v0.7.0/src/include
   ```

4. Add the library modules to your object list, alongside your own
   main module. `constants_lib.s` is equate-only (no `.o`) and gets
   `.include`d by the modules that need it, so it does not appear on
   the link line:

   ```
   LIB_MODULES = word32_lib chacha20_lib poly1305_lib \
                 chacha20poly1305_lib data_lib \
                 lib_version lib_manifest
   ```

   `lib_version.s` lives at `src/lib_version.s` (not under
   `src/lib/`); `lib_manifest.s` carries the c64-lib-contract
   manifest exports. Both are linked into every profile and are
   present in the prebuilt archives. `src/zp_config.s` assembles to
   its own `zp_config.o`, which must also be on the link line — the
   library modules import their ZP slots from it.

5. Link against your own linker config (**not** the library's
   `src/c64.cfg`). Your `SEGMENTS {}` block MUST declare
   `LIB_CHACHA20_POLY1305_CODE` (with `align = $100`) and
   `LIB_CHACHA20_POLY1305_DATA` (`type = rw`) — ld65 hard-errors on any
   input segment with no memory-area assignment. See "Library code +
   data" below for the exact lines and why both attributes matter.
   A consumer cfg that otherwise mirrors the library's memory map
   byte-for-byte is safe. Relocation is now
   partly configurable at assemble time: the 1 KB quarter-square
   table moves with `-DLIB_SHARED_SQTAB_BASE=$<addr>` (default
   `$8000`; PR #39), and the ZP slots move by editing — or shipping
   your own copy of — `src/zp_config.s`, whose `.exportzp` header
   owns every slot (PR #32). The Profile A Shoup tables
   `r_tab_lo`/`r_tab_hi` (`$6000`/`$7000`) are still fixed-address
   and still require source-level patches to `poly1305_lib.s`.

6. Call `poly1305_lib_init` exactly once at your consumer's startup
   before the first `aead_encrypt` / `aead_decrypt`. See
   [Required initialization](#required-initialization) below.

**Concrete example**: [`examples/smoke_test/`](../examples/smoke_test)
is a complete working consumer at ~200 lines of assembly plus a
~100-line `Makefile`. `examples/smoke_test/third_party/c64-chacha20poly1305-v0.3.0/`
is a direct `cp`-level simulation of the unpacked release tarball.

## Secondary import mechanism: git submodule

Supported but less hermetic. Prefer this only if you want the
upstream tag to be pinned by commit SHA inside your consumer's
`.gitmodules`, at the cost of requiring `git clone --recursive`
(or a later `git submodule update --init`) for every fresh checkout
of your consumer repo.

```
git submodule add https://github.com/JC-000/c64-ChaCha20-Poly1305.git \
    third_party/c64-chacha20poly1305
cd third_party/c64-chacha20poly1305
git checkout v0.7.0
cd ../..
git add third_party/c64-chacha20poly1305 .gitmodules
git commit -m "vendor c64-chacha20poly1305 v0.7.0 as submodule"
```

After that step, the `-I` flags, module list, and linker-config
wiring are identical to the tarball path above (just substitute the
directory name).

**Trade-offs**:

- **Pro**: single commit in your consumer tracks exactly which
  upstream commit is in use; `git submodule update --remote` fetches
  upstream bumps.
- **Con**: `git clone` of your consumer repo without `--recursive`
  produces a broken tree; CI/CD must remember `submodule update
  --init --recursive`. Tarball vendoring sidesteps this entirely.

## Memory map collision list

A consumer MUST NOT use any of the following addresses without
first relocating them in the library source (only safe at v0.4.0+):

### Zero page (always)

| ZP slot | Owner | Notes |
|---------|-------|-------|
| `$02..$03` | `zp_tmp1`, `zp_tmp2` | word32/poly1305 scratch |
| `$04..$09` | `w32_src1/src2/dst` | word32 operand pointers |
| `$14..$19` | ChaCha20 state | round/qr idx, data ptr, remain, buf pos |
| `$1a..$1d` | Poly1305 state | i, j, carry, tmp |
| `$40..$7f` | `cc20_work` / `cc20_keystream` | 64-byte ChaCha20 working state |
| `$fb..$fe` | `zp_ptr1`, `zp_ptr2` | general-purpose 16-bit pointers |

### Zero page (Profile B only: `POLY1305_PROFILE_LONG` undefined)

| ZP slot | Owner | Notes |
|---------|-------|-------|
| `$1e` | `ct_diff_raw` | `ct_mul_8x8` sign-mask absolute-value scratch (v0.3.0 CT fix) |
| `$1f` | `ct_sign_mask` | `ct_mul_8x8` sign-mask absolute-value scratch (v0.3.0 CT fix) |

### Main memory (Profile A only: `POLY1305_PROFILE_LONG=1`)

| Range | Size | Owner |
|-------|------|-------|
| `$6000..$6FFF` | 4 KB | `r_tab_lo` — Shoup per-r table low bytes |
| `$7000..$7FFF` | 4 KB | `r_tab_hi` — Shoup per-r table high bytes |

### Main memory (Profile B only)

| Range | Size | Owner |
|-------|------|-------|
| `$8000..$81FF` | 512 B | `sqtab_lo` — quarter-square low bytes |
| `$8200..$83FF` | 512 B | `sqtab_hi` — quarter-square high bytes |

> **Profile A no longer claims `$8000..$83FF`** (issue #34 F1,
> PR #38): `shoup_init` builds `r_tab_lo/hi` by incremental
> ripple-add and does not consume sqtab, so the table, its init, and
> the former `POLY1305_REU` stash/restore path are gated out of
> Profile A. The window is consumer-reclaimable on Profile A builds.

> Profile B no longer allocates the `$8400..$87FF` `sqtab2` companion
> tables — those were removed together with the `mult66` primitive
> in the v0.3.0 CT fix. Profile B now uses the `ct_mul_8x8` branchless
> quarter-square primitive (see `docs/design/ct_mul_8x8.md`) that
> reuses the same 1 KB `sqtab_lo`/`sqtab_hi` as Profile A via
> SMC-patched `abs,x` loads. Net runtime RAM: 1 KB for Profile B.

### Library code + data (both profiles)

As of the issue #48 migration the library emits **c64-lib-contract SPEC §4
prefixed segments** — it no longer places anything in the bare `CODE` /
`DATA` segments, so your own code keeps those names and you never have to
`sed` the library sources:

| Segment | Contents | Required cfg attributes |
|---|---|---|
| `LIB_CHACHA20_POLY1305_CODE` | All library code, plus the page-aligned `chacha_nibswap_*_tab` and `poly_reduce_shl6_tab` LUTs | `type = ro`, **`align = $100`** |
| `LIB_CHACHA20_POLY1305_DATA` | `cc20_*` / `poly_*` / `aead_*` state and `sqtab_ready` | **`type = rw`** in a file-emitting area — never `bss` |

Drop these two lines into your cfg's `SEGMENTS {}` block:

```
    LIB_CHACHA20_POLY1305_CODE: load = MAIN, type = ro, align = $100;
    LIB_CHACHA20_POLY1305_DATA: load = MAIN, type = rw;
```

Both attributes are load-bearing, and both fail quietly if you drop them:

- **`align = $100` is a constant-time invariant, not a perf hint.**
  `data_lib.s`'s two nibswap LUTs and `poly1305_lib.s`'s
  `poly_reduce_shl6_tab` are `.align 256` and are indexed by
  secret-derived X/Y. Without page alignment an `abs,x` page cross costs
  +1 cycle on a secret-dependent condition — a CT violation. ld65 only
  emits a *warning* ("Segment ... isn't aligned properly") and links the
  tables misaligned anyway, so nothing will fail loudly.
- **`LIB_CHACHA20_POLY1305_DATA` must PRG-load as zero.** Declaring it
  `type = bss` writes no file bytes, so `poly1305_init`'s `sqtab_ready`
  gate reads power-on garbage, skips `sqtab_init`, and poisons every
  Poly1305 multiplication. There is no link error for this — see
  `src/lib/data_lib.s:12-25`.

Also declare bss-type segments **last** in the file-backed memory area:
ld65 writes no file bytes for bss, so a file-emitting segment declared
after a non-empty `BSS` loads `__BSS_SIZE__` bytes below its linked
address, corrupting silently with no link error.

Both segments live in the `MAIN` memory region `$0900..$9FFF` under the
default `src/c64.cfg`. A consumer linker config can move them — the code
is position-independent so long as it is linked into a contiguous region
— but the sqtab / Shoup table addresses listed above are hard-coded in
`poly1305_lib.s` and will NOT move with the segment.

`src/c64.cfg` and `test_consumer/min_consumer.cfg` are both worked
examples. Note that `examples/smoke_test/` links a **vendored v0.3.0**
snapshot of the library, which predates the rename, so its cfg still uses
bare `CODE`/`DATA` — do not copy that one for a current-version link.

See `docs/MEMORY_MAP.md` for the authoritative byte-level map. The
library touches **no I/O registers** — the former Profile A
`POLY1305_REU=1` DMA path (`$DF01..$DF0A`) was removed by the
issue #34 F1 slimming (PR #38), and no REU DMA is issued on any
code path in any profile.

## Required initialization

Exactly one call at consumer startup:

```asm
jsr poly1305_lib_init   ; builds sqtab (Profile B);
                        ; no-op on Profile A (kept for
                        ; cross-profile API compatibility)
```

After `poly1305_lib_init` returns, call `aead_encrypt` /
`aead_decrypt` per the interface in `chacha20poly1305_lib.s`. The
per-packet sequence is:

1. Write 32-byte key to `aead_key`.
2. Write 12-byte nonce to `aead_nonce`.
3. Write 16-bit AAD pointer to `aead_aad_ptr` and 1-byte AAD length
   to `aead_aad_len` (AAD length is 8-bit — 0..255 bytes).
4. Write 16-bit plaintext/ciphertext pointer to `aead_data_ptr` and
   16-bit length to `aead_data_len` (little-endian, up to ~1500).
5. For decrypt: write the 16-byte expected tag to `aead_tag`.
6. `jsr aead_encrypt` or `jsr aead_decrypt`.
7. After encrypt: tag is at `poly1305_tag` (16 bytes). Ciphertext
   was written in place at `aead_data_ptr`.
8. After decrypt: `A == 0` means tag valid and plaintext was written
   in place; `A != 0` means tag mismatch and the buffer is untouched.

Skipping `poly1305_lib_init` is technically safe — on Profile B,
`poly1305_init` auto-builds `sqtab` on first use via the
`sqtab_ready` flag — but shifts ~87 k cy of table-build cost onto
the first packet. Always call it once at boot. (On Profile A the
call is a no-op either way; Shoup tables are rebuilt per key by
`poly1305_init`.)

## API reference

See `docs/API.md` for the full public symbol list,
calling conventions, clobbered registers, and per-routine cycle
counts. The `examples/smoke_test/smoke_test.s` program exercises the
subset that actually matters for a consumer (init + encrypt +
decrypt); the other exports (`chacha20_init`, `chacha20_block`,
`chacha20_encrypt`, `poly1305_init/update/final/block`) are
primarily for test harnesses and low-level users.

## Constant-time / side-channel notes

All library code is constant-time with respect to secret data as of
v0.3.0. See [`docs/CT_ANALYSIS.md`](CT_ANALYSIS.md) for the full
per-branch analysis and [`docs/AUDIT.md`](AUDIT.md) for the
top-level GREEN verdict — short version: no branches on secret
bytes, no secret-dependent addressing-mode timing (`abs,x` / `abs,y`
on page-aligned bases only; no `(zp),y` on secret indices in the
hot path), and the tag comparison uses an OR-accumulator pattern.

Three pre-existing CT findings (F1 `poly1305_final` h≥p branch,
F2 ChaCha20 `rotl32_1_zp`/`rotr32_1_zp` wrap branch, F3 Profile B
`mult66` `(zp),y` page-cross) were closed in the v0.3.0 CT fix.
The F3 fix replaces `mult66` with a new `ct_mul_8x8` branchless
quarter-square primitive; see [`docs/design/ct_mul_8x8.md`](design/ct_mul_8x8.md)
for the design memo.

## Stability promise

**v0.3.x is API-stable.** The public symbol names and their
calling conventions did not change between v0.3.0, v0.3.1, … The
memory-map collision list in this document did not change within
the v0.3.x series.

**v0.4.0 is API-stable on the default-equate paths.** Public
symbol names, calling conventions, and the default memory-map
collision list above are unchanged from v0.3.1. Consumers using
`POLY1305_REU=1` on Profile A may now optionally relocate the REU
stash destination via `POLY1305_REU_BANK` / `POLY1305_REU_OFFSET`
(see issue #19); leaving these undefined preserves v0.3.x
behaviour. The full ZP / table-base relocation work originally
planned for v0.4.0 is deferred to a later release; track that work
on the `feat/v0.4.0-relocatable` branch and its successors.

The v0.4.0 release also adds Ultimate 64 hardware backend support
to the validation tooling — that is a tooling-only change and does
not affect the library API or the linked PRG.

**v0.7.0 (2026-08-13) requires a consumer cfg change.** The library
no longer emits into the bare `CODE` / `DATA` segments — your
`SEGMENTS {}` block MUST declare `LIB_CHACHA20_POLY1305_CODE`
(with `align = $100`) and `LIB_CHACHA20_POLY1305_DATA` (`type = rw`).
ld65 hard-errors if they are missing, but both *attributes* fail
silently if dropped; see "Library code + data" above for the exact
lines and why each one matters. v0.7.0 also stops exporting the §8.x
bit constants `LIB_SHARED_PRIMITIVES_SQTAB` / `_CT_MUL_8X8` (copy the
equates locally instead), adds `LIB_<X>_`-prefixed §1 and §8.4 exports
with a `LIB_NO_BARE_EXPORTS` gate for multi-library links, and rebases
`LIB_CHACHA20_POLY1305_RESIDENT_BYTES` onto a consumer-independent
measurement — the values are now smaller, so re-check any
`.assert resident <= N`.

**v0.6.0 (2026-07-28) removes the `POLY1305_REU` API surface** (issue #34
F1, PR #38): `poly1305_reu_restore`, `poly1305_reu_sqtab_bank` /
`poly1305_reu_sqtab_offset`, and the `POLY1305_REU` /
`POLY1305_REU_BANK` / `POLY1305_REU_OFFSET` defines are gone, and
Profile A no longer emits `sqtab` / `sqtab_init` / `mul_8x8` (its
`$8000..$83FF` claim is dropped). This is a breaking change for
consumers of those symbols — see `docs/API.md` §3
"poly1305_reu_* (removed)" for the upgrade note. Consumers that
never defined `POLY1305_REU` are unaffected.

**v0.6.0 adds** (all additive; no existing symbol or convention
changes): the `LIB_VERSION_MAJOR` / `LIB_VERSION_MINOR` /
`LIB_VERSION_PATCH` exports (`src/lib_version.s`); the
`LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES` manifest export;
the `LIB_SHARED_PRIMITIVES_*` bits and the build-config-conditional
shared-primitives mask (`src/lib/lib_manifest.s`, c64-lib-contract
SPEC §8); and the `src/zp_config.s` ZP configuration module. The
variant flags (see "Variant flags" below) change code size and
cycle counts only — they do not change the AEAD ABI.

## Profile choice: A vs B

The library ships two profile builds. Pick one at assemble time by
defining `POLY1305_PROFILE_LONG`:

```
# Profile A — long-message optimized, Shoup per-r tables.
# Best for WireGuard data packets (~1280 B), TLS 1.3 bulk records.
ca65 -DPOLY1305_PROFILE_LONG=1 ...

# Profile B — short-message optimized, portable, lower init cost.
# Best for WireGuard handshakes, TLS 1.3 alerts.
ca65 ...   # (flag undefined)

# Neither profile requires (or uses) an REU.
```

Profile A precomputes 8 KB of Shoup per-r tables at each
`poly1305_init` call (~118 k cy init cost via S11 incremental
ripple), reducing `poly1305_block` from 37 950 to 11 951 cy.
Amortizes at `n ≈ 64` bytes — the measured A/B crossover per the
v0.5.0 packet-size sweep (`docs/BENCH_NSWEEP_v0.5.0.md`).

Profile B uses the `ct_mul_8x8` CT-clean quarter-square primitive
and has a per-packet floor of 80 749 cy at n=0, versus Profile A's
182 345 cy n=0 floor. Profile B claims only 1 KB of fixed-address
RAM at runtime. Neither profile touches the REU (see the
"Turbo hosts and REU-less machines" section of the README).

Target workloads:

- **WireGuard**: data path uses Profile A (long packets), handshake
  path uses Profile B (short packets). A bimodal consumer can pick
  profile per call site by linking two separate library builds,
  but this isn't a supported pattern yet — v0.3.x ships one profile
  per PRG.
- **TLS 1.3**: same bimodal split.
- **Single-profile consumers**: pick Profile B if you need stock-C64
  compatibility, Profile A if your average packet is over ~64 bytes.

Both profiles share identical ChaCha20 code and pass the full
upstream 214-test suite against the same RFC 8439 test vectors.

### Variant flags (v0.6.0+)

Orthogonal to the A/B choice, four default-off assemble-time defines
form a size/speed dial (issue #34):

- `LIB_VARIANT_AEAD_ONLY=1` — strips test-only exports down to the
  AEAD surface (this is what `make lib-aead-only` bakes into its
  archive); free in cycles.
- `POLY1305_MULTIPLY_ROLLED_OUTER=1` — rolls the outer j-loop of
  `poly1305_multiply`; +4.08% `aead_encrypt` cycles at n=1024 for
  ~8 KB less code.
- `POLY1305_MULTIPLY_ROLLED=1` — also rolls the inner
  partial-product loop; saves a further 576 B over rolled-outer but
  costs +17.4% at n=1024. Mutually exclusive with rolled-outer.
- `CHACHA20_USE_WORD32` — opt-in pointer-mode ChaCha20 for consumers
  that already ship a shared `word32.s`; the default build inlines
  the ZP-direct macro forms instead.

Combining the aead-only archive with rolled-outer (issue #34's
closing "config D" result) yields an **8 230 B** linked consumer
footprint for +4.08% cycles. None of these flags change the AEAD
calling convention or symbol names — see the stability promise
above.

## Verifying your wiring

Once you've wired the library into your consumer project, copy
`examples/smoke_test/smoke_test.s` into your build as a one-shot
smoke test. If it builds, boots, and writes `$01` to `$0400`, your
wiring is correct and you can move on to your real consumer code.

See `examples/smoke_test/run_smoke_test.py` for a minimal
VICE-based pass/fail harness that you can adapt into your CI.

### Testing from a consumer project

**Test harness convention**: `tools/test_chacha20_poly1305.py` expects
the caller to pre-build the target profile via `make profile-a` or
`make profile-b`. It does NOT auto-rebuild. This matches
`tools/benchmark_chacha20_poly1305.py` and
`examples/smoke_test/run_smoke_test.py`. The older `C64_SKIP_BUILD=1`
env var is retained as a no-op for backward compatibility with
pre-v0.3.x callers.

**Backend selection (v0.4.0+)**: all four `tools/*.py` scripts pick
their 6502 backend from `C64_BACKEND` (`vice` default, or `u64`).
For the Ultimate 64 backend, set `U64_HOST=<ip-or-hostname>`. The
backend choice is transparent to consumers — the same scripts run
the same validation on either backend, with cycle counts that match
to within ±0.2%. See the `tools/_u64_helpers.py` shim for the
backend-dispatch logic if you need to write your own U64-aware
validation tool.

**New CLI flags in v0.4.0**:

- `tools/audit_cross_check.py --vectors N` — number of random AEAD
  vectors per profile to cross-check against `pyca/cryptography`.
  Defaults to the v0.3.x value of 15 000. Use `--vectors 1000` for
  the standard U64 acceptance gate (~20 min walltime).
- `tools/benchmark_chacha20_poly1305.py --backend {vice|u64}` —
  select the bench backend explicitly. If omitted, follows
  `C64_BACKEND` (which itself defaults to `vice`).

**Granular bench + regression gate (v0.5.0+)**: `make bench` builds
the requested profile (`BENCH_PROFILE`, default B), runs
`tools/bench_granular.py`, and writes `docs/BENCH_REPORT.md` plus a
`.json` sidecar; `make bench-check` additionally diffs the run
against the committed baseline (`docs/BENCH_REPORT.baseline.json`)
and exits non-zero on >1% drift in any row — suitable as a consumer
CI gate against upstream bumps. `tools/bench_turbo_sweep.py` runs
the same wrapper across CPU turbo speeds on Ultimate 64 hardware to
verify wall-clock scaling (no ~1 MHz-anchored floor). See
[`docs/BENCH_GRANULAR.md`](BENCH_GRANULAR.md) for the methodology
and baseline-refresh procedure.
