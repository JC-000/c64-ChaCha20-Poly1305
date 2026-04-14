# Integration guide (draft)

> **Drafted by**: task #13 integrator, 2026-04-12.
> **To be compiled into**: `docs/INTEGRATION.md` by task #15.
> **Cross-links to fill in**: `docs/MEMORY_MAP.md` (task #11),
> `docs/API.md` (task #11), `docs/CT_ANALYSIS.md` (task #11),
> `CHANGELOG.md` (task #14).

## Overview

`c64-ChaCha20-Poly1305` is a ca65-assembled 6502 library providing
authenticated encryption per RFC 8439 (née 7539). It is consumed in
"library mode": downstream projects link its per-module `.o` files
into their own PRG at their own load address and call the library's
public symbols (`aead_encrypt`, `aead_decrypt`, `poly1305_lib_init`)
directly via `jsr`.

The library does **not** ship a standalone runtime — there is no
`chacha20poly1305.lib` archive, no dynamic loader, no entry vector
in low memory. A consumer's build pulls the `src/lib/*.s` sources
into its own ca65 invocation and links them alongside its own main
module.

This document describes how to wire the library into a consumer
project. The canonical worked example is
[`examples/smoke_test/`](../examples/smoke_test), which builds and
passes the RFC 7539 §2.8.2 AEAD known-answer vector on both profiles
from an entirely consumer-owned build tree (consumer `Makefile`,
consumer `smoke_test.cfg`, consumer `smoke_test.s`).

## Primary import mechanism: release-tarball vendoring

This is the recommended path. Downstream builds stay hermetic — no
submodule footguns, no network access at build time, one commit per
upstream bump.

1. Download the release tarball from the GitHub releases page:

   ```
   wget https://github.com/JC-000/c64-ChaCha20-Poly1305/releases/download/v0.3.0/c64-chacha20poly1305-v0.3.0.tar.gz
   ```

2. Unpack under `third_party/` in your consumer repo:

   ```
   mkdir -p third_party
   tar xzf c64-chacha20poly1305-v0.3.0.tar.gz -C third_party/
   # Result: third_party/c64-chacha20poly1305-v0.3.0/src/{lib,include,c64.cfg}
   ```

3. Point your consumer's ca65 invocation at the vendored `src/lib`
   and `src/include` directories via `-I` flags:

   ```
   CA65FLAGS = -t c64 -g \
       -I third_party/c64-chacha20poly1305-v0.3.0/src/lib \
       -I third_party/c64-chacha20poly1305-v0.3.0/src/include
   ```

4. Add the library modules to your object list, alongside your own
   main module. `constants_lib.s` is equate-only (no `.o`) and gets
   `.include`d by the modules that need it, so it does not appear on
   the link line:

   ```
   LIB_MODULES = word32_lib chacha20_lib poly1305_lib \
                 chacha20poly1305_lib data_lib
   ```

5. Link against your own linker config (**not** the library's
   `src/c64.cfg`). A consumer `smoke_test.cfg` that mirrors the
   library's memory map byte-for-byte is safe; anything that
   relocates the library's tables (`$6000` Shoup, `$8000` sqtab)
   will require source-level patches to `poly1305_lib.s` until
   v0.4.0 makes those addresses configurable via `-D` defines.

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
git checkout v0.3.0
cd ../..
git add third_party/c64-chacha20poly1305 .gitmodules
git commit -m "vendor c64-chacha20poly1305 v0.3.0 as submodule"
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

### Main memory (both profiles)

| Range | Size | Owner |
|-------|------|-------|
| `$8000..$81FF` | 512 B | `sqtab_lo` — quarter-square low bytes |
| `$8200..$83FF` | 512 B | `sqtab_hi` — quarter-square high bytes |

> Profile B no longer allocates the `$8400..$87FF` `sqtab2` companion
> tables — those were removed together with the `mult66` primitive
> in the v0.3.0 CT fix. Profile B now uses the `ct_mul_8x8` branchless
> quarter-square primitive (see `docs/design/ct_mul_8x8.md`) that
> reuses the same 1 KB `sqtab_lo`/`sqtab_hi` as Profile A via
> SMC-patched `abs,x` loads. Net runtime RAM: 1 KB for Profile B.

### Library code + data (both profiles)

The library's `CODE`, `DATA`, and `BSS` segments live in the `MAIN`
memory region `$0900..$9FFF` per the default `src/c64.cfg`. A
consumer linker config can move this — the `CODE` segment is
position-independent so long as it is assembled into a contiguous
region — but the sqtab / Shoup table addresses listed above are
hard-coded in `poly1305_lib.s` and will NOT move with the segment.

See `docs/MEMORY_MAP.md` (task #11) for the authoritative byte-level
map, including I/O register usage (`$DF01..$DF0A` REU DMA registers,
Profile A `POLY1305_REU=1` only).

## Required initialization

Exactly one call at consumer startup:

```asm
jsr poly1305_lib_init   ; builds sqtab (both profiles),
                        ; sqtab2 (Profile B), and stashes
                        ; sqtab to REU (Profile A + POLY1305_REU=1)
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

Skipping `poly1305_lib_init` is technically safe — `poly1305_init`
auto-builds `sqtab` on first use via the `sqtab_ready` flag — but
shifts ~87 k cy of table-build cost onto the first packet. Always
call it once at boot.

## API reference

See `docs/API.md` (task #11) for the full public symbol list,
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
calling conventions will not change between v0.3.0, v0.3.1, … The
memory-map collision list in this document will not change within
the v0.3.x series.

**v0.4.0 is planned as a breaking release.** Known breaking changes:

- `r_tab_lo/hi`, `sqtab_lo/hi` addresses become configurable via
  `-D` defines, allowing consumers to relocate the library's tables
  out of their own address space without patching the library
  source.
- Memory-map documentation will move from "fixed addresses" to
  "defaults that can be overridden".

Consumers following this integration guide on v0.3.x should be able
to upgrade to v0.4.0 by (a) adding their preferred table-base
`-D` defines to their ca65 flags, or (b) accepting the v0.3.x
defaults unchanged.

## Profile choice: A vs B

The library ships two profile builds. Pick one at assemble time by
defining `POLY1305_PROFILE_LONG`:

```
# Profile A — long-message optimized, Shoup per-r tables,
# REU-capable. Best for WireGuard data packets (~1280 B),
# TLS 1.3 bulk records.
ca65 -DPOLY1305_PROFILE_LONG=1 ...

# Profile B — short-message optimized, portable, lower init cost.
# Best for WireGuard handshakes, TLS 1.3 alerts, and plain C64
# (no REU required).
ca65 ...   # (flag undefined)
```

Profile A precomputes 8 KB of Shoup per-r tables at each
`poly1305_init` call (~118 k cy init cost via S11 incremental
ripple), reducing `poly1305_block` from 37 844 to 11 948 cy.
Amortizes at `n >= 256` bytes. With `-DPOLY1305_REU=1` (Profile A
only), the 1 KB sqtab is DMA-stashed to REU bank 0 at
`poly1305_lib_init` and can be restored in ~1.1 k cy via
`poly1305_reu_restore` if external code clobbers `$8000-$83FF`.

Profile B uses the `ct_mul_8x8` CT-clean quarter-square primitive
and has a per-packet floor of 84 560 cy at n=0, versus Profile A's
186 182 cy n=0 floor. Profile B never touches the REU and only
claims 1 KB of fixed-address RAM at runtime.

Target workloads:

- **WireGuard**: data path uses Profile A (long packets), handshake
  path uses Profile B (short packets). A bimodal consumer can pick
  profile per call site by linking two separate library builds,
  but this isn't a supported pattern yet — v0.3.x ships one profile
  per PRG.
- **TLS 1.3**: same bimodal split.
- **Single-profile consumers**: pick Profile B if you need stock-C64
  compatibility, Profile A if you have an REU and your average
  packet is over ~256 bytes.

Both profiles share identical ChaCha20 code and pass the full
upstream 214-test suite against the same RFC 8439 test vectors.

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
