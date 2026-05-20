# c64-ChaCha20-Poly1305

ChaCha20-Poly1305 AEAD (RFC 8439) for the Commodore 64 / 6502.
Library-mode assembly: sources live under `src/lib/*_lib.s` with no
absolute origin, exposing public symbols for host applications
(WireGuard, TLS 1.3, DTLS) or direct-jsr Python test harnesses.

## Build

Requires the [cc65](https://cc65.github.io/) toolchain (`ca65`
assembler + `ld65` linker). The `ca65hl` macro package and
`smc.inc` self-modifying-code helpers are vendored under
`src/include/`, so no extra installation is needed beyond cc65 itself.

```
make profile-a      # Profile A: Shoup per-r tables, optimized for long messages
make profile-b      # Profile B: stock C64, portable baseline, lower init cost
make                # alias for profile-a
```

Both produce `build/c64_chacha20_poly1305.prg` and `build/labels.txt`
(VICE-format label file for harness consumption, converted from the
ld65 label output by the Makefile).

## Build profiles

- **Profile A** precomputes 8 KB of Shoup per-r multiplication tables
  at `poly1305_init` time (~490 k cy setup cost), reducing
  `poly1305_block` from 38 760 to 12 119 cy. Best for messages longer
  than **~64 bytes**, where the table-build amortizes (measured A/B
  crossover, see `docs/BENCH_NSWEEP_v0.5.0.md`). Target workloads:
  WireGuard data packets (~1280 B), TLS 1.3 bulk records. With
  `POLY1305_REU=1`, backs up the quarter-square table to REU for
  fast restore if clobbered.

  The REU destination bank and offset are configurable two ways:

  1. **Assemble-time** (baseline, unchanged): `ca65 --asm-define
     POLY1305_REU_BANK=3 --asm-define POLY1305_REU_OFFSET=$1000`, or
     `.include` a project-wide layout header before `constants_lib.s`.
     With the defaults (`bank=0`, `offset=$0000`) the runtime behaviour
     is identical to prior releases.
  2. **Runtime** (new in [Unreleased]): the library exports two
     public RAM-backed cells — `poly1305_reu_sqtab_bank` (1 byte)
     and `poly1305_reu_sqtab_offset` (2 bytes LE) — that consumers
     may write to before calling `poly1305_lib_init`. Useful for
     hosts linking multiple REU consumers (e.g. this library
     alongside `c64-x25519`, which occupies REU banks 0-1) that need
     to coordinate layout without rebuilding. See `docs/API.md`
     §"REU layout configuration" for the protocol. See issue #19.

- **Profile B** uses the portable quarter-square multiply (1 KB table).
  Lower per-packet init cost (87 k vs 579 k cy at n=0), better for
  short packets such as WireGuard handshakes and TLS 1.3 alerts.
  Runs on any stock C64 without REU.

Both profiles share identical ChaCha20 code, pass the full 214-test
suite, and are constant-time by contract (no data-dependent branches on
secret data).

## Performance

v0.5.0 cycle counts (cycles, measured via CIA timer, identical on
VICE and Ultimate 64 hardware backends to within ±0.2%,
`tools/benchmark_chacha20_poly1305.py`, 3 samples, min per routine):

| routine              | S0 baseline |     Profile A |   change |     Profile B |   change |
|----------------------|------------:|--------------:|---------:|--------------:|---------:|
| `chacha20_block`     |     149 987 |        39 331 |  -73.8%  |        39 332 |  -73.8%  |
| `poly1305_block`     |      53 270 |        11 951 |  -77.6%  |        37 950 |  -28.8%  |
| `aead_encrypt` n=0   |     251 330 |       182 345 |  -27.4%  |        80 749 |  -67.9%  |
| `aead_encrypt` n=1024|   5 974 048 |     1 623 299 |  -72.8%  |     3 196 264 |  -46.5%  |

v0.5.0 lands **C4** (branchless rotl-4 via two page-aligned 256-byte
LUTs) on the ChaCha20 quarter-round, replacing the asl/lsr/ora chain
in `rotl32_4_zp` (~124 cy → ~80 cy, −44 cy/call × 8 inlined sites in
`chacha20_block`'s double-round body). Both profiles share identical
ChaCha20 code so the win is the same on both:

| routine               |   v0.4.0 |   v0.5.0 |   Δ vs v0.4.0 |
|-----------------------|---------:|---------:|--------------:|
| `chacha20_block`      |   43 135 |   39 331 |     **−8.8%** |
| `aead_encrypt` n=1024 A | 1 686 764 | 1 623 299 |     −3.8%   |
| `aead_encrypt` n=1024 B | 3 259 490 | 3 196 264 |     −1.9%   |

Profile A's n=0 cost (182 k cy) is the per-packet `poly1305_init`
incremental Shoup-table build (S11), down from ~579 k cy in
`v0.2-optimized`; the per-packet Shoup-table build amortizes
rapidly at **n ≥ 64** (measured A/B crossover; see
`docs/BENCH_NSWEEP_v0.5.0.md` for the full sweep). Profile B's n=0
runs in 81 k cy — **−67.9%** below the sprint-0 baseline. See
`docs/OPTIMIZATION_PLAN.md` for the full per-step progression table,
per-byte breakdowns, and estimate-vs-measured analysis, and
`docs/REPRO_CHECK.md` §4 for the post-CT-fix bench table.

## Test/audit/bench backends

As of **v0.4.0**, the four tooling scripts under `tools/` run on
either VICE (default) or Ultimate 64 hardware. Select at runtime:

```
# VICE (default — no env vars needed)
python3 tools/test_chacha20_poly1305.py

# Ultimate 64 over the network
C64_BACKEND=u64 U64_HOST=10.43.23.81 python3 tools/test_chacha20_poly1305.py
C64_BACKEND=u64 U64_HOST=10.43.23.81 python3 tools/audit_cross_check.py --vectors 1000
C64_BACKEND=u64 U64_HOST=10.43.23.81 python3 tools/ct_mul_brute_check.py
C64_BACKEND=u64 U64_HOST=10.43.23.81 python3 tools/benchmark_chacha20_poly1305.py --backend u64
```

The shim at `tools/_u64_helpers.py` routes 6502 `jsr` calls and
cycle measurements through the right transport for each backend, so
the same test/audit/bench flows produce equivalent results on both.
Library PRG output is unchanged — only the validation harness picks
up the new backend support.

## Constant-time guarantees

The library is **constant-time by internal review** with respect to
secret data (key, `r`, `s`, `h`, plaintext, ciphertext, tag). Every
branch under `src/lib/` and `src/main.s` was per-branch-classified
in v0.3.0; the audit verdict and per-branch table live in
`docs/AUDIT.md` and `docs/CT_ANALYSIS.md`. Three pre-existing CT
findings (F1 `poly1305_final` h≥p mask-blend, F2 ChaCha20 single-bit
rotate branchless rewrite, F3 Profile B branchless `ct_mul_8x8`)
were resolved in v0.3.0; see `docs/design/ct_mul_8x8.md` for the
F3 design memo.

Validation evidence shipped alongside this release:

- **30 000 / 30 000** random AEAD vectors (15 000 per profile)
  cross-checked against `pyca/cryptography`'s reference
  `ChaCha20Poly1305` (`tools/audit_cross_check.py`).
- **65 536 / 65 536** exhaustive `(a, b)` pairs in `[0,255]²`
  brute-forced for the new `ct_mul_8x8` primitive
  (`tools/ct_mul_brute_check.py`).
- **214 / 214** RFC 7539 fixed-vector test suite passes on both
  profiles at seed 7539.

This is an **internal audit**, not a third-party security review.
The library is intended for hobbyist and research use.

## Public symbols (library API)

- `chacha20_init` -- seed ChaCha20 state from `cc20_key`, `cc20_nonce`, `cc20_counter`
- `chacha20_block` -- generate one 64-byte keystream block into `cc20_keystream`
- `chacha20_encrypt` -- XOR keystream with data at `cc20_data_ptr` (in place)
- `poly1305_lib_init` -- one-time library init: build quarter-square table, set `sqtab_ready` flag. Call once before first `aead_encrypt`/`aead_decrypt`. Optional: if omitted, `poly1305_init` auto-builds on first call. With `POLY1305_REU=1` (Profile A), also DMA-backs sqtab to REU.
- `poly1305_reu_restore` -- (Profile A + `POLY1305_REU=1` only) DMA sqtab from REU back to main RAM (~1.1 k cy). Use if external code clobbers `$8000-$83FF`.
- `poly1305_init` -- clamp `poly_r`, zero `poly_h`, build multiplication tables (Shoup per-r in Profile A, quarter-square in Profile B). Skips sqtab build if already done.
- `poly1305_block` -- process one 16-byte block pointed to by `zp_ptr1`
- `poly1305_update` -- process a buffer at `zp_ptr1` of length `cc20_remain`
- `poly1305_final` -- finalize and write tag to `poly1305_tag`
- `aead_encrypt` -- full ChaCha20-Poly1305 AEAD encrypt
- `aead_decrypt` -- full ChaCha20-Poly1305 AEAD decrypt (returns A=0 on auth success)

See `src/lib/data_lib.s` for input/output data fields (`aead_key`,
`aead_nonce`, `aead_aad_ptr`, `aead_aad_len`, `aead_data_ptr`,
`aead_data_len`, `aead_tag`).

## Manifest equates (consumer fit checks)

`src/lib/lib_manifest.s` exports four integer equates per the
[c64-lib-contract SPEC §5](https://github.com/JC-000/c64-lib-contract)
aggregate-manifest convention. Consumers `.import` them and use
`.assert` to detect REU/ZP/footprint collisions at assemble time:

- `LIB_CHACHA20_POLY1305_REU_BANKS_USED` — bitmask of REU banks claimed (`1 << POLY1305_REU_BANK` on Profile A with `POLY1305_REU=1`; `$00` otherwise). Composes with the issue #19 `--asm-define POLY1305_REU_BANK=N` override.
- `LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES` — total ZP bytes claimed (88).
- `LIB_CHACHA20_POLY1305_RESIDENT_BYTES` — resident code+data upper bound from the Profile A build (16640; actual 16422 + headroom).
- `LIB_CHACHA20_POLY1305_COLD_BYTES` — overlay-able cold footprint (0; reserved for future hot/cold split).

## Layout

```
src/
  c64.cfg                      ld65 linker config
  main.s                       entry stub + BASIC SYS header
  include/
    ca65hl/                    vendored ca65hl macro package
    smc.inc                    vendored self-modifying-code helpers
  lib/
    constants_lib.s            ZP equates, profile flags
    data_lib.s                 mutable buffers (cc20_*, poly_*, aead_*)
    word32_lib.s               32-bit add / xor / rotate primitives
    chacha20_lib.s             ChaCha20 stream cipher (inlined QRs, rot-rename)
    poly1305_lib.s             Poly1305 MAC (Shoup table / quarter-square)
    chacha20poly1305_lib.s     AEAD wrapper
test/
  rfc7539_vectors.json         RFC 8439 test vectors
tools/
  test_chacha20_poly1305.py    214-test suite (VICE + harness)
  benchmark_chacha20_poly1305.py  CIA-timer benchmark suite
  audit_cross_check.py         30 000 random AEAD vectors vs pyca
  ct_mul_brute_check.py        65 536 exhaustive ct_mul_8x8 pairs
examples/
  smoke_test/                  minimal external-consumer template
                               (own Makefile / cfg / main, RFC 7539
                               §2.8.2 KAT on both profiles)
```

## Documentation

Consumer-facing docs ship under `docs/` and are versioned alongside
the source:

- [`docs/INTEGRATION.md`](docs/INTEGRATION.md) — wiring the library
  into a downstream ca65 build (call sequence, ZP layout, profile
  selection, testing from a consumer project).
- [`docs/API.md`](docs/API.md) — public symbol reference.
- [`docs/MEMORY_MAP.md`](docs/MEMORY_MAP.md) — fixed ZP slots and
  table addresses promised stable across v0.3.x.
- [`docs/AUDIT.md`](docs/AUDIT.md) — top-level constant-time audit
  verdict and methodology.
- [`docs/CT_ANALYSIS.md`](docs/CT_ANALYSIS.md) — per-branch CT
  classification and the F1/F2/F3 Resolution section.
- [`docs/REPRO_CHECK.md`](docs/REPRO_CHECK.md) — reproducibility
  fingerprints and the post-CT-fix bench table.
- [`docs/design/ct_mul_8x8.md`](docs/design/ct_mul_8x8.md) —
  branchless 8×8 multiply design memo (Profile B F3 fix).
- [`docs/OPTIMIZATION_PLAN.md`](docs/OPTIMIZATION_PLAN.md) — the
  full optimization-sprint progression table and notes.

The minimal external-consumer template is
[`examples/smoke_test/`](examples/smoke_test/), which builds and
passes the RFC 7539 §2.8.2 AEAD known-answer vector on both
profiles from a fully consumer-owned build tree.

## Releases

See [`CHANGELOG.md`](CHANGELOG.md) for the full release history.
The current release is **v0.5.0**, which lands the C4 branchless
rotl-4 LUT optimization on the ChaCha20 quarter-round (−8.8%
`chacha20_block`, −3.8% / −1.9% AEAD encrypt at n=1024 for Profile
A / B vs v0.4.0). Library PRGs change vs v0.4.0 — consumers
integrating PRG binaries directly should re-integrate. Tagged
releases are published on the
[GitHub releases page](https://github.com/JC-000/c64-ChaCha20-Poly1305/releases).

Reference build fingerprints for v0.5.0 (md5 of
`build/profile-*/c64_chacha20_poly1305.prg`):

- profile-a: `4da465a262d966059acc2038710fde87`
- profile-b: `fbcc2d509335ff8a40b8607c7fd74837`

Prior-release fingerprints (v0.3.x / v0.4.0, bit-identical on the
default-equate paths):

- profile-a: `313300ff4d86cefc6d3b195563c1383d`
- profile-b: `a0e4b682fa454c6b8e2d8a04297333ab`

## Credits

- ChaCha20 and Poly1305 algorithms by D. J. Bernstein; RFC 8439
  AEAD construction by Y. Nir and A. Langley.
- [`ca65hl`](https://github.com/Movax12/ca65hl) macro pack by
  Movax12 — vendored under `src/include/ca65hl/` with its
  upstream LICENSE preserved at `src/include/ca65hl/LICENSE`.
- `smc.inc` self-modifying-code helper macros by Christian Krüger
  (zlib-licensed, see file header) — vendored under
  `src/include/smc.inc`.

## License

MIT — see [LICENSE](LICENSE).

Vendored third-party code under `src/include/` retains its upstream
licenses:

- `ca65hl/` — MIT (Copyright © 2022 Julian Terrell), see
  `src/include/ca65hl/LICENSE`.
- `smc.inc` — zlib license (Copyright © 2016 Christian Krüger),
  see the comment header at the top of `src/include/smc.inc`.
