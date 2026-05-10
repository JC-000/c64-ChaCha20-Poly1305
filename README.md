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
  than ~256 bytes, where the table-build amortizes. Target workloads:
  WireGuard data packets (~1280 B), TLS 1.3 bulk records. With
  `POLY1305_REU=1`, backs up the quarter-square table to REU for
  fast restore if clobbered.

  The REU destination bank and offset are configurable via
  `POLY1305_REU_BANK` (default `0`) and `POLY1305_REU_OFFSET` (default
  `$0000`) so downstream projects that link multiple REU consumers
  (e.g. this library alongside `c64-x25519`, which occupies REU banks
  0-1) can allocate non-conflicting regions. Override at assemble
  time via `ca65 --asm-define POLY1305_REU_BANK=3
  --asm-define POLY1305_REU_OFFSET=$1000`, or by `.include`'ing a
  project-wide layout header that defines these before
  `constants_lib.s` is included. With the defaults the runtime
  behaviour is identical to prior releases. See issue #19.

- **Profile B** uses the portable quarter-square multiply (1 KB table).
  Lower per-packet init cost (87 k vs 579 k cy at n=0), better for
  short packets such as WireGuard handshakes and TLS 1.3 alerts.
  Runs on any stock C64 without REU.

Both profiles share identical ChaCha20 code, pass the full 214-test
suite, and are constant-time by contract (no data-dependent branches on
secret data).

## Performance

v0.3.0 cycle counts (cycles, measured via CIA timer, identical on
VICE and Ultimate 64 hardware backends to within ±0.2%,
`tools/benchmark_chacha20_poly1305.py --seed 7539`, 3 samples,
min per routine):

| routine              | S0 baseline |     Profile A |   change |     Profile B |   change |
|----------------------|------------:|--------------:|---------:|--------------:|---------:|
| `chacha20_block`     |     149 987 |        43 135 |  -71.2%  |        43 135 |  -71.2%  |
| `poly1305_block`     |      53 270 |        11 948 |  -77.6%  |        37 844 |  -28.9%  |
| `aead_encrypt` n=0   |     251 330 |       186 182 |  -25.9%  |        84 560 |  -66.4%  |
| `aead_encrypt` n=1024|   5 974 048 |     1 686 764 |  -71.8%  |     3 259 490 |  -45.4%  |

Profile A's n=0 cost (186 k cy) is the per-packet `poly1305_init`
incremental Shoup-table build (S11), down from ~579 k cy in
`v0.2-optimized`; it amortizes rapidly at n >= 256. Profile B's n=0
runs in 84 k cy -- **−66.4%** below the sprint-0 baseline. See
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
The current release is **v0.4.0**, which adds Ultimate 64 hardware
backend support to the four `tools/*.py` validation scripts and
makes the Profile A REU stash destination configurable via
`POLY1305_REU_BANK` / `POLY1305_REU_OFFSET` (issue #19). Library
PRG output is unchanged from v0.3.1 on the default-equate paths.
Tagged releases are published on the
[GitHub releases page](https://github.com/JC-000/c64-ChaCha20-Poly1305/releases).

Reference build fingerprints for v0.3.x (md5 of
`build/profile-*/c64_chacha20_poly1305.prg`):

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
