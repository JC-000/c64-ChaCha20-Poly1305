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
make profile-a              # Profile A: Shoup per-r tables, optimized for long messages
make profile-b              # Profile B: stock C64, portable baseline, lower init cost
make                        # alias for profile-a
make profile-b-rolled       # Profile B with fully-rolled poly1305_multiply (min code)
make profile-b-rolled-outer # Profile B with outer-loop-rolled poly1305_multiply
make lib                    # full ar65 archive -> build/lib/chacha20poly1305.a
make lib-aead-only          # trimmed archive -> build/lib/chacha20poly1305-aead-only.a
make bench                  # granular bench -> docs/BENCH_REPORT.md (+ JSON sidecar)
make bench-check            # bench + drift gate vs docs/BENCH_REPORT.baseline.json
make dist VERSION=vX.Y.Z    # reproducible source tarball (tools/build_release.sh)
```

The profile targets produce `build/c64_chacha20_poly1305.prg` and
`build/labels.txt` (VICE-format label file for harness consumption,
converted from the ld65 label output by the Makefile).

The `lib` / `lib-aead-only` targets produce ar65 static archives under
`build/lib/` per the c64-lib-contract SPEC §6 consumption paths:
downstream projects link `chacha20poly1305.a` (or the aead-only
variant) directly into their own ld65 build instead of integrating the
PRG. `test_consumer/` is the worked example of an archive-consuming
build; see [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for the full
consumer wiring guide.

## Build profiles

- **Profile A** precomputes 8 KB of Shoup per-r multiplication tables
  at `poly1305_init` time (~118 k cy setup cost via the S11
  incremental ripple-add), reducing `poly1305_block` from 38 760 to
  12 119 cy. Best for messages longer than **~64 bytes**, where the
  table-build amortizes (measured A/B crossover, see
  `docs/BENCH_NSWEEP_v0.5.0.md`). Target workloads: WireGuard data
  packets (~1280 B), TLS 1.3 bulk records. As of the issue #34 F1
  slimming ([PR #38](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/38)),
  Profile A no longer emits the quarter-square table or the former
  `POLY1305_REU=1` stash/restore path — see "Turbo hosts and
  REU-less machines" below.

- **Profile B** uses the portable quarter-square multiply (1 KB table).
  Lower per-packet init cost (87 k vs 579 k cy at n=0), better for
  short packets such as WireGuard handshakes and TLS 1.3 alerts.
  Runs on any stock C64 without REU (as does Profile A — see below).

Both profiles share identical ChaCha20 code, pass the full 214-test
suite, and are constant-time by contract (no data-dependent branches on
secret data).

## Size variants (issue #34)

Issue #34 (closed with this release) added two orthogonal, default-off
size knobs on top of the Profile B baseline. Measured footprints
(Profile B PRG bytes / minimal AEAD-only consumer link bytes):

| config | build | PRG | min consumer link | cycles, `aead_encrypt` n=1024 |
|--------|-------|----:|------------------:|------------------------------:|
| A — baseline | `make profile-b` + full archive | 17 448 | 17 446 | baseline |
| B — aead-only | `make lib-aead-only` archive | 17 192 | 16 422 | unchanged |
| C — rolled-outer | `-DPOLY1305_MULTIPLY_ROLLED_OUTER=1` | 9 256 | 9 254 | +4.08% |
| D — combined | aead-only archive + rolled-outer | 9 000 | **8 230** | +4.08% |

Config D is the headline result: **8,230 B** linked consumer footprint
— less than half the 17,446 B baseline minimum link — for +4.08%
cycles on `aead_encrypt` n=1024. Which knob to pick:

- **aead-only** (`make lib-aead-only`) is free in cycles — it only
  strips test-only exports (see "Public symbols" below) — so any
  consumer that calls just the AEAD ABI should take it.
- **rolled-outer** (`-DPOLY1305_MULTIPLY_ROLLED_OUTER=1`, or `make
  profile-b-rolled-outer`) is the big win: rolling the outer j-loop of
  `poly1305_multiply` trades +4.08% AEAD cycles for ~8 KB of code.
- **combined** (config D) for the minimum footprint.
- The fully-rolled variant (`-DPOLY1305_MULTIPLY_ROLLED=1`, `make
  profile-b-rolled`) also rolls the inner partial-product loop; it
  saves a further 576 B over rolled-outer but costs +17.4% at n=1024 —
  only worth it when every last page counts.

Default builds are unchanged: all of these are opt-in, and `make
profile-a` / `make profile-b` / `make lib` produce the same output as
before.

### Build-time defines

- `LIB_VARIANT_AEAD_ONLY=1` — strips test-only exports from the
  archive (set by `make lib-aead-only`; crypto code paths untouched).
- `POLY1305_MULTIPLY_ROLLED_OUTER=1` / `POLY1305_MULTIPLY_ROLLED=1` —
  the default-off size↔cycles dials above (mutually exclusive).
- `CHACHA20_USE_WORD32` — opt-in pointer-mode ChaCha20 profile for
  consumers that already ship a shared `word32.s`; default off (the
  default build inlines the ZP-direct macro forms and pulls no
  `word32_lib.o` into a minimal consumer link).

See [`docs/API.md`](docs/API.md) for the full build-time define table.

## Performance

The numbers below are the **v0.5.0 release baseline** (cycles via CIA
timer, identical on VICE and Ultimate 64 hardware backends to within
±0.2%, `tools/benchmark_chacha20_poly1305.py`, 3 samples, min per
routine).

| routine              | S0 baseline |     v0.5.0 Profile A |   change |     v0.5.0 Profile B |   change |
|----------------------|------------:|---------------------:|---------:|---------------------:|---------:|
| `chacha20_block`     |     149 987 |               39 331 |  -73.8%  |               39 332 |  -73.8%  |
| `poly1305_block`     |      53 270 |               11 951 |  -77.6%  |               37 950 |  -28.8%  |
| `aead_encrypt` n=0   |     251 330 |              182 345 |  -27.4%  |               80 749 |  -67.9%  |
| `aead_encrypt` n=1024|   5 974 048 |            1 623 299 |  -72.8%  |            3 196 264 |  -46.5%  |

HEAD cycle counts (`make bench`, samples=3, VICE):

| routine              |  HEAD Profile A |  HEAD Profile B | Δ vs v0.5.0 (A / B) |
|----------------------|----------------:|----------------:|--------------------:|
| `chacha20_block`     |          39 319 |          39 319 |   -0.03% / -0.03%   |
| `poly1305_block`     |          12 036 |          37 891 |   +0.71% / -0.16%   |
| `aead_encrypt` n=0   |         182 105 |          80 519 |   -0.13% / -0.29%   |
| `aead_encrypt` n=1024|       1 622 873 |       3 195 710 |   -0.03% / -0.02%   |

All HEAD-vs-v0.5.0 deltas are within the ~0.7% measurement noise (see
`docs/REPRO_CHECK.md` §4 for the noise floor methodology) — there is
no measurable post-v0.5.0 regression on any cited row. The numbers
above are regenerable via `make bench`, gate-checked via `make
bench-check` against `docs/BENCH_REPORT.baseline.json`. See
`docs/BENCH_GRANULAR.md` for the full per-symbol breakdown including
`chacha20_quarter_round`, `chacha20_encrypt`, `poly1305_multiply`,
`poly1305_reduce`, `aead_compute_tag`, `aead_verify_tag`,
`sqtab_init`, and `ct_mul_8x8`.

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

## Turbo hosts and REU-less machines

**This library issues no REU DMA on any code path, in any profile.**
As of the issue #34 F1 slimming
([PR #38](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/38)),
Profile A builds its Shoup tables by incremental ripple-add without
consuming the quarter-square table, so the former `POLY1305_REU=1`
sqtab stash/restore path (v0.5.x and earlier) was removed along with
its API (`poly1305_reu_restore`, `poly1305_reu_sqtab_bank` /
`poly1305_reu_sqtab_offset`). Profile B never had an REU path. The
manifest equate `LIB_CHACHA20_POLY1305_REU_BANKS_USED` reads `$00`
unconditionally, and the library touches no I/O registers at all
(CIA timer access lives in the bench tooling, not the library).

This matters on accelerated hosts (Ultimate 64 / C64 Ultimate turbo,
SuperCPU-class): REU DMA transfers at the stock ~1 MHz bus rate
regardless of CPU turbo, so REU traffic on a hot path becomes a
clock-invariant wall-time floor — see
[c64-nist-curves #69](https://github.com/JC-000/c64-nist-curves/issues/69) /
[#71](https://github.com/JC-000/c64-nist-curves/issues/71), where
per-multiply REU row fetches held `ecdsa_verify_256` to a 22.2 s
floor at 64 MHz until an on-chip-multiply profile removed them. This
library has no such floor: **AEAD throughput scales ~linearly with
CPU clock.**

Measured (Ultimate 64 Elite, Profile A, CIA chained-timer wall-clock,
min of 3 samples, single session, `tools/bench_turbo_sweep.py` —
methodology in `docs/BENCH_TURBO_SWEEP.md`):

| routine | 1 MHz wall | 16 MHz wall | 48 MHz wall | speedup @ 48 MHz | ideal |
|---------|-----------:|------------:|------------:|-----------------:|------:|
| `aead_encrypt` n=1024 | 1 647.4 ms | 102.9 ms | 35.0 ms | **47.0×** | 48× |
| `chacha20_block`      | 39.9 ms | 2.35 ms | 0.80 ms | ~48× (in jitter) | 48× |
| `poly1305_block`      | 12.1 ms | 0.72 ms | 0.24 ms | ~48× (in jitter) | 48× |

The n=1024 AEAD speedup is 98% of the ideal clock ratio — there is no
measurable speed-invariant component. (64 MHz was firmware-rejected on
the Elite-generation test device; it is a C64 Ultimate-generation
speed. The scaling conclusion does not depend on it.)

For REU-less machines: both profiles run on a stock C64 with no REU
fitted. Profile B is the portable baseline (1 KB of fixed-address
table RAM); Profile A also requires no REU — it needs only the
$6000..$7FFF Shoup window in main RAM.

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

`make test` builds each profile and runs
`tools/test_chacha20_poly1305.py` against it; the target exits non-zero
on the first failing profile. Both `make test` and the fuzz targets
below use `TEST_PYTHON` (defaults to the c64-test-harness venv) and pass
`C64_BACKEND` / `U64_HOST` through from the environment.

### Differential fuzz

`tools/hazmat_fuzz.py` is an adversarial differential fuzz of the whole
stack against pyca/cryptography hazmat (`ChaCha20Poly1305`, `ChaCha20`,
`Poly1305`) — it does not share a reference implementation with any other
tool in this repo. The corpus is edge-driven rather than uniform: block
counters at every carry boundary including the 32-bit wrap, Poly1305 keys
at the clamp fixed point and accumulator states at `p-3..p+2`, an AEAD
length grid (0..3840 plaintext x 0..255 AAD), and a tamper set (tag / ct
/ AAD bit flips, AAD length +-1, zero tag, wrong key, wrong nonce) that
must be rejected *and* leave the ciphertext buffer intact. The encrypt
tag is asserted from the documented output symbol `aead_tag` as well as
the internal `poly1305_tag`. Deterministic given `--seed`; exit status is
non-zero on any mismatch.

```
make test-fuzz        # both profiles, --quick (~1-2 min each on VICE)
make test-fuzz-full   # both profiles, full corpus
python3 tools/hazmat_fuzz.py --profile a --seed 1234   # one profile, own seed
```

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
- `poly1305_lib_init` -- one-time library init: on Profile B, build the quarter-square table and set the `sqtab_ready` flag (optional: if omitted, `poly1305_init` auto-builds on first call). On Profile A the body is a bare `rts`, retained as an exported entry point so cross-profile consumers keep working unchanged.
- `poly1305_init` -- clamp `poly_r`, zero `poly_h`, build multiplication tables (Shoup per-r in Profile A, quarter-square in Profile B). Skips sqtab build if already done.
- `poly1305_block` -- process one 16-byte block pointed to by `chacha20poly1305_zp_ptr1`
- `poly1305_update` -- process a buffer at `chacha20poly1305_zp_ptr1` of length `cc20_remain`
- `poly1305_final` -- finalize and write tag to `poly1305_tag`
- `aead_encrypt` -- full ChaCha20-Poly1305 AEAD encrypt
- `aead_decrypt` -- full ChaCha20-Poly1305 AEAD decrypt (returns A=0 on auth success)

Version constants (`src/lib_version.s`):

- `LIB_VERSION_MAJOR` / `LIB_VERSION_MINOR` / `LIB_VERSION_PATCH` --
  exported integer equates tracking the released semver (0.7.0).
  Also exported in the collision-free `LIB_CHACHA20_POLY1305_VERSION_*`
  form (contract §1 v0.7.0); the bare names are deprecated and
  suppressible with `ca65 -D LIB_NO_BARE_EXPORTS=1`. Consumers
  `.import` them and guard with
  `.assert (… VERSION_MAJOR > 0) .or (… VERSION_MINOR >= 7), lderror, "…"`.
  It must be `.assert`/`lderror` rather than `.if`/`.error`: an
  `.import`ed symbol has no value until link, so an `.if` gate does not
  assemble at all. See `docs/API.md` §8.
- `LIB_ABI_VERSION` -- monotonic generation counter for the exported
  symbol surface (currently **2**), deliberately not a mirror of MAJOR.
  It increments on any breaking export change; generation 2 covers
  v0.7.0's removed §8.x bit constants and renamed segments. See
  `docs/API.md` §8.

Under the aead-only archive variant (`-DLIB_VARIANT_AEAD_ONLY=1`, i.e.
`make lib-aead-only`) the test-only exports vanish:
`chacha20_quarter_round`, `mul_8x8`, and the word32 helpers
`rotl32_1` / `rotl32_7` / `rotr32_7` are no longer published (bodies
remain; only the symbol table shrinks). In the default build the
ChaCha20 hot path inlines its rotates, so a minimal AEAD-only consumer
link pulls in no `word32_lib.o` at all — the rest of the word32
surface (`add32`, `xor32`, the remaining rotates) is exported but
absent from such a link.

See `src/lib/data_lib.s` for input/output data fields (`aead_key`,
`aead_nonce`, `aead_aad_ptr`, `aead_aad_len`, `aead_data_ptr`,
`aead_data_len`, `aead_tag`).

`aead_data_len` is a full 16-bit count with no length cap; the caller's
one obligation is `aead_data_ptr + aead_data_len <= $10000`, since the
data walkers wrap unchecked past `$FFFF`. See the "Data-buffer domain"
note in `docs/INTEGRATION.md`.

## Manifest equates (consumer fit checks)

`src/lib/lib_manifest.s` exports seven integer equates per the
[c64-lib-contract SPEC §5](https://github.com/JC-000/c64-lib-contract)
aggregate-manifest convention (five §5 aggregate equates plus the two
§8 shared-primitive masks). Consumers `.import` them and use
`.assert` to detect REU/ZP/footprint collisions at assemble time:

- `LIB_CHACHA20_POLY1305_REU_BANKS_USED` — bitmask of REU banks claimed. Always `$00`: the library issues no REU DMA in any profile (the former Profile A `POLY1305_REU` stash was removed by the issue #34 F1 slimming, PR #38).
- `LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES` — total ZP bytes claimed (88).
- `LIB_CHACHA20_POLY1305_RESIDENT_BYTES` — resident code+data upper bound, profile-aware since the issue #34 F1 slimming diverged the two footprints. Rebased in v0.7.0 onto the library's own segment sum rather than whole-PRG size: Profile A = 15616 (measured 15544), Profile B = 16896 (measured 16838), each rounded up to the next 256-byte boundary.
- `LIB_CHACHA20_POLY1305_AEAD_ONLY_RESIDENT_BYTES` — tighter upper bound for consumers pinning the aead-only archive variant (16640, measured 16513).
- `LIB_CHACHA20_POLY1305_COLD_BYTES` — overlay-able cold footprint (0; reserved for future hot/cold split).
- `LIB_CHACHA20_POLY1305_SHARED_CONSUMES` — bitmask of shared primitives this build *uses*, whether or not it owns them (`$0005` on Profile B, `$0000` on Profile A). Paired with the ownership mask below, it distinguishes a deferring consumer — which needs exactly one owner in the link — from a non-consumer, which needs no provider at all.
- `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES` — bitmask of shared primitives this build owns (`$0005` in the default standalone build; defining `SHARED_SQTAB_INIT` or `SHARED_CT_MUL_8X8` drops the corresponding bit so composed libraries see disjoint masks, issue #21).

The §8.x bit constants themselves (`LIB_SHARED_PRIMITIVES_SQTAB` = `$0001`, `LIB_SHARED_PRIMITIVES_CT_MUL_8X8` = `$0004`) are **not** exported — they are plain local equates that consumers copy, since their names and values are identical in every adopter and exporting them collides at link (issue #57). They exist only to build the two masks above, which are the symbols meant to cross the link.

In addition, the manifest emits the [SPEC §8.4 catch-loop](https://github.com/JC-000/c64-lib-contract/blob/main/SPEC.md) precalc-table enumeration via the `LIB_PRECALC_TABLE` macro from `src/precalc_table.inc` (verbatim copy of the canonical c64-lib-contract source). Each enumerated table emits **six** exported equates since contract v0.7.0 — the library-prefixed `LIB_CHACHA20_POLY1305_PRECALC_<name>_{SIZE,REGION,SHARED}` plus the deprecated bare `LIB_PRECALC_<name>_*` triple, the latter suppressed under `-D LIB_NO_BARE_EXPORTS=1`. Cross-adopter audits grep with `od65 --dump-exports build/profile-*/lib_manifest.o | grep _PRECALC_` — note `_PRECALC_`, not `LIB_PRECALC_`, since the older pattern misses every prefixed export. Profile A enumerates four tables (`chacha_nibswap_hi_tab`, `chacha_nibswap_lo_tab`, `r_tab_lo`, `r_tab_hi`) and Profile B three (`sqtab` plus the two nibswap tables) — so a default build surfaces **24** and **18** `_PRECALC_` exports respectively, dropping to **12** and **9** under `-D LIB_NO_BARE_EXPORTS=1` once the deprecated bare triples are suppressed. `sqtab` is profile-gated as of issue #51 — Profile A neither emits nor consumes it, so it enumerates no `sqtab` row. `od65` cannot read `.a` archives, so audit the per-variant object dirs, never the archive. See [`docs/precalc-tables.md`](docs/precalc-tables.md) for per-table rationale.

## Contract conformance

This library implements
[c64-lib-contract](https://github.com/JC-000/c64-lib-contract) and is
aligned to **SPEC v0.10.3**, audited clause-by-clause rather than
assumed. §13 (network backend ABI) and §8.2 (`reu_mul`) do not apply —
this is not a network backend, and the library neither owns nor consumes
the REU multiply table (`SHARED_CONSUMES = $0005`).

| Clause | How this library satisfies it |
|---|---|
| §1 version identification | prefixed + deprecated bare exports; `src/lib_version.s` exports nothing else (TU isolation) |
| §2 zero page | 24 `.exportzp` slots, every one `.ifndef`-guarded; names under the registered `cc20_` `poly_` `w32_` `ct_` `chacha_` `chacha20poly1305_` prefixes |
| §3 REU | claims no banks — `LIB_CHACHA20_POLY1305_REU_BANKS_USED = $0000` |
| §4 segment naming | library sources emit only `LIB_CHACHA20_POLY1305_CODE`/`_DATA`; cfg declares the load-bearing `align = $100` and `type = rw` attributes |
| §5 manifest | aggregate equates in `src/lib/lib_manifest.s`, separate from `lib_version.s` |
| §6.1–§6.4 build | `lib`, `lib-aead-only`, `lib-app-owned`; `CONTRACT_DEFINES` on every target; per-archive manifests |
| §6.3 reachability | Profile A/B ride `CONTRACT_DEFINES` (one member list, so no target of their own); a knob change invalidates the object cache, so no build can exit 0 with the artifact the knob did not request. On v0.11.1's split this is the **invalidation** branch — the rejection branch is vacuous here, since no member-set axis is reachable through the defines |
| §6.5 rename window | archives dual-named; deprecated bare ZP aliases behind `LIB_NO_BARE_EXPORTS` |
| §6.6 footprint | per-archive, safe-direction, with the required `COLD_BYTES` companion |
| §6.7 reservations | `src/main.s` asserts the image cannot grow into the sqtab window |
| §8.0/§8.1/§8.3/§8.4 | bit constants, `LIB_SHARED_SQTAB_BASE` and `sqtab_lo`/`sqtab_hi` all unexported; deferral imports the provider rather than stubbing |

**`make verify-zp-usage`** is the R2 audit: it derives the occupied
zero-page set from the exported slot addresses in `zp_config.o` and
checks it against the §5 `LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES` equate,
which is otherwise a hand-maintained literal free to drift. It also
rejects an unintended alias (two distinct slots on one address would
*shrink* the union rather than fail) and an understated equate, per
§6.6's safe-direction rule. Current result: 24 exported names, 88 bytes
occupied, equate 88. Not named `lib-*` — §6.1 reserves that namespace
for targets producing archives.

**`make verify-knob-staleness`** pins the §6.3 guard (contract SPEC
v0.10.5). `CONTRACT_DEFINES` reaches every `ca65` invocation but no make
*prerequisite*, so before issue #86 a knob change reused every stale
object and shipped the previous configuration under a zero exit code —
the clause's shape-3 "silent no-op". The Makefile now records the
flattened knob string in `build/.contract-defines.stamp` and invalidates
every object and archive when it changes; unchanged knobs leave the tree
alone, so same-knob builds stay incremental. The audit checks all four
legs — change rebuilds, artifact flips profile, same knob is
incremental, revert rebuilds back — because the last two are what
separate a staleness check from an unconditional rebuild.

**ZP slot overrides do not go through these targets.** This library uses
the §6.2 consumer-assembled-source model: no archive member defines ZP,
so you assemble your own `src/zp_config.s` and override there. Passing a
slot define to a `lib*` target instead fails loudly —
`Symbol 'chacha20poly1305_zp_tmp1' is already defined` — rather than
silently producing a mismatched archive. See
[`docs/INTEGRATION.md`](docs/INTEGRATION.md).

Two standing obligations, recorded so they are not lost between releases:

- **§6.1 reserved namespace.** `lib-*` is reserved for targets producing
  archives. `make lib-verify-shared` is a verification target and is
  grandfathered under that clause **until this library's next MAJOR**,
  at which point it must be renamed out of the `lib-` namespace.
- **§6.6 release notes.** Every release MUST state footprint deltas
  **per (profile × variant)** — a single per-version number is
  meaningless when one tag carries several footprint pairs.

## Layout

```
src/
  c64.cfg                      ld65 linker config
  main.s                       entry stub + BASIC SYS header
  lib_version.s                exported LIB_VERSION_* / LIB_ABI_VERSION equates
  zp_config.s                  c64-lib-contract ZP-config header
  precalc_table.inc            SPEC §8.0 LIB_PRECALC_TABLE macro (verbatim contract copy)
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
    lib_manifest.s             SPEC §5 manifest equates + §8.0 precalc enumeration
test/
  rfc7539_vectors.json         RFC 8439 test vectors
test_consumer/
  ...                          archive-consumption worked example: minimal
                               AEAD-only consumer linked against build/lib/*.a
                               (the issue #34 footprint measurement harness)
tools/
  test_chacha20_poly1305.py    214-test suite (VICE + harness)
  benchmark_chacha20_poly1305.py  CIA-timer benchmark suite
  bench_granular.py            per-symbol granular bench (make bench / bench-check)
  bench_turbo_sweep.py         turbo-scaling wall-clock sweep (issue #44)
  build_release.sh             reproducible release tarball (make dist)
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
- [`docs/BENCH_TURBO_SWEEP.md`](docs/BENCH_TURBO_SWEEP.md) —
  turbo-scaling wall-clock sweep methodology and results (issue #44).
- [`docs/BENCH_GRANULAR.md`](docs/BENCH_GRANULAR.md) — granular
  per-symbol bench methodology (`make bench` / `make bench-check`).
- [`docs/BENCH_REPORT.md`](docs/BENCH_REPORT.md) — latest generated
  per-symbol bench report (regenerated by `make bench`).
- [`docs/BENCH_NSWEEP_v0.5.0.md`](docs/BENCH_NSWEEP_v0.5.0.md) —
  packet-size (n) sweep baseline and the measured A/B crossover.
- [`docs/BENCH_NSWEEP_v0.6.0.md`](docs/BENCH_NSWEEP_v0.6.0.md) —
  v0.6.0 n-sweep; still current through v0.8.0, whose codegen is
  byte-identical and measured cycles unchanged.
- [`docs/BENCH_NSWEEP_u64_v0.6.0.md`](docs/BENCH_NSWEEP_u64_v0.6.0.md)
  — v0.6.0 n-sweep on Ultimate 64 hardware; likewise still current.
- [`docs/precalc-tables.md`](docs/precalc-tables.md) — SPEC §8.0
  precalc-table enumeration rationale and exempt list.
- [`docs/RELEASE_NOTES_v0.5.0.md`](docs/RELEASE_NOTES_v0.5.0.md) —
  v0.5.0 release notes.
- [`docs/RELEASE_NOTES_v0.6.0.md`](docs/RELEASE_NOTES_v0.6.0.md) —
  v0.6.0 release notes.
- [`docs/RELEASE_NOTES_v0.7.0.md`](docs/RELEASE_NOTES_v0.7.0.md) —
  v0.7.0 release notes (created in this release pass).
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
The current release is **v0.9.0** (tagged 2026-08-15;
`src/lib_version.s` declares 0.9.0, `LIB_ABI_VERSION` **3**): a
hardening release — the §6.7 image guard against silent sqtab
corruption, the `make verify-zp-usage` drift ratchet, and a
clause-by-clause conformance record against c64-lib-contract v0.10.3.
**No migration required**: both PRGs and the exported symbol surface are
byte-identical to v0.8.0, so it is a drop-in. See
[`docs/RELEASE_NOTES_v0.9.0.md`](docs/RELEASE_NOTES_v0.9.0.md).

The prior release, **v0.8.0** (2026-08-15;
`LIB_ABI_VERSION` **3**), was the
packaging-and-naming conformance release, bringing the library from
c64-lib-contract v0.7.2 up to v0.9.2. **It is breaking on two axes** —
the four general-purpose ZP slots are renamed to
`chacha20poly1305_zp_*` under the SPEC §2 prefix registry, and archives
gain their canonical `chacha20poly1305[-variant].a` basenames; see
[`docs/RELEASE_NOTES_v0.8.0.md`](docs/RELEASE_NOTES_v0.8.0.md) for the
migration steps. The default-build PRG is **byte-identical to v0.7.0**,
so codegen and measured cycles are unchanged.

The prior release, **v0.7.0** (2026-08-13; its tag reports
`LIB_ABI_VERSION` 1, corrected afterwards per issue #67), was the
contract-conformance release that brought the library from
c64-lib-contract v0.4.0 up to v0.7.2 and made it composable with a
sibling library for the first time, moving library code to
`LIB_CHACHA20_POLY1305_CODE`/`_DATA`. The prior
release, **v0.6.0** (2026-07-28), was the c64-lib-contract adoption +
size-variants release, closing issue #34 with the ar65 archive
variants and the rolled-multiply size knobs (config D: 8,230 B linked
consumer footprint — see "Size variants" above). **v0.5.0** landed the C4 branchless
rotl-4 LUT optimization on the ChaCha20 quarter-round (−8.8%
`chacha20_block`, −3.8% / −1.9% AEAD encrypt at n=1024 for Profile
A / B vs v0.4.0). Tagged releases are published on the
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
