# c64-ChaCha20-Poly1305 v0.6.0 — Release Notes

Released 2026-07-28. Compared to v0.5.0 (2026-05-15).

Packaging, contract-alignment, and size-variant release: lands the
`make lib` / `make lib-aead-only` archive targets (c64-lib-contract
SPEC §6), the `POLY1305_MULTIPLY_ROLLED{,_OUTER}` size↔cycles
variants that closed [issue #34](https://github.com/JC-000/c64-ChaCha20-Poly1305/issues/34),
and the §8 shared-primitive adoption wave (§8.0/§8.1/§8.3). Unlike
v0.5.0, the export surface **does** change: symbols are both added
(`LIB_VERSION_*`, manifest/shared-primitive equates, the
`src/zp_config.s` ZP surface) and removed (the `poly1305_reu_*` API
and Profile A's dead sqtab/`mul_8x8`, PR #38). Semver: MINOR bump on
the pre-1.0 scale. Default-build codegen is nearly unchanged — see
Performance.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md); this
file is the concise release summary plus the reproducible-tarball
record.

## What's new

### Packaging (SPEC §6)

- **`make lib`** → `build/lib/c64-chacha20-poly1305.a` (every
  exported symbol, ar65 archive) and **`make lib-aead-only`** →
  `build/lib/c64-chacha20-poly1305-aead-only.a`
  (`LIB_VARIANT_AEAD_ONLY=1`, test-only exports stripped). ld65
  pulls only referenced modules; `test_consumer/` is the worked
  consumption example. (PR #35)

### Size variants (issue #34)

Two default-off knobs re-roll the Poly1305 schoolbook multiply —
the single largest symbol at ~53% of Profile B CODE:

| Config | Profile B PRG | min consumer link |
|---|---:|---:|
| baseline | 17,448 B | 17,446 B |
| aead-only archive | 17,192 B | 16,422 B |
| `POLY1305_MULTIPLY_ROLLED_OUTER` | 9,256 B | 9,254 B |
| combined | 9,000 B | **8,230 B (−52.8%)** |

Cycle cost of `ROLLED_OUTER`: **+4.08%** on `aead_encrypt n=1024`.
The fully-rolled `POLY1305_MULTIPLY_ROLLED` trades a further 576 B
for +17.4%. Build targets `make profile-b-rolled{,-outer}` cover
both. The combined config brings a consumer link ~3.8 KB under
c64-wireguard's ~12 KB integration budget — the ask that opened
issue #34. (PR #36)

### Contract alignment (c64-lib-contract)

- **§8.0** catch-loop precalc enumeration — `LIB_PRECALC_TABLE`
  invocations in `src/lib/lib_manifest.s` (PR #42).
- **§8.1** canonical sqtab equate — relocatable via
  `-DLIB_SHARED_SQTAB_BASE` (default `$8000`) (PR #39), with the
  SMC target-site operand derived from the same equates (PR #41).
- **§8.3** `ct_mul_8x8` **canonical owner** — bit `$0004`;
  `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES` defaults to `$0005`
  with `SHARED_SQTAB_INIT` / `SHARED_CT_MUL_8X8` deferral switches
  dropping their bits (PR #43, issue #21).
- **Version + manifest exports** — `LIB_VERSION_MAJOR/MINOR/PATCH`
  + `LIB_ABI_VERSION` (PR #30); ZP usage, profile-aware resident
  bytes, and aead-only resident bytes equates (PRs #33/#35).
- **ZP relocation** — `src/zp_config.s` `.exportzp` header; ZP
  layout overridable via ca65 `-D` pre-defines (PR #32).
- **`CHACHA20_USE_WORD32`** opt-in pointer-mode profile; default
  off preserves existing codegen (PR #31).

### Tooling

- **Granular per-symbol benching** — `make bench` /
  `make bench-check` with a diffable JSON sidecar
  (`tools/bench_granular.py`, `docs/BENCH_GRANULAR.md`) (PR #37).
- **Turbo-scaling sweep** — `tools/bench_turbo_sweep.py` +
  `docs/BENCH_TURBO_SWEEP.md`; measured **47× wall-clock at 48 MHz**
  on Ultimate 64, with the turbo-hygiene guard (force 1 MHz before
  benching) baked into the bench tools (PR #45, issue #44).

### Removed

- **The `POLY1305_REU` path and Profile A's dead sqtab/`mul_8x8`**
  (issue #34 F1, PR #38). Neither profile issues any REU DMA;
  REU-less machines and turbo hosts are first-class.

## Performance

Default-build cycle counts are unchanged from v0.5.0 within noise,
except a small `poly1305_final` loop-fuse win measured in
[`docs/BENCH_NSWEEP_v0.6.0.md`](BENCH_NSWEEP_v0.6.0.md) (VICE) and
[`docs/BENCH_NSWEEP_u64_v0.6.0.md`](BENCH_NSWEEP_u64_v0.6.0.md)
(Ultimate 64). Profile A's PRG shrinks 16,424 → 16,168 B from the
PR #38 dead-code gating.

Variant cycle costs (issue #34 bench, config D vs baseline):

| routine | baseline | combined D | Δ |
|---|---:|---:|---:|
| `poly1305_multiply` | 37,445 | 39,689 | +5.99% |
| `aead_encrypt n=1024` | 3,195,683 | 3,326,092 | **+4.08%** |
| `aead_compute_tag` | 2,495,149 | 2,625,631 | +5.23% |
| `chacha20_block` | 39,319 | 39,404 | +0.22% (layout artifact) |

## Validation

- **214 / 214** RFC 7539 fixed-vector test suite passes at release
  HEAD (VICE backend, default profiles).
- Variant configs: full suite passes on the rolled-outer PRG
  config; the aead-only archive configs strip test-only entry
  points by design, so the RFC 7539 §2.8.2 AEAD KAT is the
  functional gate there — it passes on all four configs (issue #34
  measurement thread).
- Both profiles reproducible from clean checkout.

## Security

- **No CT regression on default builds** — no crypto-path codegen
  change since v0.5.0's GREEN verdict (`docs/AUDIT.md`, F1/F2/F3
  resolved) beyond the equate-derived SMC operand fix (PR #41),
  which preserves the §8.1 placement contract by construction.
- The new variant flags received a **static CT review** recorded in
  the "Variant builds" note in `docs/CT_ANALYSIS.md`: loop control
  in the rolled multiply variants iterates public limb indices
  only; `CHACHA20_USE_WORD32` changes addressing mode on public
  data.

## Reference build fingerprints

PRG md5 (`build/profile-*/c64_chacha20_poly1305.prg`):

- profile-a: `79deb98c0028488f84278aa2ec645c9d` (16 168 B, top CODE label `$4727`)
- profile-b: `4afe54d466ad92ca38b91c94a2ea2b36` (17 448 B, top CODE label `$4C27`)

Both well under the `$5000` benchmark-plaintext-buffer floor. The
`LIB_VERSION_*` equate bump emits no bytes — fingerprints match the
post-PR-#41 state.

## Source tarball

Built reproducibly via `tools/build_release.sh v0.6.0` (alias:
`make dist VERSION=v0.6.0`). `git archive` + `gzip -n -9` for
byte-identical output across re-runs. The recorded SHA256 of the
v0.6.0 tarball is captured in the GitHub release description.
