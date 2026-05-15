# c64-ChaCha20-Poly1305 v0.5.0 — Release Notes

Released 2026-05-15. Compared to v0.4.0 (2026-05-10).

Performance release: lands **C4 (branchless rotl-4 LUT)** on the
ChaCha20 quarter-round. Measured −8.8% on `chacha20_block`, flowing
through to −3.8% / −1.9% on `aead_encrypt n=1024` for Profile A /
Profile B vs v0.4.0. Library PRGs change on both profiles —
consumers integrating PRG binaries directly should re-integrate;
consumers linking from source see the change automatically. No
public symbols were added, removed, or renamed.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md); this
file is the concise release summary plus the reproducible-tarball
record.

## What's new

### Macro change

- **`rotl32_4_zp` in `src/lib/chacha20_lib.s`** rewritten from the
  prior asl/lsr/ora chain (~124 cy) to a straight-line stitch
  across two 256-byte page-aligned LUTs (~80 cy). Saves ~44 cy
  per call × 8 inlined sites in `chacha20_block`'s looped
  double-round body = −3 804 cy / `chacha20_block`.
- **Two new page-aligned LUTs in `src/lib/data_lib.s`**
  (`chacha_nibswap_hi_tab`, `chacha_nibswap_lo_tab`) housed in a
  new `.segment "CODE"` block. `.align 256` so `lda abs,x` against
  them never crosses a page — preserves the prior macro's CT
  posture (no data-dependent branches; no page-cross timing
  dependency on the secret index).

### Tooling

- **Reproducible release tarball builder** (this file ships in the
  tarball it produces): `tools/build_release.sh <tag>` /
  `make dist VERSION=<tag>`. `git archive` + `gzip -n -9` →
  byte-identical tarball for a given tag. Same pattern as
  `c64-nist-curves`.

## Performance

v0.5.0 cycle counts (CIA timer, 3 samples min per routine, identical
on VICE and Ultimate 64 within ±0.2%):

| routine                   |    v0.4.0 |    v0.5.0 |          Δ |
|---------------------------|----------:|----------:|-----------:|
| `chacha20_block` (A/B)    |    43 135 |    39 331 |  **−8.8%** |
| `poly1305_block` (A)      |    11 948 |    11 951 |      noise |
| `poly1305_block` (B)      |    37 844 |    37 950 |      noise |
| `aead_encrypt n=0` (A)    |   186 182 |   182 345 |      −2.1% |
| `aead_encrypt n=0` (B)    |    84 560 |    80 749 |      −4.5% |
| `aead_encrypt n=1024` (A) | 1 686 764 | 1 623 299 |  **−3.8%** |
| `aead_encrypt n=1024` (B) | 3 259 490 | 3 196 264 |  **−1.9%** |

## Validation

- **214 / 214** RFC 7539 fixed-vector test suite passes on Ultimate
  64 (`C64_BACKEND=u64 python tools/test_chacha20_poly1305.py`).
  Rotation sub-group is **70 / 70** — load-bearing correctness gate
  for the C4 macro.
- Both profiles reproducible from clean checkout.

## Security

- **No CT regression.** Both LUTs are `.align 256` so `lda abs,x`
  against them is strictly constant-time; the macro has zero
  data-dependent branches. v0.4.0's GREEN audit verdict
  (`docs/AUDIT.md`, F1/F2/F3 resolved) carries forward unchanged —
  C4 only modifies the ChaCha20 rotation primitive, which was
  already CT-clean via the asl/lsr/ora chain; the LUT form
  preserves that property by construction.

## Reference build fingerprints

PRG md5 (`build/profile-*/c64_chacha20_poly1305.prg`):

- profile-a: `4da465a262d966059acc2038710fde87` (16 424 B, top CODE label `$4827`)
- profile-b: `fbcc2d509335ff8a40b8607c7fd74837` (17 448 B, top CODE label `$4C27`)

Both well under the `$5000` benchmark-plaintext-buffer floor.

## Source tarball

Built reproducibly via `tools/build_release.sh v0.5.0` (alias:
`make dist VERSION=v0.5.0`). The script uses `git archive` +
`gzip -n -9` for byte-identical output across re-runs. The recorded
SHA256 of the v0.5.0 tarball is captured in the GitHub release
description.

## Re-implementation history

This release re-implements
[PR #22](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/22),
which had originally landed C4 but was closed unmerged with its
head branch unrecoverable. The current implementation follows the
spec from the closed PR (macro identity, LUT shapes, page-alignment
rationale) but is byte-different from the lost binary — PR #22's
predicted md5 fingerprints reflected that PR's specific
register/sequencing choices, not the spec itself. The 214-test
suite is the load-bearing correctness check, and it passes cleanly
on both profiles.
