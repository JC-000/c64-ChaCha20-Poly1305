# c64-ChaCha20-Poly1305 v0.12.0 — Release Notes

**ABI generation stays 4.** No exported symbol added, removed or renamed:
97 export rows at v0.11.0, 97 at this tag, zero name difference — reconciled
against raw `Name:` counts on both sides, so the equality means something.

**All four profile PRGs are byte-identical to v0.11.0**: profile-a
`38ea1c83614e7fced3ba6d70e150038d`, profile-b `85f19d9b6408d0734f4f6c2c5d67e9ef`,
B-rolled `67014ae7b41839deade9e4bdbc8cb455`, B-rolled-outer
`2e87bb963a96efa86bf428a0afdef4de`. Nothing about the emitted code changed in
this release. The v0.11.0 VICE suite and CT posture carry.

## Consumer migration

**Nothing to do, and nothing a current consumer reads changes.**

- **Label output is cleaner.** `AEAD_DOMAIN_GUARD` no longer emits 8
  `.LOCAL-MACRO_SYMBOL-NNNN` names into your `-Ln` label file. If you carry a
  workaround stripping them — `c64-wireguard` does — it becomes dead code at
  this pin. Verify with `grep -c 'LOCAL-MACRO_SYMBOL' <your labels file>`
  before removing it; expect 0.
- **One declared figure was raised**, for `make lib` with
  `SHARED_CT_MUL_8X8` **alone** and without `SHARED_SQTAB_INIT`:
  `LIB_CHACHA20_POLY1305_RESIDENT_BYTES` 17664 → **17920**. That configuration
  was under-declared by 60 B — §5's unsafe direction. **No current consumer
  builds it**: `c64-wireguard` passes both switches and still reads 17664,
  unchanged. If you defer `ct_mul_8x8` without deferring `sqtab_init`, budget
  256 B more.

## What changed

### Fixed

- **Macro-local label leak (#117).** `.local` inside `AEAD_DOMAIN_GUARD` made
  ca65 synthesise a name per expansion; four expansions put 8 into every
  consumer link, and the `-` in them is outside the charset a VICE label parser
  accepts. Now unnamed `:` labels, which synthesise nothing. A measured
  side-benefit: a named label inside a macro expansion also opens a new
  cheap-local scope and orphans the enclosing proc's `@labels` — latent here,
  never live, and now removed.
- **`RESIDENT_BYTES` under-declared for one configuration (#126).** The branch
  keyed on one deferral switch while the figure had been measured with both.
- **`verify-label-hygiene` examined almost nothing when run after another
  gate.** It scanned objects that §6.3 knob-staleness invalidation had already
  deleted. Its own non-empty positive control is what surfaced this rather than
  a silent pass.

### Added

- **`make verify`** — one target running all six gates, and
  `tools/build_release.sh` now runs *that* inside the extracted tarball rather
  than its own hand-copied list, which had already drifted to four of six.
  A release can no longer be cut past a red gate: demonstrated both directions
  against real tags. Six of the seven gates #119 lists; `bench-check` needs the
  on-target harness and is deliberately excluded.
- **`make verify-label-hygiene`** (#117) — rejects synthesised macro-local
  names and any label name outside the consumer charset, across six
  configurations — five shipped plus the one `c64-wireguard` actually builds.
  Each absence check sits behind positive controls that are themselves
  demonstrated capable of failing: for a label file, readable / non-empty /
  sentinel present / extracted-name count reconciles against the raw line
  count; for an object, readable / non-empty / sentinel present. A run that
  examines nothing fails rather than reporting success.
- **Gate coverage for configurations nobody was building** (#122): the
  configuration `c64-wireguard` actually builds, each §8 deferral switch alone,
  and the two footprint axes `lib_manifest.s` models nowhere —
  `POLY1305_MULTIPLY_ROLLED` and `CHACHA20_USE_WORD32`. Eleven footprint legs,
  up from six.

## Footprint

Unchanged except the one corrected figure above. `verify-resident-bytes` now
checks eleven configurations rather than six, including the consumer's own.

## Contract conformance

**Span unchanged at SPEC v1.2.2**, which is still the latest tag. No clause
moved that affects this library.

`c64-lib-contract` PR #200, **unmerged at this tag**, would change §5's
footprint *measurand* by excluding the per-segment start charge as the
consumer's. This release measures on the current basis — od65 sum + fragment
fill + a 255 B per-aligned-segment start charge — because that is the only
tagged one. Under the proposed basis the #126 configuration would not have been
under-declared; the correction to 17920 is safe under both. When that clause
tags, the change here is to `tools/measure_resident_bytes.py`, not to any
declared literal.

## Verification

`make verify` green: all six gates, serial and `-j8`. Six of the seven gates
#119 enumerated — `bench-check` is deliberately out, because it needs the
c64-test harness and a VICE or hardware target, so it can live in neither a
toolchain-only umbrella nor the release tarball. Each gate independently
demonstrated capable of failing. `make dist` runs the same umbrella inside the
extracted tarball.
