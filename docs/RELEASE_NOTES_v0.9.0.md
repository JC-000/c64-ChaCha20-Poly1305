# c64-ChaCha20-Poly1305 v0.9.0 — Release Notes

Released 2026-08-15. Compared to v0.8.0 (same day).

Hardening release. It adds a link-time guard against a silent corruption
mode the previous release could not detect, a drift ratchet for a
hand-maintained manifest equate, and a clause-by-clause conformance
record against `c64-lib-contract` **v0.10.3**.

**No code changed, and nothing breaks.** Both profile PRGs are
byte-identical to v0.8.0 (`52b87cdf…` / `dd043279…`), the exported symbol
surface is identical (95 symbols, diffed), and footprints are unchanged
in every (profile × variant) combination. `LIB_CHACHA20_POLY1305_ABI_VERSION`
stays **3**.

Semver: **MINOR**, on one trigger — `make verify-zp-usage` is a new make
target, and §6.5 makes make-target names contract surface, which §7
classifies as additive. Nothing else in the release would have moved the
number.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md).

## Consumer migration

**None required.** No exported symbol, slot address, calling convention
or footprint changed. If you link v0.8.0 today, v0.9.0 is a drop-in.

Two things are worth adopting, neither mandatory:

**1. Mirror the sqtab image guard.** The §8.1 sqtab is placed by an
*equate*, so ld65 does not know the region exists — a memory area
spanning it will place growing segments straight across the table, link
clean, and corrupt it at runtime with no diagnostic at any stage. This
release guards the library's own image; your memory map is yours to
guard. See "Mirror the sqtab image guard" in
[`docs/INTEGRATION.md`](INTEGRATION.md) for the three-line pattern.

**2. Pin the ABI generation.** `.assert LIB_CHACHA20_POLY1305_ABI_VERSION
= 3, lderror, "…"` — `.assert`/`lderror`, never `.if`/`.error`, because
the operand is an import with no value until link.

The version-guard example in `src/lib_version.s` still reads `v0.8+`.
That is deliberate, not stale: v0.8.0 was the last release to change what
a consumer must do, so v0.8 remains the correct minimum. Bumping the
example every release would make it over-restrictive by habit.

## What's new

### §6.7 image guard for the equate-placed sqtab window (issue #80)

`src/c64.cfg`'s `MAIN` area spans `$0900–$9FFF`, which **contains** the
`$8000` sqtab default. Nothing prevented the image growing across the
table, and the failure would have been silent at every stage — no
assemble error, no link error, no warning, just a corrupted table at
runtime.

`MAIN` now publishes its extent via `define = yes`, and `src/main.s`
asserts `__MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE`.

Two details that make the guard trustworthy rather than merely present:

- The base is derived **source-level** through the new
  `src/include/sqtab_base.inc`, never `.import`ed — §8.1 forbids
  exporting `LIB_SHARED_SQTAB_BASE`. Holding the default in one shared
  include is a contract v0.10.2 MUST: two copies could silently
  disagree, and the guard would then check a different window than the
  table occupies.
- The guard lives in a TU that ships in **no** archive. That is a §6.7
  constraint, not a preference — an `.import __MAIN_LAST__` inside an
  archive member would force every consumer to declare a `MAIN` area
  with `define = yes` or eat an unresolved external.

Verified by seeding a violation, not by observing that it assembles:
`-D LIB_SHARED_SQTAB_BASE=0x1000` fails the link with the named error.
The boundary is exact to the page — image last `$4D27`, base `$4E00`
passes and `$4D00` fires. (Byte-exactness is not observable here because
§8.1 separately requires page alignment.)

Current headroom: Profile B's image ends at `$4D27`, leaving 13,017 bytes
before the window. Nothing was ever broken — but the headroom was
incidental rather than enforced, and now it is enforced.

### `make verify-zp-usage` — the R2 drift ratchet

`LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES` is a hand-maintained literal.
Nothing tied it to the actual `.exportzp` surface, so adding or widening
a slot would have left it silently stale — and a consumer sizing its own
zero-page budget against a stale number is exactly the failure the
equate exists to prevent.

The check derives truth from the **built object**, not source text: it
reads exported slot addresses out of `zp_config.o` via `od65`, maps each
to a declared width, unions the occupied addresses, and compares the
cardinality against the equate exported by `lib_manifest.o`.

Current result: 24 exported names, **88** bytes occupied, equate **88**.
Occupied runs `$02-$09`, `$14-$1F`, `$40-$7F`, `$FB-$FE`.

Three drift modes, each verified by seeding it:

| seeded | detected as |
|---|---|
| equate understated `88 → 80` | `equate 80 < actual 88` (§6.6 safe-direction) |
| exported slot with no declared width | `exported slots with no declared width` |
| unintended alias | checked by name |

The alias check earns its place: two distinct slots landing on one
address **shrink** the union rather than inflating it, so a total-only
comparison would pass while hiding a real collision. Aliases are
therefore checked by name — the four bare↔canonical §2 pairs plus
`cc20_keystream`↔`cc20_work` are the only ones permitted.

The `od65` dump is sentinel-checked: `od65` cannot read `.a` archives and
exits `0` on one, so an unchecked grep-based audit is indistinguishable
from a clean pass.

The target is deliberately **not** named `lib-*` — §6.1 reserves that
namespace for targets producing archives.

### Contract conformance record (SPEC v0.10.3)

The README now carries a clause-by-clause conformance table, audited by
measurement rather than inspection. §13 (network backend ABI) and §8.2
(`reu_mul`) do not apply.

It also records two standing obligations that would otherwise be lost
between releases:

- **§6.1** reserves the `lib-*` make-target namespace for
  archive-producing targets. `make lib-verify-shared` is a verification
  target and is grandfathered **until this library's next MAJOR**, when
  it must be renamed out of `lib-`.
- **§6.6** requires release notes to state footprint deltas per
  (profile × variant) — which is why the table below exists.

Citations now follow contract v0.10.3's heading split: the precalc
catch-loop clause is **§8.4**, not §8.0. `src/precalc_table.inc` is
deliberately untouched — it is byte-identical to the contract's canonical
file, which §8.4 requires be copied verbatim and which says not to edit
locally. Its header still cites §8.0; that is upstream's to fix, and
editing our copy would break the verbatim property.

### Release tarball manifest fixed and ratcheted

Found while verifying this very release: a clean extraction of the first
v0.9.0 tarball **could not build the library**. `tools/build_release.sh`
ships an explicit path allowlist, and `src/include/sqtab_base.inc` —
added by issue #80 in this same release — was never added to it.

The failure was partial, which is what made it dangerous: Profile A
builds clean because it includes no sqtab, so only `make lib` and
`make profile-b` broke. Checking only the default target would have
shipped it.

Three more files were omitted for the same reason and are now included:
`tools/verify_zp_usage.py`, `docs/precalc-tables.md` (§8.4 requires the
doc half, not just the macro) and `docs/REPRO_CHECK.md`.

The script now **ratchets its own manifest**: it extracts what it just
built, verifies the shipped tree closes over its own `.include` graph
and that every tool a supported target invokes is present, then names
the missing file and deletes the tarball rather than leaving a broken
artifact behind. Negative-tested by re-seeding the original omission.

The `v0.9.0` tag was moved onto the commit carrying this fix, so the tag
ships tooling that reproduces its own tarball. No release had been
published at that point and nothing had consumed the earlier tag.

## Footprint (§6.6, per profile × variant)

Every combination is unchanged from v0.8.0. Measured from each archive's
own manifest, not inferred.

| Profile | Variant | `RESIDENT_BYTES` | `COLD_BYTES` | Δ vs v0.8.0 |
|---|---|---:|---:|---:|
| A (`POLY1305_PROFILE_LONG=1`) | full | 15 616 | 0 | **0** |
| B | full | 16 896 | 0 | **0** |
| B | aead-only | 16 640 | 0 | **0** |
| B | app-owned | 16 640 | 0 | **0** |

`COLD_BYTES` is 0 across the board: this library has no
reclaimable-after-init region.

## Correctness

- Test suite **214/214 on both profiles** (VICE), including the 79
  pyca-cross-checked AEAD vectors.
- Both PRGs **byte-identical to v0.8.0** — `52b87cdf…` / `dd043279…`.
- Exported symbol surface **identical to v0.8.0** (95 symbols, diffed) —
  which is why the ABI generation does not move.
- Three archive variants build with **zero** ld65 warnings; canonical and
  deprecated basenames byte-identical.
- `make lib-verify-shared` OK; `make verify-zp-usage` OK.
- The §6.7 guard verified to **fire**, not merely to exist.

## Performance

**Unchanged, and not re-measured.** The PRGs are byte-identical to
v0.8.0, so cycle counts cannot differ. The v0.6.0 n-sweep measurements
([`BENCH_NSWEEP_v0.6.0.md`](BENCH_NSWEEP_v0.6.0.md),
[`BENCH_NSWEEP_u64_v0.6.0.md`](BENCH_NSWEEP_u64_v0.6.0.md)) still
describe this release.

## Source tarball

Built reproducibly via `tools/build_release.sh v0.9.0` (alias:
`make dist VERSION=v0.9.0`). `git archive` + `gzip -n -9` for
byte-identical output across re-runs. The recorded SHA256 is captured in
the GitHub release description.

The script requires the tag to exist and the matching
`docs/RELEASE_NOTES_v0.9.0.md` to be present *at* that tag, so the
tarball is produced after tagging, not before.

See [`REPRO_CHECK.md`](REPRO_CHECK.md) for the verification procedure.
