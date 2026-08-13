# c64-ChaCha20-Poly1305 v0.7.0 — Release Notes

Released 2026-08-13. Compared to v0.6.0 (2026-07-28).

Contract-conformance release. It brings the library from
`c64-lib-contract` v0.4.0 up to **v0.7.2** and closes every open adopter
gap — the SPEC §4 segment migration, a §8.3 deferral switch that turned
out to be manifest-only, three distinct link-collision classes, and the
v0.5.0 three-state shared-primitive semantics.

The point of all of it is composability. Before this release,
`c64-wireguard` could link this library alongside `c64-x25519` only by
(a) ceding the bare `CODE`/`DATA` segment names to us and renaming its
own boot code, (b) carrying a `sed` over our archive members to strip
colliding exports, and (c) verifying our manifest values out-of-band
with `od65`, because importing both libraries' manifests broke the link
outright. **All three workarounds can now be dropped.**

Semver: **MINOR** bump on the pre-1.0 scale — breaking changes are
permitted there, the same basis on which v0.6.0 removed the
`poly1305_reu_*` surface. `LIB_ABI_VERSION` stays **1**, per SPEC §1's
rule that it tracks the MAJOR bump. That said, this is the most
consumer-breaking release the library has had, so the required migration
steps are front-and-centre below rather than buried in the detail.

Default-build codegen is byte-for-byte unchanged and measured
performance is flat — see Performance.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md); this
file is the concise summary plus the reproducible-tarball record.

## Consumer migration

**1. Add two segment declarations to your ld65 cfg.** The library no
longer emits into bare `CODE`/`DATA`:

```
LIB_CHACHA20_POLY1305_CODE: load = MAIN, type = ro, align = $100;
LIB_CHACHA20_POLY1305_DATA: load = MAIN, type = rw;
```

ld65 hard-errors if the segments are missing entirely — but both
*attributes* fail **silently** if you drop them, so copy the lines
verbatim:

- `align = $100` is a **constant-time invariant**, not a perf hint.
  `data_lib.s`'s nibswap LUTs and `poly1305_lib.s`'s
  `poly_reduce_shl6_tab` are `.align 256` and indexed by secret-derived
  X/Y; without page alignment an `abs,x` page cross costs +1 cycle on a
  secret-dependent condition. ld65 emits only a *warning* and links them
  misaligned anyway.
- `LIB_CHACHA20_POLY1305_DATA` must be `type = rw` in a file-emitting
  area. `bss` writes no file bytes, so `poly1305_init`'s `sqtab_ready`
  gate reads power-on garbage, skips `sqtab_init`, and poisons every
  Poly1305 multiplication — with no link error.

Also declare bss-type segments **last** in the file-backed area: ld65
writes no file bytes for bss, so a file-emitting segment declared after
a non-empty `BSS` loads `__BSS_SIZE__` bytes below its linked address.

**2. Linking two or more libraries?** Build them all with
`ca65 -D LIB_NO_BARE_EXPORTS=1` and import the `LIB_<X>_`-prefixed
manifest equates. The unprefixed forms are still exported by default and
are removed at contract v1.0.

**3. If you imported the §8.x bit constants**
(`LIB_SHARED_PRIMITIVES_SQTAB` / `_CT_MUL_8X8`), copy the equates into
your own source instead — they are no longer exported.

**4. Re-check `.assert LIB_CHACHA20_POLY1305_RESIDENT_BYTES <= N`.** The
values are rebased and are now *smaller*; see below.

## What's new

### SPEC §4 segment naming (issue #48)

All library code moves to `LIB_CHACHA20_POLY1305_CODE` and all library
state to `LIB_CHACHA20_POLY1305_DATA`. `src/main.s` and
`src/zp_config.s` keep plain segments — §4 governs library sources, and
the harness `lib_entry` stub must hold `$0900` for the BASIC stub's
SYS 2304.

Proving it was a pure rename needed a different technique than the
sibling libraries used. c64-x25519 could show a byte-identical PRG; here
that is structurally impossible, because the 1-byte `lib_entry` stub
occupies `$0900` and so the page-aligned library segment can only begin
at `$0A00` — the standalone PRG necessarily gains 255 B of pad. Instead
the proof runs one level down: **the library objects linked alone**,
under pre/post configs that place them identically, are byte-identical
across all four build configurations, with per-object segment totals
conserved exactly (old `CODE` 15 250 B = 1 B harness stub + 15 249 B
library; `DATA` 295 B unchanged). That pad exists only in the in-tree
test PRG — it is not in the shipped archives.

### §8.3 deferral made real (issue #47)

`-D SHARED_CT_MUL_8X8=1` previously flipped only the manifest ownership
bit while the `ct_mul_8x8` body and the `mul_8x8` / `poly_prod_lo` /
`poly_prod_hi` exports stayed live, so a two-archive link against
c64-x25519 v0.8.0 died on `Duplicate external identifier:
'poly_prod_hi'`. The switch now gates the body and imports the five §8.3
names from the designated owner, per SPEC §8.3 "Migration shape".

`ct_mul_8x8` is also **exported** for the first time. The manifest has
claimed §8.3 canonical ownership since v0.6.0, but the body was a local
label with no `.export` — so no sibling could actually defer *to* this
library. The claim is now satisfiable.

### Three link-collision classes closed

| Collision | Fix | Covered by SPEC? |
|---|---|---|
| `poly_prod_hi` etc. under the deferral switch | gate bodies + exports (#47) | §8.3 |
| `LIB_VERSION_*`, `LIB_PRECALC_*` across two libraries | prefixed forms + `LIB_NO_BARE_EXPORTS` (#53/#54) | §1 / §8.4, v0.7.0 |
| `LIB_SHARED_PRIMITIVES_*` bit constants | stop exporting them (#57) | **no clause — found by measurement** |

The third is worth calling out: it is *not* covered by contract v0.7.0
and survives that migration, so prefixing alone would have left the
two-library link broken. §8.1/§8.2/§8.3 present the bit constants as
plain local equates that adopters copy verbatim, and the v0.6.1 §13.0
clause states the reasoning outright for the analogous `NET_FAMILY_*`
bits — only exported symbols can collide. c64-nist-curves had always
kept them local, which is why it never surfaced there. It has since been
codified upstream.

### v0.5.0 three-state shared-primitive semantics (issues #51, #52)

`LIB_CHACHA20_POLY1305_SHARED_CONSUMES` joins the ownership mask. The
pair distinguishes a *deferring consumer* — which still reads the
primitive and so needs exactly one owner in the link — from a
*non-consumer*, which needs no provider at all. The ownership bit alone
cannot tell those apart, and they impose opposite obligations.

Fixing this exposed a live defect: **Profile A was claiming ownership of
`$0005`** — both the §8.1 sqtab and the §8.3 `ct_mul_8x8` — although
issue #34 F1 had gated both out of that profile entirely. A consumer
composing Profile A with c64-x25519 saw a false double-ownership
collision, and the coverage assert concluded sqtab had an owner in the
link when this library provides no `sqtab_init` at all.

| Build | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` |
|---|---|---|
| Profile A | `$0000` | `$0000` |
| Profile B standalone | `$0005` | `$0005` |
| Profile B `-D SHARED_CT_MUL_8X8=1` | `$0001` | `$0005` |
| Profile B `-D SHARED_SQTAB_INIT=1` | `$0004` | `$0005` |
| Profile B, both switches | `$0000` | `$0005` |

### `make lib-verify-shared`

A §8.3 deferral-build linkage guard: it assembles `poly1305_lib.s` in
owner and deferral configurations and pins the symbol surface each must
present. Pure `od65` inspection, ~1 s, no emulator. Against the pre-#47
source it fails with 11 named errors.

It is also hardened against the failure mode contract v0.7.2 documents:
`od65` **cannot read `.a` archives** — pointed at one it prints
`(no xo65 object file)` and exits `0`, so a grep-based audit reports zero
matches and is indistinguishable from a clean pass. Every dump is
sentinel-checked so a broken dump fails loudly.

## Changed: `RESIDENT_BYTES` measurement basis

The equates now report the library's **own segment contribution**
(`LIB_CHACHA20_POLY1305_CODE` + `_DATA`, summed across the archive's
member objects), rounded up to the next 256-byte boundary.

| Build | measured | equate | was |
|---|---|---|---|
| Profile A | 15 544 B | **15 616** | 16 384 |
| Profile B full | 16 838 B | **16 896** | 17 664 |
| Profile B aead-only | 16 513 B | **16 640** | 16 384 |

The previous basis — whole-PRG size minus the load header — counted the
harness stub, the BASIC stub and the §4 inter-segment pad, none of which
a consumer links, and it moved when the *test harness* layout changed.
It had drifted into under-reporting the real consumer link, which is the
dangerous direction for a fit assert. The new numbers are smaller
because the old ones counted harness overhead.

## Performance

**Unchanged.** `make bench-check` passes all 14 rows within ±1%, the
largest drift being 0.016% (measurement noise):

| Symbol | v0.7.0 | baseline | Δ |
|---|---:|---:|---:|
| `chacha20_block` | 39,319 | 39,319 | 0.000% |
| `chacha20_encrypt n=1024` | 658,271 | 658,271 | 0.000% |
| `poly1305_block` | 37,897 | 37,891 | +0.016% |
| `ct_mul_8x8` | 101.4 | 101.4 | 0.000% |
| `aead_encrypt n=1024` | 3,195,713 | 3,195,710 | 0.000% |

This was worth confirming rather than assuming: the §4 migration shifted
every library instruction by 255 bytes, which could plausibly have moved
branches across page boundaries and cost cycles. It did not.

The v0.6.0 n-sweep measurements ([`BENCH_NSWEEP_v0.6.0.md`](BENCH_NSWEEP_v0.6.0.md),
[`BENCH_NSWEEP_u64_v0.6.0.md`](BENCH_NSWEEP_u64_v0.6.0.md)) therefore
still describe this release; they were not re-run.

## Correctness

- Test suite **214/214 on both profiles** (VICE), including the 79
  pyca-cross-checked AEAD vectors.
- Both archive variants link through `test_consumer/` and pass
  `run_aead_smoke.py`.
- The §8.3 deferral is verified **functionally**, not just at link time:
  a composed PRG in which c64-x25519 v0.8.0 supplies `ct_mul_8x8` and
  `mul_tables_init`, and this library defers both, passes 214/214. A
  link-only check would not have caught a calling-convention or
  scratch-placement mismatch.
- Six make targets build with zero ld65 warnings.

## Source tarball

Built reproducibly via `tools/build_release.sh v0.7.0` (alias:
`make dist VERSION=v0.7.0`). `git archive` + `gzip -n -9` for
byte-identical output across re-runs. The recorded SHA256 of the
v0.7.0 tarball is captured in the GitHub release description.

Note the script requires the tag to exist and the matching
`docs/RELEASE_NOTES_v0.7.0.md` to be present *at* that tag, so the
tarball is produced after tagging, not before.

See [`REPRO_CHECK.md`](REPRO_CHECK.md) for the verification procedure.
