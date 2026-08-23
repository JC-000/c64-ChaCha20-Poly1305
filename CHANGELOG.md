# Changelog

All notable changes to this project are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **A `CONTRACT_DEFINES` change did not invalidate the object cache**
  (issue #86; contract SPEC v0.10.5 §6.3). The knobs reach every `ca65`
  invocation through `CA65FLAGS`, but they reach no make *prerequisite*,
  so the cache is keyed on source mtimes alone. A re-invocation with
  different knobs reused every stale object, answered `Nothing to be
  done`, exited 0 — and shipped the archive built with the *previous*
  knobs. Measured: `make lib CONTRACT_DEFINES="-D
  POLY1305_PROFILE_LONG=1"` over a default tree left the Profile B
  archive in place (18 `_PRECALC_` exports, not Profile A's 24), while
  the same command against a clean `build/lib` correctly built Profile A.

  This is §6.3's shape-3 "silent no-op", the least visible rung of the
  looks-reachable ladder: every command is documented, the exit code is
  zero, and the artifact is a perfectly *coherent* archive — just not the
  one requested. §6.3 ¶1 reachability was never in question here; the
  axis is genuinely define-reachable from a clean tree.

  Scope was wider than the profile knob, which is only the sharpest
  demonstration because the difference is legible in the manifest: every
  §6.2 knob rode the same hole, including `LIB_NO_BARE_EXPORTS` — the
  suppression contract §1 points at for the [#43]-class duplicate-symbol
  failures — and `LIB_SHARED_SQTAB_BASE`, where the stale value is a
  wrong *address* for the §8.1 window. The named variant targets were
  never affected in their own axis: `lib-aead-only` and `lib-app-owned`
  each own a separate objects dir, so their defines are part of the path.

  Fix is the `c64-nist-curves` `CONTRACT_STAMP` idiom, widened from that
  repo's flat `$(BUILD_DIR)/*.o` to a `find` because our objects live in
  seven per-profile and per-variant directories: the flattened knob
  string is recorded in `build/.contract-defines.stamp` at parse time,
  and a change invalidates every object and archive — the knobs reach
  every TU, so every object genuinely *is* stale. Unchanged knobs leave
  the tree alone, so same-knob incremental builds stay incremental.

  Build-system only: both PRGs are byte-identical across the fix
  (`29567114…` / `6e9a989f…`, rebuilt from separate worktrees — linked
  output is the sound comparand per §6.3's checkability note, never
  `.o`/`.a` bytes, which carry `ca65`'s `OPT_DATETIME`).

### Added
- **`make verify-knob-staleness`** — mechanical pin for the guard above,
  in the manner of `lib-verify-shared` and `verify-zp-usage`. Four legs,
  all four required: a knob change rebuilds *and* the artifact flips
  profile; the same knob again is incremental; reverting rebuilds back.
  Legs 3 and 4 are what separate a staleness check from an
  unconditional rebuild, which would pass the first two. Verified
  non-vacuous — it fails on the pre-fix `Makefile` with the three
  expected failures. Runs against a throwaway copy of `Makefile` +
  `src/` so it does not cost the caller their per-profile object cache.

### Contract conformance — span extended to SPEC v0.11.1
The v0.9.0 record ran to **v0.10.3**. Findings for the six revisions
since, in order:

- **v0.10.4** (§6.3 posture scoped to define-reachable combinations;
  documented member-set axes take a §6.1 target) — no-op. Profile A/B
  differ by assembly configuration only, not member set: `LIB_MODULES`
  is one list, so the axis rides §6.2 defines as the clause intends and
  needs no target of its own. The two member-set-shaped axes
  (`aead-only`, `app-owned`) already have §6.1 targets.
- **v0.10.5** (looks-reachable; a knob naming an axis MUST select it or
  fail loudly) — **was not satisfied**; closed by issue #86 above. The
  knob-naming half is vacuous here (there is no `PROFILE=`-style make
  variable — the profile rides `CONTRACT_DEFINES` directly); the
  staleness half was live.
- **v0.10.6** (§8.3 provider surface enumerated; a deferral switch MUST
  leave `.import`s behind) — already conformant, and already pinned.
  `src/lib/poly1305_lib.s` exports all five names when it provides
  (`ct_mul_8x8`, `smc_sum_a_imm`, `smc_diff_a_imm`, `poly_prod_lo`,
  `poly_prod_hi`) and imports all five under `SHARED_CT_MUL_8X8`;
  `make lib-verify-shared` checks both directions. No change.
- **v0.10.7** (`mlkem_` registered to `c64-mlkem`) — no-op. Additive
  registry row; no collision with this library's six registered
  prefixes.
- **v0.11.0** (zero-consumer carve-outs in §1 and §6.5) — **inapplicable
  to this library, deliberately.** Both are scoped to a library with no
  released consumers, and this one has one: `c64-wireguard` `v1.0.0`
  pins `libs/chacha20poly1305` at `4a7f225`, which is this repo's
  `v0.6.0` tag (verified at the ref, not from `consumers.md`). So §1's
  `MUST also export` the deprecated bare version forms still binds —
  they stay, gated on `LIB_NO_BARE_EXPORTS` — and the `lib_version.o` /
  `lib_manifest.o` member basenames stay on §6.5's MAJOR path rather
  than being born prefixed. Recorded so the next reader does not
  re-derive it from the carve-out text alone.
- **v0.11.1** (§6.3 states which consequence its select-or-reject rule
  carries in which case) — **already satisfied, by the work in this same
  release.** The clause splits on whether the target can honor the knob: a
  value it *cannot* honor is rejected at parse time, one it *can* honor
  must invalidate whatever it reconfigures. This library has no member-set
  axis reachable through `CONTRACT_DEFINES` — the three variants carry
  identical seven-object member sets and differ only by `-D` — so the
  rejection branch is vacuous here and the invalidation branch is the
  whole obligation. That is the `CONTRACT_STAMP` guard above, and both of
  the clause's load-bearing guard properties are pinned by `make
  verify-knob-staleness`: unchanged knobs must not rebuild (leg 3) and the
  check must assert the artifact flipped rather than that something
  rebuilt (legs 2 and 4). The clause cites this library's issue #86 as its
  motivating measurement.

  **Citing it is not yet possible at a tag.** SPEC v0.11.1 is on the
  contract's `main` (`f21db36`) and untagged, and §12 versions are citable
  only at tags — the contract's own README banner flags this. So this
  record cites `main`; it should be re-pointed at `v0.11.1` once that tag
  exists, and this library's next release notes are the natural place to
  do it.


## [0.9.0] — 2026-08-15

Hardening release: a link-time guard against a silent sqtab-corruption
mode, a drift ratchet for the hand-maintained `ZP_USAGE_BYTES` equate,
and a clause-by-clause conformance record against `c64-lib-contract`
**v0.10.3**.

**Nothing breaks.** Both PRGs are byte-identical to v0.8.0
(`52b87cdf…` / `dd043279…`), the exported surface is identical (95
symbols, diffed), footprints are unchanged in every (profile × variant)
combination, and `ABI_VERSION` stays **3**.

MINOR on one trigger: `make verify-zp-usage` is a new make target, which
§6.5 makes contract surface and §7 classifies as additive.

See [`docs/RELEASE_NOTES_v0.9.0.md`](docs/RELEASE_NOTES_v0.9.0.md).

### Fixed
- **Release tarball omitted `src/include/sqtab_base.inc`** — a clean
  extraction could not build the library. `tools/build_release.sh` ships
  an explicit path allowlist, and the file added by issue #80 was never
  added to it. The failure was partial and therefore easy to miss:
  Profile A builds fine (it includes no sqtab), so only `make lib` and
  `make profile-b` failed, with `Cannot open include file
  'sqtab_base.inc'`.

  Caught by the clean-extraction check in the release procedure, before
  any release was published.

  Also added, same cause: `tools/verify_zp_usage.py` (so
  `make verify-zp-usage` works from a tarball), `docs/precalc-tables.md`
  (the §8.4 doc half — the clause requires both the doc and the macro),
  and `docs/REPRO_CHECK.md` (linked from every release-notes file).

- **`build_release.sh` now ratchets its own manifest.** An allowlist is
  the right shape for a reproducible tarball, but it fails *silently*
  when a source grows a new dependency. The script now extracts what it
  just built and verifies the shipped tree closes over its own
  `.include` graph, plus that every tool a supported target invokes is
  present; on a gap it names the missing file and deletes the tarball
  rather than leaving a broken artifact behind.

  Verified by seeding the original omission — it now fails with
  `MANIFEST ERROR: a shipped source .include's 'sqtab_base.inc'`.

  The tools check is deliberately scoped: `bench_granular.py` and
  `build_release.sh` itself are correctly absent from a source tarball
  (the bench targets need the unshipped test harness, and re-rolling a
  release from inside a release tarball is not a supported operation).


### Added
- **§6.7 image guard for the equate-placed sqtab window** (issue #80;
  contract v0.10.0 §6.7, corrected by v0.10.2). `src/c64.cfg`'s `MAIN`
  now publishes its extent via `define = yes`, and `src/main.s` — which
  ships in no archive — asserts `__MAIN_LAST__ <= LIB_SHARED_SQTAB_BASE`.

  `MAIN` spans `$0900–$9FFF`, which contains the `$8000` sqtab default.
  ld65 does not know the equate-placed window exists, so a growing
  segment could be placed across the table, link clean, and corrupt it at
  runtime with no diagnostic at any stage.

  The base is derived **source-level** through the new
  `src/include/sqtab_base.inc`, never `.import`ed — §8.1 forbids
  exporting `LIB_SHARED_SQTAB_BASE`. Holding the default in one shared
  include is itself a v0.10.2 MUST: two copies could silently disagree
  and the guard would then check a different window than the table
  occupies.

  Costs nothing — both profiles are byte-identical with and without it.

- **`make verify-zp-usage`** — the R2 exported-vs-summed ZP audit. The
  §5 `ZP_USAGE_BYTES` equate is a hand-maintained literal with nothing
  tying it to the actual `.exportzp` surface, so adding or widening a
  slot would leave it silently stale — and a consumer sizing its own ZP
  budget against a stale number is the failure this catches.

  It derives the occupied set from exported slot addresses in the built
  object (not from source text), and fails on three drift modes: an
  understated equate (§6.6 safe-direction), an exported slot with no
  declared width (uncounted, so usage is understated), and an unintended
  alias — two distinct slots sharing an address would shrink the union
  rather than fail, so aliases are checked by name.

  All three failure modes were verified by seeding them, not assumed.
  Current result: 24 exported names, 88 bytes occupied, equate 88, with
  every shared address an intended alias (four bare↔canonical §2 pairs
  plus `cc20_keystream`↔`cc20_work`). Profile A occupies 86, under the
  declared 88 — the equate is deliberately the A+B union.

  Not named `lib-*`: §6.1 reserves that namespace for archive-producing
  targets.

### Changed
- **Catch-loop citations follow the v0.10.3 heading split.** Contract
  v0.10.1 folded the precalc-table clause into §8.0 and v0.10.3 restored
  it as its own **§8.4** heading (reported as contract #109). Our
  references in `README.md`, `src/lib/lib_manifest.s` and
  `docs/precalc-tables.md` now cite §8.4.

  `src/precalc_table.inc` is deliberately **not** touched: it is a
  byte-identical copy of the contract's canonical file, which §8.4
  requires be copied verbatim and explicitly says not to edit locally.
  Its own header still cites §8.0 — that is upstream's to correct, and
  editing our copy would break the verbatim property the clause depends
  on.

- **README records contract conformance** against SPEC v0.10.3
  clause-by-clause, plus two standing obligations: `lib-verify-shared`
  is grandfathered in the §6.1 reserved `lib-*` namespace until the next
  MAJOR, and §6.6 requires release notes to state footprint deltas per
  (profile × variant).


## [0.8.0] — 2026-08-15

Contract-conformance release: `c64-lib-contract` v0.7.2 → **v0.9.2**.
Naming, packaging and manifest only — the default-build PRG is
**byte-identical to v0.7.0** (`52b87cdf…`), so measured performance is
unchanged and not re-measured.

Breaking for consumers on two axes: the four general-purpose ZP slot
names, and `LIB_CHACHA20_POLY1305_ABI_VERSION` 1 → **3**. See
[`docs/RELEASE_NOTES_v0.8.0.md`](docs/RELEASE_NOTES_v0.8.0.md) for the
migration steps.

### Changed
- **BREAKING — ZP slot names take the §2 registry prefix** (issue #76;
  SPEC v0.9.0 §2, gate added v0.9.1 §6.5). `zp_tmp1`, `zp_tmp2`,
  `zp_ptr1` and `zp_ptr2` become `chacha20poly1305_zp_*`. The bare
  spellings were unregistered general-purpose names that
  `c64-nist-curves` also exports, so linking the two libraries failed
  with `ld65: Error: Duplicate external identifier: 'zp_ptr2'` — and
  that error was the only thing standing between two libraries' live
  scratch and a silent address overlap.

  The bare names ship on as aliases for the §6.5 rename window and are
  removed at the next MAJOR. They sit behind `LIB_NO_BARE_EXPORTS`,
  which §6.5 names as the canonical gate for bare-name cases: an
  ungated alias would preserve the collision for the window's whole
  duration, leaving a composed link no better off than before. A
  consumer's deprecated-spelling override still works — `-D zp_tmp1=0x40`
  relocates the canonical slot (measured: canonical reads `0x40`).

  Gating **our** side is sufficient: our `zp_config.o` built with
  `-D LIB_NO_BARE_EXPORTS=1` links cleanly against an *unmodified*
  `c64-nist-curves` `zp_config.o`. The same pair without the flag still
  reproduces the duplicate-identifier error.

  **`LIB_CHACHA20_POLY1305_ABI_VERSION` is now 3.** Two reasons: the
  library's TUs `.importzp` the canonical names, so a consumer that
  supplied the bare slots from its own `zp_config` must export the
  canonical spellings or fail to link (`c64-wireguard` is in exactly
  this position); and under `LIB_NO_BARE_EXPORTS` the bare exports
  disappear, which is a removal from the surface a composing consumer
  sees.

  The rename is **codegen-neutral** — the test PRG is byte-identical
  before and after (`52b87cdf…`), so nothing about placement or timing
  moved.

### Added
- **Canonical archive basenames** (issue #76;
  [contract #76](https://github.com/JC-000/c64-lib-contract/issues/76)
  Gap 1, SPEC v0.9.0 §6.1). Archives are now written as
  `chacha20poly1305[-<variant>].a` — `<shortname>` being the §1 library
  prefix lowercased. The previous `c64-chacha20-poly1305*.a` spelling is
  a deprecated dialect under §6.1.

  Per the §6.5 rename window both names are produced for one MINOR
  release and the old form is dropped at the next MAJOR. The two files
  are byte-identical copies of the same `ar65` output — verified per
  build, not assumed — so either links to the same result. A filename,
  unlike an exported symbol, cannot collide at link time, so no
  opt-out define is needed.

  `test_consumer/` now links the canonical names, which is what
  demonstrates the migration rather than merely documenting it.

- **Build targets now accept consumer-supplied defines** (issue #74;
  [contract #76](https://github.com/JC-000/c64-lib-contract/issues/76)
  A.1). `CA65FLAGS` was hard-assigned, so a consumer following §2's
  normative `ca65 -D <slot>=$<addr>` had nowhere to put it — passing
  `CA65FLAGS` clobbered the include paths and failed with
  `Cannot open include file 'precalc_table.inc'`. §2's prescribed
  override was normative and unreachable here.

  Every target now forwards **`CONTRACT_DEFINES`** — the
  contract-normative spelling, so a multi-library consumer script uses
  one variable name across every library it builds. `EXTRA_CA65FLAGS`
  remains as a back-compat alias and is also appended.

  ```
  make lib CONTRACT_DEFINES="-D LIB_SHARED_SQTAB_BASE=0x9000"
  make lib-app-owned CONTRACT_DEFINES="-D LIB_NO_BARE_EXPORTS=1"
  ```

  One line, additive, and it makes every existing target
  defines-accepting at once. Overriding `CA65` still works but silently
  drops `-t c64 -g`; `CONTRACT_DEFINES` is the supported seam.

  **Documented with `0x` hex, not `$` hex** — measured, and the failure
  is silent. `-D LIB_SHARED_SQTAB_BASE=$9000` never reaches ca65 intact:
  the shell expands `$9` as a positional parameter, which is empty,
  leaving `-D ...=000` — **decimal zero**, with no error or warning. A
  consumer pasting it would place the 1 KB quarter-square table at
  `$0000`. ca65 accepts both spellings; only `0x` survives shell and
  make unquoted.

  **No `CONTRACT_ZP_DEFINES`**, deliberately: our archives ship no
  ZP-defining member — `src/zp_config.s` is excluded precisely so
  consumers assemble their own — so §2 slot overrides belong in that
  assembly rather than a forwarded define.

- **`make lib-app-owned`** → `build/lib/chacha20poly1305-app-owned.a`
  (issue #74; contract #76 A.2, [#72](https://github.com/JC-000/c64-lib-contract/issues/72)).
  The SPEC §8.0 `APP_OWNED` configuration: the consumer's own modules
  provide both shared primitives and this library defers both. Built with
  `SHARED_SQTAB_INIT` + `SHARED_CT_MUL_8X8`.

  Contract #76 counts **0 of 4 adopters** shipping such a target, which
  is what forces consumers into `ar65` member surgery — the practice that
  makes contract #72's manifest divergence reachable. Since #47 our
  deferral switches gate bodies, exports and manifest bits together, so
  the archive is truthful by construction:

  | archive | measured | `RESIDENT_BYTES` | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` |
  |---|---|---|---|---|
  | full | 16 838 B | 16 896 | `$0005` | `$0005` |
  | aead-only | 16 513 B | 16 640 | `$0005` | `$0005` |
  | **app-owned** | 16 582 B | 16 640 | **`$0000`** | **`$0005`** |

  That last row is §8.0's "deferring consumer" state — owns nothing,
  consumes both. Verified by linking the prebuilt archive against
  c64-x25519 as the §8.1/§8.3 provider: **links clean, both §8.0
  composition asserts satisfied, zero `ar65` surgery**, with `ct_mul_8x8`
  resolving to x25519's `mul_8x8.o` in the map.

  `RESIDENT_BYTES` gating extended to cover it, continuing #69's
  per-variant work.

### Fixed
- **Each archive's manifest now describes that archive** (issue #69;
  contract [#62](https://github.com/JC-000/c64-lib-contract/issues/62)).
  `RESIDENT_BYTES` was gated on the profile only, so the aead-only
  archive shipped a manifest describing the **full** build — reporting
  16 896 against a measured 16 513, a build the consumer had not linked.

  Now gated on `LIB_VARIANT_AEAD_ONLY` as well. All four configurations
  re-measured from the library's own segment sum and verified to
  over-report their own build by less than one page:

  | configuration | measured | `RESIDENT_BYTES` | headroom |
  |---|---|---|---|
  | Profile A full | 15 544 B | 15 616 | +72 |
  | Profile A aead-only | 15 219 B | 15 360 | +141 |
  | Profile B full | 16 838 B | 16 896 | +58 |
  | Profile B aead-only | 16 513 B | 16 640 | +127 |

  `AEAD_ONLY_RESIDENT_BYTES` is profile-aware for the same reason, so it
  reports the trimmed footprint of whichever profile is built. In an
  aead-only build it equals `RESIDENT_BYTES`; that redundancy is
  deliberate, since a consumer pinning the trimmed archive may import
  either name.

  Truthfulness rather than a bug fix: the old value **over**-reported,
  which is the safe direction for `.assert resident <= N`, and 383 B on
  16 513 is 2.3% — inside §5's own "within 5% is fine". A consumer
  asserting against the old figure still passes against the new, smaller
  one. It is fixed because §5 does not define
  `AEAD_ONLY_RESIDENT_BYTES`, so a consumer following the spec alone had
  no way to reach the accurate number.

### Fixed
- **§4 cfg declarations understated both the diagnostics and the `bss`
  consequence** (issue #71; contract v0.8.3). The v0.8.0 clause we wrote
  those declarations against carried a wrong risk assessment, corrected
  upstream after a `c64-nist-curves` report: **both placement
  diagnostics are conditional on the library's shape, not on the
  violation.**

  Re-measured against our own Profile B objects on ld65 V2.18:

  - The `bss` violation produces **no diagnostic at all** — not a
    warning, not an error. The bss warning keys on the segment's byte
    values, and `LIB_CHACHA20_POLY1305_DATA` is 19 `.res` reservations,
    so it vanishes silently. We previously said "no link error", which
    was true but understated.
  - 295 bytes leave the image either way, and the consequence depends
    on placement:

    | `_DATA` placement | effect |
    |---|---|
    | last in the file-emitting area (both our shipped cfgs) | addresses unchanged; `sqtab_ready` reads power-on garbage — the failure we documented |
    | anything file-emitting after it | every byte past the hole loads **295 B below** its linked address; `aead_encrypt` links at `$4824`, loads at `$46FD` |

    Only the first was documented. The second is what a consumer
    ordering segments differently would hit, and it can appear to work
    by coincidence when the absent content is zeros.
  - The alignment warning fires for us **because our sources carry
    `.align 256`** — ld65 checks the cfg against that directive, not
    against the missing attribute. Now stated, so the declaration stays
    correct if those tables ever stop using `.align`.

  Corrected in `src/c64.cfg`, `test_consumer/min_consumer.cfg`,
  `docs/INTEGRATION.md` and the `src/lib/data_lib.s` header. The
  `align = $100` and `type = rw` requirements themselves are unchanged
  and still correct — only the stated rationale and severity were wrong.

### Changed
- **`LIB_ABI_VERSION` 1 → 2** (issue #67; contract §1/§7 v0.7.5).
  `ABI_VERSION` is now a **monotonic generation counter** for the
  exported surface, independent of MAJOR — it "starts at 1 and
  increments on any breaking export change — a removed or renamed
  symbol, a changed calling convention, a changed memory model." The old
  "matches the MAJOR bump" rule was repudiated because §7 permits
  breaking changes on MINOR bumps pre-1.0, so MAJOR stays `0` across
  breakage and a consumer gating on it never fires.

  v0.7.0 removed two exported symbols (the §8.x bit constants, #57) and
  renamed every library segment (#48), but shipped the counter at 1
  under the then-current wording. That is a live gap, not a theoretical
  one: **`c64-wireguard/src/contract_asserts.s:66` imports this equate**
  as a breakage gate, and it read `1` on both sides of our most breaking
  release.

  Mitigating, and recorded so it isn't overstated: no consumer ever
  imported the removed bit constants — every apparent hit across the
  sibling repos was in a stale agent worktree referencing *x25519's*
  copy. The removal broke nobody; the defect is that the gate could not
  have said so.

  The **v0.7.0 tag is not retagged** and still reports 1. Generation 2
  describes that same surface and ships from `main` onward.

  **Consumer note:** a gate written as
  `.assert LIB_CHACHA20_POLY1305_ABI_VERSION = 1, lderror, "…"` will now
  fire. That is the intended behaviour — re-check the integration, then
  move the expected generation to 2.

  Because this changes an exported equate's value, the next tag is at
  minimum a MINOR bump, not a PATCH.

### Fixed
- **Published version-guard snippets could not assemble** (issue #68;
  contract §1 v0.8.1). All three used `.if` on an `.import`ed symbol.
  `.if` needs an assemble-time constant and an imported symbol has no
  value until link, so ca65 rejected the guard outright:

  ```
  guard.s(4): Error: Constant expression expected
  ```

  A consumer pasting it got a build failure, not a working check — worse
  than a guard that silently passes. Fixed at all three sites
  (`docs/API.md`, `src/lib_version.s` header, `README.md`) to the
  `.assert … , lderror, "…"` form, which defers evaluation to ld65, the
  only stage that knows the imported value. Verified both directions
  against the real `lib_version.o`: assembles and links clean against
  the shipped 0.7.0, and fires with the intended message when the floor
  is raised to 0.8.

  Our *logic* was already correct — `MAJOR = 0 .and MINOR < 7` has two
  boolean operands, so `.and` was right, unlike the SPEC's own example.
  Only the `.if` mechanism was fatal.

- **README drift from the v0.7.0 pass** (issue #68). Four corrections,
  each measured against a real build rather than re-derived:
  - manifest exports **seven** equates, not eight — the two §8.x bit
    constants stopped being exported in #57, and `SHARED_CONSUMES` was
    missing from the list entirely
  - `RESIDENT_BYTES` figures were the pre-v0.7.0 values (16384/17664/
    16384); they are now 15616/16896/16640 on the rebased basis
  - each enumerated table emits **six** `_PRECALC_` equates since
    contract v0.7.0 (prefixed + deprecated bare), not three; a default
    build surfaces 24 on Profile A and 18 on Profile B, dropping to 12
    and 9 under `-D LIB_NO_BARE_EXPORTS=1`. The stated Profile A count
    also predated #51's profile-gating of the `sqtab` row.
  - the audit grep is `_PRECALC_`, not `LIB_PRECALC_`, which misses
    every prefixed export; and `od65` cannot read `.a` archives

- **`test_consumer/min_consumer.cfg` now states the consequence** of
  getting `type = rw` wrong, not just the requirement (contract §4
  v0.8.0: "state the consequence, not just the requirement"). That file
  tells the reader to copy from it, so it is the one that travels.

### Fixed
- **`precalc_table.inc` re-copied from the v0.7.4 canonical** (issue #65).
  The §8.4 macro now pins the `_REGION` and `_SHARED` exports `: abs`, so
  they stop inferring `zeropage` from their byte-sized values and warning
  against a consumer's absolute `.import`:

  ```
  ld65: Warning: Address size mismatch for 'LIB_CHACHA20_POLY1305_PRECALC_sqtab_REGION'
  ```

  Same defect class as #62, but in the contract's **verbatim-copied
  canonical** rather than our own source, so it had to be fixed upstream
  first — which is why #62 deliberately left it alone while
  [c64-lib-contract#58](https://github.com/JC-000/c64-lib-contract/issues/58)
  was still open. This is a clean verbatim re-copy of contract `9da3aca`
  (SPEC v0.7.4); no local edits, no invocation changes.

  `_SIZE` is deliberately left unhinted upstream — its address size is
  value-dependent by design (absolute at 1024, far at 131072 for the §8.2
  REU table), so pinning it would break the large-table adopters.

  Measured: **2 warnings → 0** on our side, with the emitted equate sets
  otherwise unchanged (Profile B 9 prefixed / 9 bare, Profile A 12 / 12;
  bare suppressed under `LIB_NO_BARE_EXPORTS`). Both PRGs byte-identical.

  Note the composed link with c64-x25519 **v0.9.0 still emits 2
  warnings**, now entirely from its side — it has not yet re-copied the
  v0.7.4 canonical. Was 4 before this change.

## [0.7.0] — 2026-08-13

Contract-conformance release. Brings the library from c64-lib-contract
v0.4.0 up to **v0.7.2**, closing every open adopter gap: the SPEC §4
segment migration, a §8.3 deferral that was manifest-only, three
separate link-collision classes, and the v0.5.0 three-state
shared-primitive semantics. `src/lib_version.s` now declares 0.7.0.

Together these make the library composable with a sibling for the first
time: c64-wireguard could previously link this library alongside
c64-x25519 only by ceding the bare `CODE`/`DATA` segment names, carrying
a `sed` over the archive members, and verifying manifest values
out-of-band with `od65` because importing both manifests broke the link.
All three workarounds can now be dropped.

Semver: **MINOR** bump. Pre-1.0, so the breaking changes below are
allowed in MINOR (same basis as v0.6.0's removal of the `poly1305_reu_*`
surface). `LIB_ABI_VERSION` stays **1** in this tag, matching SPEC §1's
rule *as it read at release time* — that it tracks the MAJOR bump. Note
this is the most consumer-breaking release the library has had, and the
required actions are listed below rather than left to the section
detail.

> **Correction (2026-08-14, issue #67).** Contract v0.7.5 repudiated
> that rule — `ABI_VERSION` is a generation counter independent of
> MAJOR, incrementing on "a removed or renamed symbol". This release
> removed two exported symbols and renamed every library segment, so its
> surface is generation **2**. Corrected on `main`; this tag is not
> retagged and still reports 1.

### Consumer action required

1. **Add two segment declarations to your ld65 cfg.** The library no
   longer emits into bare `CODE`/`DATA`:

   ```
   LIB_CHACHA20_POLY1305_CODE: load = MAIN, type = ro, align = $100;
   LIB_CHACHA20_POLY1305_DATA: load = MAIN, type = rw;
   ```

   Both attributes are load-bearing and **fail silently** if omitted:
   `align = $100` is a constant-time invariant (ld65 only *warns* and
   links the secret-indexed LUTs misaligned), and `type = rw` in a
   file-emitting area is what makes `sqtab_ready` load as zero. ld65
   hard-errors if the segments are absent entirely.

2. **If you link this library alongside another**, build every library
   with `ca65 -D LIB_NO_BARE_EXPORTS=1` and import the `LIB_<X>_`-prefixed
   manifest equates. The unprefixed forms remain exported by default and
   are removed at contract v1.0.

3. **If you imported `LIB_SHARED_PRIMITIVES_SQTAB` or
   `LIB_SHARED_PRIMITIVES_CT_MUL_8X8`**, copy the equates locally
   instead — they are no longer exported (they never should have been;
   see **Fixed**).

4. **Re-check any `.assert LIB_CHACHA20_POLY1305_RESIDENT_BYTES <= N`.**
   The values are rebased onto a consumer-independent measurement and are
   now *smaller*; see **Changed**.

### Changed
- **`RESIDENT_BYTES` rebased onto a consumer-independent measurement.**
  Through v0.6.0 the basis was "PRG file size minus the 2-byte LOADADDR
  header", taken from `build/profile-*/*.prg`. That figure included
  things no consumer links — the harness `main.s` stub, the BASIC stub,
  and (after the §4 migration) 255 B of inter-segment pad — and it moved
  when the *test harness* layout changed, which is not a property of the
  library. By this release it had drifted into **under-reporting** the
  real consumer-side link, the dangerous direction for a
  `.assert resident <= N` fit check.

  The basis is now the library's own segment contribution
  (`LIB_CHACHA20_POLY1305_CODE` + `_DATA`, summed across the archive's
  member objects via `od65 --dump-segsize`), rounded up to the next
  256-byte boundary so the equate is always ≥ actual:

  | Build | measured | equate | was |
  |---|---|---|---|
  | Profile A | 15 544 B | **15 616** | 16 384 |
  | Profile B full | 16 838 B | **16 896** | 17 664 |
  | Profile B aead-only | 16 513 B | **16 640** | 16 384 |

  The values are *smaller* than before because the old basis counted
  harness overhead. Re-check any consumer assert pinned to the old
  numbers.

- **c64-lib-contract SPEC §4 segment migration** (issue #48). The library
  no longer emits into the bare ld65 `CODE` / `DATA` segments. All library
  code moves to `LIB_CHACHA20_POLY1305_CODE` and all library state to
  `LIB_CHACHA20_POLY1305_DATA` (`src/lib/{word32,chacha20,poly1305,
  chacha20poly1305,data}_lib.s`, 6 directives). `src/main.s` and
  `src/zp_config.s` keep plain segments — §4 governs library sources, and
  the harness `lib_entry` stub must stay at `$0900` for the BASIC stub's
  SYS 2304. This lets a consumer place library bytes by name with zero
  source patches; previously `c64-wireguard` had to cede the bare
  `CODE`/`DATA` names to this library and rename its own boot code out of
  `CODE`.

  **Consumer action required**: your ld65 cfg MUST declare the two new
  segments, and both attributes below are load-bearing —

  ```
  LIB_CHACHA20_POLY1305_CODE: load = MAIN, type = ro, align = $100;
  LIB_CHACHA20_POLY1305_DATA: load = MAIN, type = rw;
  ```

  `align = $100` is a **constant-time invariant** (the `chacha_nibswap_*`
  and `poly_reduce_shl6_tab` LUTs are `.align 256` and secret-indexed);
  ld65 only *warns* and links them misaligned if it is missing.
  `LIB_CHACHA20_POLY1305_DATA` must stay `type = rw` in a file-emitting
  area — `bss` writes no file bytes, so `sqtab_ready` reads power-on
  garbage and every Poly1305 multiplication is poisoned, with no link
  error. See `docs/INTEGRATION.md` "Library code + data".

  Proven a pure rename: linking the library objects alone under
  equivalent pre/post configs yields **byte-identical output** across all
  four build configurations (Profile A 15 911 B, Profile B 17 191 B,
  aead-only 16 935 B, rolled-outer 8 999 B), and per-object segment
  totals are conserved exactly (old `CODE` 15 250 B = 1 B harness stub +
  15 249 B library; `DATA` 295 B unchanged). Tests 214/214 on both
  profiles; both archive variants pass the `test_consumer` link + smoke.

  The in-tree standalone PRG grows +256 B on both profiles (Profile A
  16 168 → 16 424 B) — `main.s`'s 1-byte `lib_entry` stub holds `$0900`,
  so the page-aligned library segment starts at `$0A00`. That pad is an
  artifact of the test harness layout only; it is not in the shipped
  archives, and a consumer whose own `CODE` fills the gap pays nothing.

  `examples/smoke_test/` links a vendored v0.3.0 snapshot that predates
  the rename, so its cfg still uses bare `CODE`/`DATA` and is unchanged.

### Added
- **`LIB_CHACHA20_POLY1305_SHARED_CONSUMES`** (issue #52) — the companion
  mask contract v0.5.0 made mandatory for any adopter consuming a §8
  primitive. Ownership says what this build provides; consumes says what
  it uses, which is what distinguishes a *deferring consumer* (needs
  exactly one owner in the link, must be initialized at boot) from a
  *non-consumer* (no provider obligation). It unlocks the consumer-side
  coverage assert that turns a missing provider into a named assemble-time
  error instead of an unresolved external or a silent wrong result.

  | build | `SHARED_PRIMITIVES` | `SHARED_CONSUMES` |
  |---|---|---|
  | Profile A | `$0000` | `$0000` |
  | Profile B standalone | `$0005` | `$0005` |
  | Profile B `-D SHARED_CT_MUL_8X8=1` | `$0001` | `$0005` |
  | Profile B `-D SHARED_SQTAB_INIT=1` | `$0004` | `$0005` |
  | Profile B, both switches | `$0000` | `$0005` |

  `lib_manifest.s` also carries the §8.0 subset assert (`ownership ⊆
  consumes`), verified to fire with its named message when the issue-#51
  gate shape is re-seeded.

- **Library-prefixed §1 version exports + `LIB_NO_BARE_EXPORTS` gate**
  (issues #53, #57 item 1; contract v0.7.0). `src/lib_version.s` now
  exports `LIB_CHACHA20_POLY1305_VERSION_{MAJOR,MINOR,PATCH}` and
  `LIB_CHACHA20_POLY1305_ABI_VERSION`. The bare `LIB_VERSION_*` names are
  kept as **aliases** (still required through contract v0.x, removed at
  v1.0) and are suppressed under `ca65 -D LIB_NO_BARE_EXPORTS=1`, which a
  consumer applies to every library in the link. Aliasing rather than
  restating the literals means a release bump touches four lines and the
  forms cannot drift. §1's TU-isolation rule was already satisfied and is
  now stated in the file so it stays that way.

- **Library-prefixed §8.4 precalc equates** (issues #54, #57 item 3;
  contract v0.7.0). `src/precalc_table.inc` is re-copied **verbatim** from
  the contract canonical (`c64-lib-contract@62a5318`) and all five
  `LIB_PRECALC_TABLE` invocations pass the fifth library-prefix argument,
  emitting `LIB_CHACHA20_POLY1305_PRECALC_<name>_{SIZE,REGION,SHARED}`
  beside the gated bare triple. Table *names* stay unprefixed and
  normative — the prefix identifies the declaring library, never the
  table. This enables a cross-library check the bare form could not
  express, verified against c64-x25519 v0.8.0:

  ```asm
  .assert LIB_X25519_PRECALC_sqtab_SIZE = LIB_CHACHA20_POLY1305_PRECALC_sqtab_SIZE, lderror, "linked libraries disagree on the shared sqtab size"
  ```

- **`make lib-verify-shared`** — a §8.3 deferral-build linkage guard.
  Assembles `poly1305_lib.s` in owner and deferral configurations and
  pins the symbol surface each must present (owner exports all six §8.3
  names; the deferral build exports none and imports the five it
  references). Pure `od65` inspection, ~1 s, no emulator. Confirmed to
  fail with 11 named errors against the pre-#47 source.

### Fixed
- **`SHARED_CT_MUL_8X8` now actually defers the SPEC §8.3 primitive**
  (issue #47). The switch previously flipped only the manifest ownership
  bit: `poly1305_lib.s` kept exporting `poly_prod_lo` / `poly_prod_hi` /
  `mul_8x8` and kept emitting its own `ct_mul_8x8` body, so a two-archive
  link of a deferral build against c64-x25519 v0.8.0 — which exports the
  same names — died with
  `ld65: Error: Duplicate external identifier: 'poly_prod_hi'`.
  Reproduced, then fixed per SPEC §8.3 "Migration shape": under
  `-D SHARED_CT_MUL_8X8=1` the `ct_mul_8x8` body, the legacy `mul_8x8`
  body and the `poly_prod_lo`/`poly_prod_hi` scratch are all gated out,
  and `ct_mul_8x8`, `poly_prod_lo`, `poly_prod_hi`, `smc_sum_a_imm` and
  `smc_diff_a_imm` are imported from the designated owner instead.
  c64-wireguard can drop its staged-member workaround.

- **`ct_mul_8x8` is now exported**, making this library's §8.3
  canonical-owner claim satisfiable (issue #47). The manifest and
  `docs/API.md` have claimed the `$0004` ownership bit since PR #43, but
  `ct_mul_8x8` was a local label with no `.export`, so no sibling could
  actually defer *to* us. The `smc_sum_a_imm` / `smc_diff_a_imm` operand
  bake sites are exported alongside it (unsuffixed aliases of the SMC
  macro pack's `_SMC` labels, matching c64-x25519's spelling) — a caller
  patching our body needs them.

  Verified by building a composed PRG in which c64-x25519 v0.8.0 supplies
  both `ct_mul_8x8` and `mul_tables_init` and this library defers both:
  **214/214 tests pass** against that binary. All four default builds
  remain **byte-identical** to before the change.

- **Profile A no longer over-claims §8.0 shared-primitive ownership**
  (issue #51). `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES` was built with no
  profile gate, so Profile A advertised `$0005` — ownership of both the
  §8.1 `sqtab` and the §8.3 `ct_mul_8x8` — although issue #34 F1 gated
  sqtab, `sqtab_init` and `mul_8x8` out of Profile A entirely and the
  `ct_mul_8x8` body is Profile B only. Measured on the pre-fix tree:
  `profile-a/poly1305_lib.o` exports none of those symbols while
  `profile-a/lib_manifest.o` exported `$0005`.

  A consumer composing Profile A with c64-x25519 therefore hit the §8.0
  disjointness assert as a false double-ownership error, and the v0.5.0
  coverage assert concluded `sqtab` had an owner in the link when this
  library provides no `sqtab_init` at all — the silent-wrong-result
  direction (table read with no init). Profile A now reads `$0000`.

  The `LIB_PRECALC_TABLE "sqtab", ...` enumeration row is profile-gated
  for the same reason, so Profile A's `_PRECALC_` export count drops from
  15 to 12; it already omitted the Profile-A-only Shoup rows on Profile B.

- **§8.x bit constants are no longer exported** (issue #57 item 2). The
  two `.export LIB_SHARED_PRIMITIVES_{SQTAB,CT_MUL_8X8}:abs` lines emitted
  unprefixed names with identical values in every adopter, so linking with
  c64-x25519 died on `Duplicate external identifier:
  'LIB_SHARED_PRIMITIVES_CT_MUL_8X8'`. **No SPEC clause ever asked for
  this export** — and unlike the deprecated bare §1 names, the v0.7.0
  prefixing does not fix it, so it survived that migration. §8.1/§8.2/§8.3
  present the bit constants as plain local equates adopters copy verbatim
  (the v0.6.1 §13.0 clause states the reasoning outright for the analogous
  `NET_FAMILY_*` bits: only exported symbols can collide). They exist to
  *build* the two prefixed masks, which are the symbols meant to cross the
  link. c64-nist-curves has always kept them local, which is why the
  collision never surfaced there.

- **§5 aggregate equates exported `:abs`** (issue #62). The five §5
  exports carried no address-size hint, so ca65 inferred it from the
  *value* — `REU_BANKS_USED` (`$00`), `ZP_USAGE_BYTES` (88) and
  `COLD_BYTES` (0) came out `zeropage` while a consumer's `.import`
  defaults to absolute, warning three times in every composed link:

  ```
  ld65: Warning: Address size mismatch for 'LIB_CHACHA20_POLY1305_REU_BANKS_USED':
        Exported from lib_manifest.o as 'zeropage', import as 'absolute'
  ```

  Pre-existing, but only became reachable once #57's prefixed exports
  made these symbols importable at all. Noise rather than breakage — the
  values resolve and the asserts evaluate — but the diagnostic tracked
  the value rather than the interface (it would vanish if this library
  ever claimed an REU bank above `$FF`, and return if it dropped back),
  and the obvious consumer workaround, `.import ...: zeropage`, pins a
  manifest constant to an address size that is an artifact of its
  current value. Measured: 3 warnings before, **0** after.

- **Copy-paste-facing snippets corrected** (issue #55). `.and` → `&` in
  the REU-bank collision assert (`lib_manifest.s`): ca65's `.and` is
  *boolean*, so the published snippet was true whenever both masks were
  non-zero regardless of which bits were set — a real bank collision
  passed silently (contract v0.4.2). And `--asm-define` → `-D` at five
  sites (`Makefile`, `test_consumer/Makefile`, `poly1305_lib.s`,
  `docs/precalc-tables.md`, a historical `CHANGELOG.md` entry):
  `--asm-define` is `cl65`'s spelling and `ca65` rejects it outright with
  `Unknown option`, so every one of those snippets failed when copied
  (contract v0.7.1).

- **`make lib-verify-shared` hardened against a false-negative class**
  (contract v0.7.2). `od65` cannot read `.a` archives — pointed at one it
  prints `(no xo65 object file)` **and exits 0**, so a grep-based audit
  reports zero matches and looks like a clean pass. The target already
  read `.o` files, but its "must NOT export" checks would still have
  passed vacuously against an empty or unreadable dump. Each dump is now
  sentinel-checked for a symbol known to be present, so a broken dump
  fails loudly instead of reporting success. Verified by emptying a dump
  and confirming the sentinel fires.

## [0.6.0] — 2026-07-28

Portability + tooling + correctness release. Adopts the
c64-lib-contract consumer surface (exported version equates, the
`zp_config.s` ZP-config header, manifest equates, ar65 archive
variants, and the SPEC §8 shared-primitive clauses), adds a runtime
REU layout API for downstream coexistence, an n-sweep benchmark mode
for packet-size sensitivity work, and corrects a planning-doc claim
about REU/Shoup caching that doesn't survive the per-packet `r`
dependency. Minor `poly1305_final` loop fuse contributes a
consistent ~200 cy / packet on both profiles (below per-measurement
noise but signal across the 20-point sweep). Late in the cycle, the
issue #34 F1 slimming removes the entire `POLY1305_REU` path (and
with it the runtime REU layout API added above) — see **Removed**;
the rolled-multiply variants and the `lib-aead-only` archive then
close issue #34 outright (see **Added**). `src/lib_version.s` now
declares 0.6.0 (`LIB_ABI_VERSION` stays 1).

Semver: **MINOR** bump — additive export surface (`LIB_VERSION_*`,
manifest equates, variant build targets) plus removal of the
`poly1305_reu_*` surface (pre-1.0, removals allowed in MINOR).

### Removed
- **The `POLY1305_REU` path and Profile A's sqtab** (issue #34 F1,
  [PR #38](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/38),
  commit `88927aa`). The Step-11 incremental-ripple `shoup_init`
  populates `r_tab_lo/hi` without consuming the quarter-square
  table, so Profile A no longer emits `sqtab_lo/hi`, `sqtab_init`,
  or `mul_8x8`, and the REU stash had nothing left to stash. Gone
  with it: `poly1305_reu_restore`, the `poly1305_reu_sqtab_bank` /
  `poly1305_reu_sqtab_offset` runtime cells (added earlier in this
  same release cycle, issue #19), and the `POLY1305_REU` /
  `POLY1305_REU_BANK` / `POLY1305_REU_OFFSET` defines. **The
  library now issues no REU DMA on any code path in any profile**;
  `LIB_CHACHA20_POLY1305_REU_BANKS_USED` reads `$00`
  unconditionally, and `$8000..$83FF` is consumer-reclaimable on
  Profile A builds. Breaking for consumers of the removed symbols
  (flagged in `docs/INTEGRATION.md` §Stability); consumers that never defined
  `POLY1305_REU` are unaffected. Also removes any REU-DMA
  wall-clock floor on turbo hosts (issue #44 context): all hot
  paths now scale with CPU clock.

### Added
- **Turbo-scaling wall-clock sweep** (`tools/bench_turbo_sweep.py`,
  `docs/BENCH_TURBO_SWEEP.md`, issue #44). Benches the same PRG at
  1/16/48 MHz on Ultimate hardware via the existing CIA
  chained-timer wrapper (CIA ticks ≈ wall-clock µs regardless of
  turbo), with per-speed overhead recalibration and guaranteed
  1 MHz restore on exit. Measured Profile A `aead_encrypt` n=1024:
  16.0× at 16 MHz, 47.0× at 48 MHz (98% of ideal) — no
  speed-invariant floor, matching the zero-REU-DMA static audit.
  README gains a "Turbo hosts and REU-less machines" section making
  the no-REU/turbo story a first-class consumer property.
- **Granular per-symbol benchmark** (`tools/bench_granular.py`, `make
  bench`, `make bench-check`). Adds 14 per-routine cycle-count rows
  (chacha20_quarter_round, chacha20_block, chacha20_encrypt n=64/1024,
  poly1305_multiply, poly1305_reduce, poly1305_block,
  aead_compute_tag, aead_verify_tag, sqtab_init, ct_mul_8x8, plus
  aead_encrypt n=0/64/1024) so perf regressions can be attributed to
  a specific symbol. Reuses the existing CIA #1 Timer A+B 32-bit
  wrapper at `$C080` from `tools/benchmark_chacha20_poly1305.py`;
  `set_turbo_mhz(client, 1)` after reset on the U64 path. `make
  bench-check` diffs against a committed baseline JSON
  (`docs/BENCH_REPORT.baseline.json`) and exits non-zero on >1%
  drift. See `docs/BENCH_GRANULAR.md` for the methodology and
  reachability matrix.
- **Turbo-hygiene fix** in `tools/audit_cross_check.py`,
  `tools/ct_mul_brute_check.py`, `tools/test_chacha20_poly1305.py`:
  one-line `set_turbo_mhz(client, 1)` after `client.reset()` on the
  U64 path so a sibling agent's bench (at e.g. 48 MHz) cannot leak
  CIA-rate mismeasurement into these (non-timing-sensitive but
  device-sharing) tools, and vice versa.
- **Exported `LIB_VERSION_MAJOR` / `LIB_VERSION_MINOR` /
  `LIB_VERSION_PATCH` (plus `LIB_ABI_VERSION`) constants** in
  `src/lib_version.s`
  ([PR #30](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/30),
  issue #28). The value tracks the release — 0.6.0 as of this
  release — with `LIB_ABI_VERSION` at 1.
- **`CHACHA20_USE_WORD32` opt-in build-time define**
  ([PR #31](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/31),
  issue #27) — pointer-mode profile; default OFF preserves the
  existing codegen.
- **`src/zp_config.s` `.exportzp` ZP-config header**
  ([PR #32](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/32),
  issue #26). The ZP equates move out of `constants_lib.s` (which
  now `.importzp`s them) — a consumer-visible relocation mechanism
  and a new link-line object.
- **Manifest equates** (surviving set)
  ([PR #33](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/33),
  issue #29): `LIB_CHACHA20_POLY1305_ZP_USAGE_BYTES` and a
  profile-aware `RESIDENT_BYTES` equate. *Note: the REU-layout part
  of this PR was later removed by
  [PR #38](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/38)
  — see **Removed**.*
- **`make lib` / `make lib-aead-only` ar65 archive targets**
  ([PR #35](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/35),
  issue #34), per c64-lib-contract SPEC §6. Outputs
  `build/lib/c64-chacha20-poly1305.a` and
  `build/lib/c64-chacha20-poly1305-aead-only.a`; the
  `LIB_VARIANT_AEAD_ONLY=1` toggle strips test-only exports.
- **`POLY1305_MULTIPLY_ROLLED` / `POLY1305_MULTIPLY_ROLLED_OUTER`
  size↔cycles variants** (default off) plus `make profile-b-rolled`
  / `make profile-b-rolled-outer` targets
  ([PR #36](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/36),
  issue #34). Measured "config D": `make lib-aead-only` +
  `-DPOLY1305_MULTIPLY_ROLLED_OUTER=1` gives an 8,230 B linked
  consumer footprint (~3.8 KB under c64-wireguard's ~12 KB budget)
  at +4.08% cycles on `aead_encrypt` n=1024. This closed issue #34
  (2026-07-28).
- **c64-lib-contract SPEC §8.1 canonical sqtab adoption via
  `LIB_SHARED_SQTAB_BASE`**
  ([PR #39](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/39);
  follow-up SMC-operand fix in
  [PR #41](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/41)
  — see **Fixed**). The quarter-square table base becomes the
  contract's canonical consumer-overridable equate
  (`-D LIB_SHARED_SQTAB_BASE=0x<addr>`).
- **c64-lib-contract SPEC §8.3 `ct_mul_8x8` canonical-owner bit
  `$0004`**
  ([PR #43](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/43),
  issue #21), with a build-config-gated conditional mask:
  `LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES` defaults to `$0005`,
  and the `SHARED_SQTAB_INIT` / `SHARED_CT_MUL_8X8` deferral
  switches each drop their bit.
- **c64-lib-contract SPEC §8.0 catch-loop adoption**
  ([PR #42](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/42),
  commit `9e08f24`).
  Adds the canonical `LIB_PRECALC_TABLE` macro source to
  `src/precalc_table.inc` (copied verbatim from
  `c64-lib-contract@b039ab9` per SPEC §8.0 convention) and emits five
  macro invocations from `src/lib/lib_manifest.s` enumerating every
  precalculated table this library ships above the §8.0 floor (≥ 256 B
  AND one of: REU-resident / hot-loop-read / page-aligned). Profile A
  exports 15 `LIB_PRECALC_*` equates (5 tables × 3 each: `sqtab`,
  `chacha_nibswap_hi_tab`, `chacha_nibswap_lo_tab`, `r_tab_lo`,
  `r_tab_hi`); Profile B exports 9 (the three unconditional tables).
  Cross-adopter audit via
  `od65 --dump-exports build/profile-*/lib_manifest.o | grep LIB_PRECALC_`
  surfaces shape collisions that should promote to a §8.x shared-
  primitive clause. See [`docs/precalc-tables.md`](docs/precalc-tables.md)
  for per-table rationale and the below-floor exempt list. Makefile
  gains `-I src` so the manifest TU can `.include "precalc_table.inc"`
  without a relative path. No runtime behavior change; metadata only.
- **Runtime-configurable REU layout** (PR — sprint). Two new
  exported public RAM-backed symbols, both 8-bit cells in DATA:
  - `poly1305_reu_sqtab_bank` — REU bank for sqtab backup
  - `poly1305_reu_sqtab_offset` — 2-byte LE REU offset (lo, hi)
  Consumers may write to these cells *before* calling
  `poly1305_lib_init` to relocate the 1 KB sqtab backup region (e.g.,
  to coexist with c64-x25519 banks 0-1). Defaults remain `bank=0,
  offset=$0000`, baked at link time from the existing assemble-time
  defines (`POLY1305_REU_BANK` / `POLY1305_REU_OFFSET`), so existing
  consumers that never touch the cells get identical behavior to
  v0.5.0. *Note: removed later in this same release cycle along
  with the whole `POLY1305_REU` path — see **Removed** above.*
- **`--sweep` benchmark mode** in `tools/benchmark_chacha20_poly1305.py`
  (additive flag, doesn't break n=0/n=1024 single-shot mode). Sweeps
  `aead_encrypt` across n=[16, 32, 64, 128, 192, 256, 384, 512, 1024,
  1500] per profile, emits a markdown comparison table with the new
  `--sweep-md <path>` flag. Used to capture v0.5.0 baseline at
  `docs/BENCH_NSWEEP_v0.5.0.md` and resolve the previously-unmeasured
  short-packet regime.
- **`docs/BENCH_NSWEEP_v0.5.0.md`** — packet-size sweep baseline for
  v0.5.0 (commit `5bdf535`). Documents the Profile A / Profile B
  crossover point at **n ≈ 64** (Profile B wins at n=16-32, ties at
  n=64, loses badly beyond) — this replaces the README's previously
  documented "n ≥ 256" crossover claim, which the data does not
  support.

### Changed
- **`poly1305_final` (in `src/lib/poly1305_lib.s`) fuses the trailing
  `h += s` and tag-output loops** into a single 16-iteration loop
  (commit `fb314a9`). Eliminates one full loop's overhead plus a
  redundant `lda poly_h,x`. Measured `aead_encrypt` Profile A n=0
  −221 cy; n=1024 −167 cy. Profile B n=0 −227 cy; n=1024 −65 cy
  (in-noise). Constant-time preserved (straight-line, no
  data-dependent branches).
- **`chacha20_encrypt` register handling** (commit `f9f9c00`):
  drops the redundant `sta cc20_buf_pos` ahead of the XOR loop and
  drives the data-pointer ADC off `tya` from the in-flight loop
  counter. Cumulative ≈ −10 cy at n=1024 (below per-measurement
  noise; clean-up only).
- **PRG fingerprints update.** Reference builds at v0.6.0 HEAD:
  - profile-a: `79deb98c0028488f84278aa2ec645c9d` (16,168 B)
  - profile-b: `4afe54d466ad92ca38b91c94a2ea2b36` (17,448 B)
  The `LIB_VERSION_*` equate bump emits no bytes, so these match
  the post-[PR #41](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/41)
  fingerprints.

### Fixed
- **`ct_mul_8x8` SMC target-site operand is now derived from
  `sqtab_lo` / `sqtab_hi` equates** instead of literal `$8000` /
  `$8200` immediates (`src/lib/poly1305_lib.s`). The SMC *dispatch*
  (the hi-byte patch math driving `SMC_StoreHighByte smc_{lo,hi}_addr`)
  was already equate-driven via `lda #>sqtab_lo` /
  `adc #(>sqtab_hi - >sqtab_lo)`; only the *target site* (the
  `lda abs,x` placeholder bytes) still embedded the default base.
  Behavior is unchanged under documented use — `ct_mul_8x8` always
  patches the hi byte before the indexed load executes — but the
  static image was out of sync with a consumer override
  (`-D LIB_SHARED_SQTAB_BASE=0x<addr>`) until the patch ran.
  Defense in depth: assembled bytes are now `BD 00 <hi(sqtab_lo)>` /
  `BD 00 <hi(sqtab_hi)>` from the start. The fix itself changes no default-build bytes —
  fingerprints are identical before and after it within this release
  cycle (profile-a md5 `79deb98c…`, profile-b md5 `4afe54d4…`; both
  differ from v0.5.0's, which predate the PR #38 dead-code
  gating). 214/214
  tests pass on default profile-a, default profile-b, and an
  `LIB_SHARED_SQTAB_BASE=$7800` override build. Issue #40 audit
  follow-up
  ([PR #41](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/41)).
- **`docs/OPTIMIZATION_PLAN.md` retracts the "Optional Step 10 REU
  Shoup-table preload" claim** (commit `b3eac9b`). The original
  proposal conflated the r-independent quarter-square table (sqtab —
  legitimately REU-cacheable, already shipped via
  `poly1305_reu_restore`) with the r-dependent Shoup per-r tables
  (which must rebuild every packet because `poly_r` is derived per-
  packet from the ChaCha20 OTK keystream). RETRACTED blockquotes
  added inline at the three affected passages; original text kept
  visible behind strike-through for traceability. New "Lessons"
  subsection in §8 codifies the r-independent vs r-dependent rule
  for future REU work.

### Sprint findings (not code changes, but worth recording)
- **ChaCha20 perf ceiling effectively reached.** Two proposed
  optimizations — C9 rotl32_8 offset-rename and the
  rotl32_8 + rotr32_1 fusion at the rotl-7 site — targeted dead-code
  macros. `rotl32_8_zp` and several sibling macros are defined in
  `chacha20_lib.s` but never called from production; rot-8 / rot-16
  were absorbed into compile-time operand renames in commit
  `71fabf3` (C3, v0.3.0). Future analyses of ChaCha20 should
  verify call-site reachability before estimating cycle wins.
- **BSS is not zero-cleared in this project.** The c64.cfg layout
  declares `BSS` as `type=bss` without `fill`, so BSS values are
  load-image undefined. New state cells must live in `.segment
  "DATA"` with explicit `.byte` initializers; this is now the
  pattern for the new REU layout cells. Documented in `data_lib.s`
  header comments since at least v0.4.0.
- **A/B crossover at n ≈ 64**, not n=256 as previously documented.
  At n=16 Profile B is ~32% faster than Profile A (159 k vs 235 k
  cy); they're within 1% at n=64; Profile A pulls ahead by 49% at
  n=1024. For short-packet workloads (handshake, alerts, DTLS
  control), Profile B remains the better choice.

## [0.5.0] — 2026-05-15

Performance release: lands **C4 (branchless rotl-4 LUT)** on the
ChaCha20 quarter-round. Measured −8.8% on `chacha20_block`, flowing
through to −3.8% / −1.9% on `aead_encrypt n=1024` for Profile A /
B vs v0.4.0. Library PRGs change on both profiles — consumers
integrating PRG binaries directly should re-integrate; consumers
linking from source see the change automatically.

### Added
- **Two page-aligned 256-byte LUTs in `src/lib/data_lib.s`**
  (PR #24): `chacha_nibswap_hi_tab[V] = (V << 4) & $FF` and
  `chacha_nibswap_lo_tab[V] = V >> 4`. Both `.align 256` in a new
  `.segment "CODE"` block in `data_lib.s`. Used by the rewritten
  `rotl32_4_zp` macro to stitch the four-byte nibble rotate in
  straight-line code: `new_b_i = hi_tab[b_i] | lo_tab[b_{(i-1) mod 4}]`.

### Changed
- **`rotl32_4_zp` macro in `src/lib/chacha20_lib.s` rewritten as
  the C4 branchless LUT form** (PR #24). Replaces the prior
  asl/lsr/ora chain (~124 cy) with a straight-line stitch across
  the two new LUTs (~80 cy). Saves ~44 cy per call × 8 inlined
  sites in `chacha20_block`'s looped double-round body =
  −3 804 cy / `chacha20_block` (matches PR #22's predicted
  ~−3 520 cy; small overshoot from tighter register choice).
  Constant-time posture preserved: no data-dependent branches,
  `lda abs,x` against page-aligned tables eliminates the page-cross
  timing dependency on the secret index. The macro now also
  clobbers X (in addition to A and `zp_tmp1`); verified safe
  against all call sites in `cc20_qr_body_rest`.
- **Library PRG fingerprints updated.** v0.5.0 reference builds:
  - profile-a: `4da465a262d966059acc2038710fde87` (16 424 B,
    top CODE label `$4827`)
  - profile-b: `fbcc2d509335ff8a40b8607c7fd74837` (17 448 B,
    top CODE label `$4C27`)
  Both profiles remain under the `$5000` benchmark-plaintext-buffer
  floor. Size delta vs v0.4.0 is +685 B on both profiles: −128 B
  from the smaller `chacha20_block` body, +173 B of `.align 256`
  padding between `chacha20poly1305_lib.o` end and the new
  `data_lib.o` CODE additions, +512 B of LUT data.

### Performance

v0.5.0 cycle counts (CIA timer, 3 samples min per routine, identical
on VICE and Ultimate 64 within ±0.2%):

| routine                | v0.4.0   | v0.5.0   | Δ |
|------------------------|---------:|---------:|---:|
| `chacha20_block` (A/B) |   43 135 |   39 331 | **−8.8%** |
| `poly1305_block` (A)   |   11 948 |   11 951 | noise |
| `poly1305_block` (B)   |   37 844 |   37 950 | noise |
| `aead_encrypt n=0` (A) |  186 182 |  182 345 | −2.1% |
| `aead_encrypt n=0` (B) |   84 560 |   80 749 | −4.5% |
| `aead_encrypt n=1024` (A) | 1 686 764 | 1 623 299 | **−3.8%** |
| `aead_encrypt n=1024` (B) | 3 259 490 | 3 196 264 | **−1.9%** |

### Validation
- **214 / 214** RFC 7539 fixed-vector test suite passes on Ultimate
  64 (`C64_BACKEND=u64 python tools/test_chacha20_poly1305.py`).
  The rotation sub-group is **70 / 70** — load-bearing correctness
  check for the C4 macro (covers all 80 logical
  `rotl32_4_zp` invocations per `chacha20_block` via the dynamic
  `chacha20_quarter_round` test entry).
- Profile A and Profile B PRG fingerprints reproducible from clean
  checkout.

### Security
- **No CT posture regression.** The new macro has zero data-dependent
  branches; both LUTs are `.align 256` so `lda abs,x` against them
  is strictly constant-time. v0.4.0's GREEN audit verdict
  (F1/F2/F3 resolved) carries forward unchanged — C4 modifies only
  the ChaCha20 rotation primitive, which was already CT-clean in
  v0.4.0 via the asl/lsr/ora chain; the LUT form preserves that
  property by construction.

### Re-implementation history
- This release re-implements [PR #22](https://github.com/JC-000/c64-ChaCha20-Poly1305/pull/22),
  which had originally landed C4 but was closed unmerged with its
  head branch unrecoverable. The current implementation follows
  the spec from the closed PR (macro identity, LUT shapes,
  page-alignment rationale) but is byte-different from the lost
  binary — PR #22's predicted md5 fingerprints
  (`418ce549…` / `27a71517…`) reflected that PR's specific
  register/sequencing choices, not the spec itself. The 214-test
  suite is the load-bearing correctness check, and it passes
  cleanly on both profiles.

## [0.4.0] — 2026-05-10

First release with **Ultimate 64 (U64) hardware backend support** for
the validation tooling. The four tooling scripts under `tools/`
(`test_chacha20_poly1305.py`, `audit_cross_check.py`,
`ct_mul_brute_check.py`, `benchmark_chacha20_poly1305.py`) now route
all 6502 `jsr` calls through a backend-agnostic shim, so the same
test/audit/bench flows that ran on VICE in v0.3.x now also run on a
real Ultimate 64 over the network at full silicon speed. Library
PRGs (`build/c64_chacha20_poly1305.prg`) are unchanged on both
profiles — the changes are entirely in the Python tooling and in two
ca65 source equates that make the Profile A REU stash destination
configurable.

### Added
- **U64 backend across the four tooling scripts.** All four
  `tools/*.py` scripts now select VICE or Ultimate 64 at runtime via
  `C64_BACKEND={vice|u64}` (and `U64_HOST=<ip-or-hostname>` for U64).
  VICE remains the default; existing flows are unaffected. Tested on
  Ultimate 64 Elite firmware 3.14d at `10.43.23.81`.
- **Backend-agnostic shim at `tools/_u64_helpers.py`.** New
  `run_subroutine(manager, addr)` and `measure_cycles(manager, addr)`
  helpers that dispatch on the underlying transport: on VICE they
  call `c64_test_harness.execute.jsr` directly; on U64 they drive a
  small trampoline at `$0360..$0377` that wraps `jsr <target>` with
  a sentinel-write + status flag + re-arm flag, polled by the host
  over the U64 control socket. `measure_cycles` returns true cycle
  counts on both backends via the existing CIA-timer wrapper.
- **`audit_cross_check.py --vectors N` CLI flag** for runtime
  budgeting. Defaults to the v0.3.x value of 15 000 vectors per
  profile. The U64 acceptance gate runs at `--vectors 1000` to fit a
  ~20 min walltime; see harness issue
  [#82](https://github.com/JC-000/c64-test-harness/issues/82).
- **`benchmark_chacha20_poly1305.py --backend` CLI flag.** Was
  previously hardcoded to `vice`; now accepts `vice` or `u64` and
  defaults to whatever `C64_BACKEND` selects (VICE if unset).
- **Configurable REU destination for Profile A sqtab backup**
  (issue #19). Two new `.ifndef`-guarded equates in
  `src/lib/constants_lib.s` — `POLY1305_REU_BANK` (default `0`) and
  `POLY1305_REU_OFFSET` (default `$0000`) — let downstream projects
  relocate the 1 KB quarter-square table that `poly1305_lib_init`
  stashes to REU under `POLY1305_REU=1`. Motivating use case:
  co-installing this library with `c64-x25519`, which already
  occupies REU banks 0-1. Override at assemble time via
  `ca65 -D POLY1305_REU_BANK=3
  -D POLY1305_REU_OFFSET=$1000`, or by `.include`'ing a
  project-wide layout header that defines them before
  `constants_lib.s` is included. The equates are gated on
  `POLY1305_PROFILE_LONG` + `POLY1305_REU`, so Profile B and non-REU
  Profile A builds are unaffected.

### Changed
- **`test_chacha20_poly1305`, `audit_cross_check`, `ct_mul_brute_check`,
  `benchmark_chacha20_poly1305` route their JSRs through the
  backend-agnostic shim** instead of calling
  `c64_test_harness.execute.jsr` directly. The `tools/` flows pick
  up VICE or U64 transparently from `C64_BACKEND` / `U64_HOST` with
  no per-test code changes.
- **Bench cycle measurement reworked.** VICE keeps the existing
  CIA-timer wrapper unchanged; U64 reuses the same wrapper via the
  shim, with a tolerance-window wrapper-verify (`501 ± jitter` on
  VICE, `501 ± max(spread, 50)` on U64) sourced from the bench's own
  calibration data. This absorbs the few-cycle silicon jitter
  observed on real U64 hardware without weakening the VICE gate.
- **Profile A + `POLY1305_REU=1` PRG grows by 8 bytes** at default
  equates (issue #19). The compact 11-byte `lda #$00 / sta $DF04 /
  sta $DF05 / sta $DF06` sequence inside `poly1305_lib_init`'s
  stash block and `poly1305_reu_restore` is now a 15-byte
  override-aware form (`lda #<POLY1305_REU_OFFSET` / `sta $DF04` /
  `lda #>POLY1305_REU_OFFSET` / `sta $DF05` /
  `lda #POLY1305_REU_BANK` / `sta $DF06`) because the three DMA
  register destinations no longer share a value. +4 bytes per block
  × 2 blocks = 8 bytes total. The shift propagates through labels
  in `shoup_init`, `poly1305_clamp`, `sqtab_init`, and `mul_8x8`
  until the `.align 256` boundary at `poly_reduce_shl6_tab` ($1D00)
  absorbs it. Runtime semantics with default equates are unchanged.
- **Non-REU Profile A PRG is bit-identical to v0.3.1** (md5
  `313300ff4d86cefc6d3b195563c1383d` preserved). The new code lives
  entirely inside `.ifdef POLY1305_REU`, so the default `make
  profile-a` build does not touch it.

### Fixed
- **VICE 3.10 + macOS-26 autostart hang.** The default
  `-autostart` VirtualFS mode hangs in an IEC busy-wait on
  macOS-26 builds of VICE 3.10 when the harness pre-loads a PRG.
  All four `tools/*.py` scripts now pass `-autostartprgmode 1`
  (RAM-injection autostart), which sidesteps the IEC path entirely.
  No effect on Linux VICE flows.

### Validation
- **Acceptance gate on Ultimate 64 Elite (firmware 3.14d):**
  Profile A and Profile B fully GREEN under the standard
  `C64_BACKEND=u64 AUDIT_VECTORS=1000` baseline — 142/142 RFC 7539
  fixed vectors per profile; 1 000/1 000 random AEAD vectors per
  profile cross-checked against `pyca/cryptography`; 65 536/65 536
  exhaustive `(a, b)` pairs for `ct_mul_8x8`; bench cycle counts
  within ±0.2% of the v0.3.0 VICE baselines on every routine.
- **VICE 3.10 + macOS-26 quick-verification:** probe 4/4,
  `ct_mul_brute_check` 65 536/65 536, `test_chacha20_poly1305`
  Profile A + Profile B 142/142 each. (Test-runner exit codes are
  non-zero due to a harness teardown bug surfaced by this work,
  tracked at harness issue
  [#79](https://github.com/JC-000/c64-test-harness/issues/79); all
  crypto assertions pass before the teardown `AttributeError`.)

### Known limitations
- **Audit reduced from 15 000 → 1 000 vectors per profile** in the
  U64 acceptance gate, to fit a ~20 min walltime. VICE still runs
  the full 15 000. Rationale and follow-on harness work tracked at
  [#82](https://github.com/JC-000/c64-test-harness/issues/82).
- **VICE gate exit-code hygiene blocked on harness
  [#79](https://github.com/JC-000/c64-test-harness/issues/79).**
  Test-runner returns non-zero on Profile A/B suites due to an
  `AttributeError` in the harness teardown path, but every crypto
  assertion passes before the failure. Crypto correctness is
  verified; the exit-code cleanup is a downstream harness fix.

### Follow-on harness work
This release surfaced a portability backlog in the
`JC-000/c64-test-harness` package, filed as
[issues #76–#85](https://github.com/JC-000/c64-test-harness/issues?q=is%3Aissue+76..85).
Resolving these will let v0.5.x simplify the
`tools/_u64_helpers.py` shim and remove the harness-side
workarounds.

## [0.3.1] — 2026-04-14

A patch release on top of v0.3.0 covering two post-release polish
PRs plus a small set of distribution and documentation cleanups.
The shipped library binaries are **bit-identical to v0.3.0** on
both profiles; consumers who already integrate v0.3.0 PRGs need
not re-integrate for v0.3.1.

### Added
- **`LICENSE` at repo root — MIT** (Copyright © 2026 JC-000).
  Vendored third-party code under `src/include/` retains upstream
  licenses: `ca65hl/` MIT (Julian Terrell), `smc.inc` zlib license
  (Christian Krüger). README gains a short License section.

### Changed
- **SMC sites now use `src/include/smc.inc` macros** (PR #17).
  Five hand-rolled self-modifying-code sites have been converted to
  the matching `smc.inc` `SMC` / `SMC_StoreLowByte` /
  `SMC_StoreHighByte` / `SMC_StoreValue` macros: the two AEAD
  partial-block dispatch sites in `chacha20poly1305_lib.s`
  (`@partial_smc`, `@zfill_smc`); the Profile A `shoup_init`
  incremental Shoup-table build in `poly1305_lib.s` (six page-byte
  patches plus one immediate); and the two Profile B `ct_mul_8x8`
  primitive sites in `poly1305_lib.s` (the self-patched abs,x
  hi-byte patches inside the primitive and the J-outer immediate
  patches in `poly1305_multiply`). Placeholder bytes inside each
  `SMC label, { statement }` block are preserved literally
  (`#$00`, `lda $8000,x`, etc.), so the generated PRG is
  bit-identical to v0.3.0 on both profiles. The cosmetic benefit
  is removal of the `+1` / `+2` off-by-one footgun: future SMC
  edits select the operand byte by name instead of by hand-counted
  offset.

### Fixed
- **`tools/test_chacha20_poly1305.py` no longer destructively
  auto-rebuilds** (PR #16). The test harness previously ran
  `make clean && make` unconditionally at startup, which defaulted
  to Profile A regardless of which profile had been pre-built.
  This caused sequential in-session Profile A → Profile B
  test-then-bench flows to silently return wrong-profile numbers
  (a Profile B bench against a freshly-clobbered Profile A PRG).
  The harness now expects the caller to pre-build via
  `make profile-a` or `make profile-b` and fails loudly if
  `build/c64_chacha20_poly1305.prg` is missing. The
  `C64_SKIP_BUILD=1` environment variable is retained as a no-op
  for backward compatibility with consumer scripts that set it.
  Aligns the harness with the bench harness and `examples/smoke_test/`
  pre-build conventions.

### Docs
- `docs/INTEGRATION.md` (PR #16): added a "Testing from a
  consumer project" subsection documenting the pre-build
  convention shared by `tools/test_chacha20_poly1305.py`,
  `tools/benchmark_chacha20_poly1305.py`, and
  `examples/smoke_test/run_smoke_test.py`.
- `docs/OPTIMIZATION_PLAN.md` (PR #17): added a Task #9 row to
  the progression table and a note explaining the cosmetic
  refactor.

### Security
- **No security-relevant changes.** v0.3.0's constant-time posture
  (F1/F2/F3 resolved, GREEN audit verdict in `docs/AUDIT.md`) is
  unchanged. PRG binaries are bit-identical to v0.3.0; consumers
  that ship v0.3.0 binaries need not re-integrate for v0.3.1.

## [0.3.0] — 2026-04-13

First release of the library as an external-consumer target. Two
performance sprints (S1–S10, S11–S13) are now folded in, the build
system has moved from ACME to ca65, and the full audit documentation
set ships with the repository.

### Added
- ca65 + ld65 toolchain with per-module `.o` builds, replacing the
  monolithic ACME build. Both Profile A and Profile B link from the
  same object set via `src/c64.cfg`.
- `src/include/ca65hl/` (Movax12's ca65hl macro pack) and
  `src/include/smc.inc` (cc65's self-modifying-code helper) vendored
  onto the include path for downstream consumers.
- `examples/smoke_test/` — minimal external-consumer template showing
  the expected include order, ZP layout, and call sequence.
- `docs/AUDIT.md`, `docs/API.md`, `docs/MEMORY_MAP.md`,
  `docs/INTEGRATION.md` — consumer-facing documentation covering the
  per-branch constant-time audit, the public API, the fixed memory
  map, and the integration contract.
- `tools/audit_cross_check.py` — 30 000 random AEAD vectors
  (15 000 per profile) checked against
  `cryptography.hazmat.primitives.ciphers.aead.ChaCha20Poly1305`.
- `tools/ct_mul_brute_check.py` — exhaustive 65 536-pair
  brute-force correctness gate for the new `ct_mul_8x8` primitive
  introduced by the v0.3.0 CT fix.
- `docs/CT_ANALYSIS.md`, `docs/REPRO_CHECK.md`, and
  `docs/design/ct_mul_8x8.md` — per-branch CT audit, reproducibility
  record, and the design memo for the Profile B branchless multiply.
- Sprint-2 structural addition: `poly1305_lib_init` public one-time
  setup entry point (carried over from S10).

### Changed
- Profile A `shoup_init` — the 16 Shoup per-r tables are now built by
  a straight-line ripple-add (`T_j[k] = T_j[k-1] + r[j]`) instead of
  4 096 `mul_8x8` calls. This is the S11 change and collapses the
  per-packet `poly1305_init` fixed cost from ~438 k cy to ~118 k cy.
- Profile B `poly1305_multiply` — the schoolbook multiply primitive
  has been replaced by a new branchless constant-time 8×8 multiply
  `ct_mul_8x8` (v0.3.0 CT fix, commit `dc4c575`). The Step-12
  `mult66` primitive and its `sqtab2_lo/hi` companion tables at
  `$8400..$87FF` have been **removed**; Profile B now reuses the
  same 1 KB `sqtab_lo`/`sqtab_hi` that Profile A uses, driven via
  SMC-patched `abs,x` loads. The J-outer / I-inner loop reversal
  and 16-byte straight-line block-add (P7) from S12 are retained.
  See `docs/design/ct_mul_8x8.md` for the design memo.
- ChaCha20 `chacha20_block` — the 64-byte `state → work` copy prelude
  is now fully unrolled straight-line code (C8, S13), and the row-0
  words of the expand-32-byte-k constants are baked in as `lda #imm`
  / `adc #imm` in the prelude and the `work += state` tail (C5 sites
  1 + 3, S13). Site 2 (first column round a-operand bake) is deferred
  — see S13 notes in `docs/OPTIMIZATION_PLAN.md` for why.

### Performance (vs `v0.2-optimized`)

Measured on the merged v0.3.0 release-candidate commit `f4f049e`
via `tools/benchmark_chacha20_poly1305.py --seed 7539`, 3 samples,
min per routine. These numbers supersede every pre-CT-fix draft
figure: the CT fix reshaped the Profile B hot path (F3 resolution)
and contributed a small Profile A win (F2 resolution). See
`docs/REPRO_CHECK.md` §4 for the full post-CT-fix bench table.

| routine                            |   v0.2-optimized |           v0.3.0 |       Δ |
|------------------------------------|-----------------:|-----------------:|--------:|
| Profile A `chacha20_block`         |           44 920 |           43 135 | −4.0%   |
| Profile A `poly1305_block`         |           12 122 |           11 948 | −1.4%   |
| Profile A `aead_encrypt` n=0       |          579 280 |          186 182 | −67.9%  |
| Profile A `aead_encrypt` n=1024    |        2 197 974 |        1 686 764 | −23.3%  |
| Profile B `chacha20_block`         |           44 920 |           43 135 | −4.0%   |
| Profile B `poly1305_block`         |           38 760 |           37 844 | −2.4%   |
| Profile B `aead_encrypt` n=0       |           74 844 |           84 560 | +13.0%  |
| Profile B `aead_encrypt` n=1024    |        3 415 291 |        3 259 490 | −4.6%   |

Additional notes:
- The Profile A n=0 collapse is the S11 incremental Shoup build
  (~438 k → ~118 k cy per `poly1305_init`) plus the S10 sqtab
  one-time preload; the CT fix contributes only the `−877 cy`
  rot1 branchless win on top.
- Profile B `aead_encrypt` n=0 regresses **+13.0%** versus
  `v0.2-optimized`. Root cause: the F3 CT fix replaces the fast
  but CT-unsafe `mult66` primitive with the branchless
  `ct_mul_8x8` (see Security section below). This is a deliberate
  correctness-over-performance trade-off — Profile B still
  delivers **−45.4%** on `aead_encrypt` n=1024 versus the
  sprint-0 baseline (5 974 048 cy → 3 259 490 cy).
- Cumulative vs the S0 baseline (`923d34d`, pre-sprint),
  Profile A `aead_encrypt` n=1024 moved 5 974 048 → 1 686 764 cy,
  **−71.8%** over two sprints plus the CT fix.

### Security

The v0.3.0 release is the first with a completed per-branch
internal constant-time audit. See `docs/AUDIT.md` for the
top-level GREEN verdict and `docs/CT_ANALYSIS.md` for the full
per-branch analysis plus post-fix Resolution section.

Three pre-existing constant-time findings were discovered by the
audit and **resolved in this release** (PR #14, commit `dc4c575`):

- **F1 — `poly1305_final` h ≥ p branch.** The final reduction
  selected between `h` and `h − p` via a `bcs` branch on secret
  state. Fixed by replacing the branch with a branchless
  mask-blend: compute both candidates, derive a sign-mask from
  the borrow-out, and merge byte-by-byte. Affects both profiles.
- **F2 — `rotl32_1_zp` / `rotr32_1_zp` wrap branch.** The 32-bit
  single-bit rotates used a `bcc no_wrap` carry-propagation
  branch that took a data-dependent path on every word whose top
  bit was set. Fixed by rewriting as a branchless ASL/ROL chain.
  The two public labels were rewritten in place (not deleted)
  because `rotr32_7` falls through to `rotl32_1` and `rotl32_7`
  tail-calls `rotr32_1` via `jmp`. Affects both profiles. Bonus:
  the branchless rewrite is **faster** than the original
  (`chacha20_block` −1 346 cy per block).
- **F3 — Profile B `mult66` `(zp),y` secret-pointer load.** The
  Step-12 inner multiply loaded `r[j]+h[i]` through a
  `(zp),y`-style pointer whose effective address varied with
  secret data, producing address-dependent page-cross timing on
  certain operand combinations. Fixed by **structurally removing**
  `mult66` and its Step-12 `sqtab2` companion tables at
  `$8400..$87FF`, replacing them with a new branchless
  constant-time 8×8 multiply primitive `ct_mul_8x8` that uses
  the quarter-square identity with a sign-mask absolute-value
  step. All table loads are `abs,x` on page-aligned bases, so
  no secret-dependent addressing-mode timing remains. Profile B
  only. See `docs/design/ct_mul_8x8.md` for the design memo and
  the quantified perf/RAM trade-off.

### Validation

- **30 000 / 30 000** random AEAD vectors (15 000 per profile)
  cross-checked against `pyca/cryptography`'s reference
  `ChaCha20Poly1305` — all byte-identical
  (`tools/audit_cross_check.py`).
- **65 536 / 65 536** `(a, b)` pairs in `[0,255]²` brute-forced
  against Python's arbitrary-precision reference for the new
  `ct_mul_8x8` primitive — exhaustive correctness gate
  (`tools/ct_mul_brute_check.py`).
- **214 / 214** RFC 7539 fixed-vector test suite passes on both
  profiles at seed 7539.
- **Bit-for-bit reproducible PRG builds** across clean rebuild
  cycles (see `docs/REPRO_CHECK.md` §2).

This remains an internal audit rather than a third-party
security review. The library is still intended for hobbyist /
research use.

### API stability
- v0.3.x carries a backward-compatibility promise within the series:
  the public entry points (`aead_encrypt`, `aead_decrypt`,
  `poly1305_lib_init`) and the memory map documented in
  `docs/MEMORY_MAP.md` are fixed for the lifetime of v0.3.x.
- **v0.4.0 is a planned breaking release.** It will make the ZP
  slots and the table base addresses configurable via ca65 `-D`
  defines so that consumers can co-locate the library alongside
  their own code. Consumers that need address flexibility should
  expect to re-integrate at v0.4.0.

## [0.2-optimized] — 2026-04-11

Tagged from the commit that closes sprint 1 (steps S1–S8 plus the
S9 profile-documentation tag; S10 and the ca65 port landed after the
tag as pre-sprint-2 work).

### Added
- Dual build profiles. `make profile-a` targets Shoup per-r tables
  for long messages (WireGuard, TLS 1.3 records, >= 256 B amortized);
  `make profile-b` is the stock-C64 portable baseline that wins on
  short messages and zero-length AEAD.
- Profile A: 8 KB Shoup per-r table at `$6000..$7FFF`
  (16 × 2 × 256 B, page-aligned per limb).
- Profile A: REU-assisted sqtab backup (`POLY1305_REU=1`, S10).
- Per-packet AEAD glue fast paths: S8 A5 folds the OTK derivation
  into the encrypt/decrypt counter prime; A3 unrolls the zero-length
  branch; A4 adds an SMC dispatch for partial Poly1305 blocks; A6
  skips redundant re-init on decrypt.

### Changed
- ChaCha20 hot path: `cc20_work` moved to ZP (C1); all eight
  quarter-rounds of `chacha20_quarter_round` inlined into
  `chacha20_block` (C2); rot-8 and rot-16 reworked as offset renames
  (C3). `chacha20_block`: 149 987 → 44 920 cy, **−70.0%**.
- Poly1305 multiply: `poly1305_multiply` fully unrolled from its
  previous schoolbook loop (P1). Profile A: replaced with 272-entry
  Shoup per-r table lookup (P3). Both profiles: reduction rewritten
  as a single fused Donna-style wrap pass with a 256 B
  `poly_reduce_shl6_tab` (P4, the form that is realisable in
  byte-layout Poly1305).
- AEAD: `cc20_keystream = cc20_work` alias (C7), eliminating the
  64 B keystream copy per block.
- Sprint-1 sqtab-build move (S10): the quarter-square table is now
  built once at `poly1305_lib_init` time instead of per-packet,
  saving ~89 k cy per `aead_encrypt` call on both profiles.

### Performance (vs S0 baseline `923d34d`)
- Profile A `chacha20_block`: 149 987 → 44 920 cy (**−70.0%**).
- Profile A `poly1305_block`: 53 270 → 12 122 cy (**−77.2%**).
- Profile A `aead_encrypt` n=1024: 5 974 048 → 2 197 974 cy (**−63.2%**).
- Profile B `chacha20_block`: 149 987 → 44 920 cy (**−70.0%**).
- Profile B `poly1305_block`: 53 270 → 38 760 cy (**−27.2%**).
- Profile B `aead_encrypt` n=1024: 5 974 048 → 3 415 291 cy (**−42.8%**).

See `docs/OPTIMIZATION_PLAN.md` Section 8 for the full per-step
measurement table and the plan-vs-measured retrospective.

## [0.1] — 2026-04-11

### Added
- Initial release. Baseline scaffold, cycle-accurate benchmark harness,
  and independent pyca cross-check. (No tagged git release; date is
  taken from the first scaffold commit `602012e`.)
