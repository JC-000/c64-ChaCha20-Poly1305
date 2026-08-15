# c64-ChaCha20-Poly1305 v0.8.0 — Release Notes

Released 2026-08-15. Compared to v0.7.0 (2026-08-13).

Packaging-and-naming conformance release. It brings the library from
`c64-lib-contract` v0.7.2 up to **v0.9.2** and closes every open adopter
gap — the SPEC §2 ZP prefix registry, the §6.1 canonical archive
basenames, the §6.2 `CONTRACT_DEFINES` seam, the §6.3 app-owned archive,
per-variant manifests, and the v0.7.5 reclassification of
`ABI_VERSION` as a generation counter.

**No code changed.** The default-build PRG is byte-for-byte identical to
v0.7.0 — SHA256 `52b87cdf…` on both — so measured performance is
unchanged and was not re-measured. Everything below is names, packaging
and manifest values.

Semver: **MINOR** bump on the pre-1.0 scale, where §7 permits breaking
changes — the same basis as v0.7.0 and v0.6.0. Two breaking axes, both
front-and-centre below.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md); this
file is the concise summary plus the reproducible-tarball record.

## Consumer migration

**1. ZP slot names changed.** The four general-purpose slots are now:

| was | now |
|---|---|
| `zp_tmp1` | `chacha20poly1305_zp_tmp1` |
| `zp_tmp2` | `chacha20poly1305_zp_tmp2` |
| `zp_ptr1` | `chacha20poly1305_zp_ptr1` |
| `zp_ptr2` | `chacha20poly1305_zp_ptr2` |

The library's four *registered* prefixes — `cc20_`, `poly_`, `w32_`,
`ct_` — already conformed to the §2 registry and did **not** move.

What you have to do depends on how you supply the slots:

- **You assemble our `src/zp_config.s`** (the common case, and what
  `test_consumer/` and `examples/smoke_test/` do): nothing. The bare
  names are still exported as aliases.
- **You supply these slots from your own `zp_config`** — `c64-wireguard`
  does — you must export the canonical spellings, or the link fails with
  an unresolved external. Addresses are unchanged on both sides, so this
  is naming only:

  ```asm
  chacha20poly1305_zp_tmp1 = zp_tmp1
  chacha20poly1305_zp_tmp2 = zp_tmp2
  chacha20poly1305_zp_ptr1 = zp_ptr1
  chacha20poly1305_zp_ptr2 = zp_ptr2
  .exportzp chacha20poly1305_zp_tmp1, chacha20poly1305_zp_tmp2
  .exportzp chacha20poly1305_zp_ptr1, chacha20poly1305_zp_ptr2
  ```

- **You compose this library with another**: build with
  `-D LIB_NO_BARE_EXPORTS=1`, the same flag you already set for the §1
  version exports. That suppresses the deprecated bare aliases.

Slot overrides keep working in both spellings through the rename window:
`-D zp_tmp1=0x40` relocates the canonical slot exactly as
`-D chacha20poly1305_zp_tmp1=0x40` does.

**2. `LIB_CHACHA20_POLY1305_ABI_VERSION` is now 3** (was 1 at the v0.7.0
tag). If you pin it — `c64-wireguard/src/contract_asserts.s` does — the
assert fires until you update it. That is the gate working: the exported
surface genuinely changed.

**3. Archive basenames changed.** Link `chacha20poly1305.a` (or
`-aead-only` / `-app-owned`). The old `c64-chacha20-poly1305*.a` names
are still written for this release and are removed at the next MAJOR.

**4. Passing your own defines?** Use `CONTRACT_DEFINES`, and write hex
as `0x…`, never `$…`.

## What's new

### SPEC §2 ZP prefix registry (issue #76)

The bare `zp_tmp*` / `zp_ptr*` names were unregistered general-purpose
spellings that `c64-nist-curves` also exports. Two such libraries in one
link fail outright:

```
ld65: Error: Duplicate external identifier: 'zp_ptr2'
```

That error was the *only* thing standing between two libraries' live
scratch and a silent address overlap — which is why the contract treats
same-named slots across libraries as a defect class
([contract #83](https://github.com/JC-000/c64-lib-contract/issues/83))
rather than a naming preference.

The deprecated bare names sit behind `LIB_NO_BARE_EXPORTS`, per contract
v0.9.1 §6.5. That gate is the point: an *ungated* alias would have kept
the collision alive for the whole rename window, leaving a composed link
no better off the day the window opened than the day before.

**Gating one side is sufficient.** Measured: this library's
`zp_config.o` built with `-D LIB_NO_BARE_EXPORTS=1` links cleanly
against an **unmodified** `c64-nist-curves` `zp_config.o`. That library
does not have to migrate first — useful, since its trio has in-archive
importers.

### SPEC §6.1 canonical archive basenames (issue #76)

| canonical (link this) | deprecated (removed at next MAJOR) |
|---|---|
| `chacha20poly1305.a` | `c64-chacha20-poly1305.a` |
| `chacha20poly1305-aead-only.a` | `c64-chacha20-poly1305-aead-only.a` |
| `chacha20poly1305-app-owned.a` | `c64-chacha20-poly1305-app-owned.a` |

Each deprecated file is a `cp` of the canonical one, so there is exactly
one `ar65` invocation per variant and drift between the two names is
structurally impossible. Byte-identity is checked on every build rather
than asserted once.

Unlike a symbol rename, a filename rename cannot collide at link time,
so this half needed no suppression gate.

### SPEC §6.2 / §6.3 — `CONTRACT_DEFINES` and `lib-app-owned` (issue #74)

`CA65FLAGS` had been hard-assigned, which made §2's normative
`ca65 -D <slot>=<addr>` override unreachable: overriding the variable
dropped the `-I` paths and the build failed with
`Cannot open include file 'precalc_table.inc'`. Every target now
forwards **`CONTRACT_DEFINES`** — the contract-normative spelling, so a
multi-library consumer script uses one variable name across every
library. `EXTRA_CA65FLAGS` remains as a back-compat alias.

`make lib-app-owned` ships the §8.0 `APP_OWNED` archive with both shared
primitives deferred (`SHARED_PRIMITIVES=$0000`,
`SHARED_CONSUMES=$0005`), verified linking against `c64-x25519` as
provider with zero `ar65` surgery.

There is deliberately **no `CONTRACT_ZP_DEFINES`**: no archive member
defines ZP, because `src/zp_config.s` is excluded so consumers assemble
their own. The contract calls this the consumer-assembled-source model.

### Use `0x` hex, never `$` hex, in `-D` values

Measured, and worth repeating because it is silent: unquoted
`-D FOO=$9000` has `$9` eaten by the shell as a positional parameter,
leaving `-D FOO=000` — **decimal 0**, with no diagnostic from the shell,
`ca65` or `ld65`. Through `make` it is worse: `$40` and `$$40` both
yield 0, and `$$$$40` yields the shell's PID — a plausible-looking
address that changes between invocations. A pasted sqtab override would
place a 1 KB table at `$0000`.

### Other contract items closed

- **Per-variant manifests** (issue #69): each archive's manifest now
  describes *that* archive. `RESIDENT_BYTES` — full 16896, aead-only
  16640.
- **§4 declaration diagnostics** (issue #71): the documented consequences
  of dropping a cfg attribute were understated. For this library's shape
  a `bss` violation on `LIB_CHACHA20_POLY1305_DATA` is **completely
  silent**.
- **`ABI_VERSION` as a generation counter** (issue #67): contract v0.7.5
  reclassified it as monotonic and independent of MAJOR. v0.7.0's tag
  reports 1 under the old "mirrors MAJOR" rule and is deliberately not
  retagged.
- **Version-guard snippets that could not assemble** (issue #68): guards
  must be `.assert …, lderror, "…"`. A `.if` on an `.import`ed symbol
  fails with `Constant expression expected`, because an imported symbol
  has no value until link.

## Correctness

- Test suite **214/214 on both profiles** (VICE), including the 79
  pyca-cross-checked AEAD vectors.
- Default-build PRG **byte-identical to v0.7.0** (`52b87cdf…`) — the
  strongest available evidence that a naming release changed no
  behaviour.
- All three archive variants build with **zero** ld65 warnings.
- `make lib-verify-shared` passes: §8.3 surface owned in the default
  build, fully deferred under `SHARED_CT_MUL_8X8`.
- `test_consumer/` links the canonical archives with the renamed ZP
  slots; `run_aead_smoke.py` passes on both `full` and `aead`.
- The ZP gate verified by symbol dump, every `od65` dump
  sentinel-checked — `od65` cannot read `.a` archives and exits 0 on
  one, so an unchecked grep-based audit is indistinguishable from a
  clean pass.

## Performance

**Unchanged, and not re-measured.** The PRG is byte-identical to
v0.7.0, so cycle counts cannot differ. The v0.6.0 n-sweep measurements
([`BENCH_NSWEEP_v0.6.0.md`](BENCH_NSWEEP_v0.6.0.md),
[`BENCH_NSWEEP_u64_v0.6.0.md`](BENCH_NSWEEP_u64_v0.6.0.md)) therefore
still describe this release.

## Source tarball

Built reproducibly via `tools/build_release.sh v0.8.0` (alias:
`make dist VERSION=v0.8.0`). `git archive` + `gzip -n -9` for
byte-identical output across re-runs. The recorded SHA256 is captured in
the GitHub release description.

The script requires the tag to exist and the matching
`docs/RELEASE_NOTES_v0.8.0.md` to be present *at* that tag, so the
tarball is produced after tagging, not before.

See [`REPRO_CHECK.md`](REPRO_CHECK.md) for the verification procedure.
