# c64-ChaCha20-Poly1305 v0.11.0 — Release Notes

Released 2026-09-06. Compared to v0.10.0 (same day).

**Conformance and correctness release.** It makes the library's archive
members conformant to contract §6.1 member isolation, and corrects five
published footprint equates that under-reported what a consumer pays.

**No code changed.** All four profile PRGs are byte-identical to v0.10.0
(`298e6fbd…` / `01a2cdd7…` / `d35517cb…` / `5a5ca9db…`), and every symbol
sits at the same address. `LIB_CHACHA20_POLY1305_ABI_VERSION` stays **4**.

Semver: **MINOR**. One new exported symbol arrived in v0.10.0's line, no
export was removed or renamed, and no calling convention moved.

## Consumer migration

**One thing to check, and it is not optional if you size a region from our
equates.**

`LIB_CHACHA20_POLY1305_RESIDENT_BYTES` **rises by 768 B in every
configuration**:

| Variant | v0.10.0 | v0.11.0 |
|---|---|---|
| Profile A full | 15 872 | **16 640** |
| Profile A aead-only | 15 360 | **16 384** |
| Profile B full | 17 152 | **17 920** |
| Profile B aead-only | 16 640 | **17 664** |
| Profile B app-owned | 16 896 | **17 664** |

The old values were **wrong in the dangerous direction** — they
under-reported what a consumer actually pays, so a fit check could pass
while the library overran. If you assert against these, your assert's
left-hand side grows by 768 B. If that now fails, the failure is real and
predates this release; it was simply invisible.

`LIB_CHACHA20_POLY1305_ABI_VERSION` is unchanged, deliberately. Contract
§7 says the counter holds "when documentation is corrected to match code
that did not change: a consumer relying on the wrong documented contract
was already broken at every prior release, so the correction discloses
that rather than causing it." That is exactly this.

Nothing else changes. No slot address, segment name, archive basename,
entry point or return value moved.

## Why the equates were wrong

The basis summed each **object's** segment sizes via `od65`. That cannot
see the padding `ld65` inserts **between** sections — and this library
forces that padding to exist, because `LIB_CHACHA20_POLY1305_CODE` must
carry `align = $100` as the constant-time invariant for its
secret-indexed lookup tables.

Measured across two trees, all ten rows: `sum + fill = link` **exactly**.
Rounding up to 256 adds at most 255 B of cushion; the fill runs 246–419 B,
so the round-up never reliably covered the omission — the convention
assumed one page-aligned section and there are three.

The declared value is now a bound:

```
sum
  + (alignment - 1) per page-aligned fragment
  + (alignment - 1) for the segment start itself
  rounded up to 256
```

It is **not** derived from a measured link, deliberately: a consumer
pulling part of the archive measures 453 B *below* the sum, one pulling
all of it measures above. §5 asks for what stays resident "in every
consumer", which only a bound covers.

**It over-reserves by roughly 350–500 B, and the equate says so.** If your
fit check fails by a few hundred bytes, a real link may still fit —
measure yours. What you must not do is lower the literal on the strength
of that measurement: it is a bound over every consumer, not a description
of yours.

**Scope.** The bound covers alignments *this library* declares. A consumer
declaring `align = $200` forces more (measured +38 B; `$400` +550;
unbounded). That is permitted, not a violation — §4's obligation is on the
library and 512-aligned implies 256-aligned — so excluding it is this
library narrowing §5 by fiat, and it is stated as such.

## Member isolation (contract §6.1)

Two archive members mixed symbols a consumer may displace with symbols a
consumer imports:

| Member | Displaceable | Sharing the member |
|---|---|---|
| `lib_manifest.o` | 9 bare `LIB_PRECALC_*` | 8 §5/§8 equates |
| `poly1305_lib.o` | 8 `APP_OWNED` §8.1/§8.3 names | 9 Poly1305 entry points |

`lib_manifest.o`'s case is **library-versus-library** and live: four
independently-built libraries in this fleet emit the bare
`LIB_PRECALC_sqtab_*` triple, so any composed link without
`LIB_NO_BARE_EXPORTS` collides.

`poly1305_lib.s` is now seven translation units, grouped by which switch
drops each name, so deferring §8.1 does not drag in §8.3. What it buys:

| | v0.10.0 | v0.11.0 |
|---|---|---|
| consumer supplies its own §8.1/§8.3 bodies, links the **default** archive | `Duplicate external identifier: 'sqtab_init'` | links; the displaceable members are **not pulled** |

It does not fix double-ownership composition — two owner archives still
need a deferral switch. If you already build us with `SHARED_SQTAB_INIT`
and `SHARED_CT_MUL_8X8`, this changes nothing for you; the value is making
the **default** archive safe for a consumer who does not know to pass
them.

## New checks

- **`make verify-resident-bytes`** — six checks, both profiles × three
  variants, each reading the equate out of the object it just built. The
  "wave 3 item F" the manifest had been asking for since v0.9.0; its
  absence is why five wrong literals shipped through four releases.
- **`make lib-verify-isolation`** — measures the displaceable set by
  differencing builds rather than listing names, reconciles
  `bare + prefixed + other == exports` per member, and checks its own
  suppression roster against the switches actually present in `src/`.
- **`r_tab_lo`/`r_tab_hi` page-alignment asserts** — the fifth alignment
  mechanism in the library, absolute literals, secret-indexed, previously
  with no check at all.

`make dist` now runs the verify targets inside the extracted tarball, not
just the build targets.

## Footprint (per profile × variant)

Resident bytes are **unchanged** — no code moved. Only the declared bound
changed, and it changed because it was wrong. The measured segment sum
fell 83–145 B purely because a `.align` pad crossed a counting boundary
during the split; three independent proofs confirm no byte moved.

## Correctness

- `make test`: **215/215 on both profiles**, VICE.
- Four profile PRGs and five `test_consumer` PRGs byte-identical to
  v0.10.0.
- `verify-resident-bytes`, `lib-verify-isolation`, `lib-verify-shared`,
  `verify-zp-usage`, `verify-knob-staleness`: all pass, all demonstrated
  capable of failing.

## Contract conformance

Span extended to **v1.2.2**, which is where the contract is frozen. §6.1
member isolation is now met; it was the only outstanding clause.
