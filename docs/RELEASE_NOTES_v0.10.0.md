# c64-ChaCha20-Poly1305 v0.10.0 — Release Notes

Released 2026-09-06. Compared to v0.9.0 (2026-08-15).

**Security and hardening release, and the first since v0.6.0 whose PRGs
are not byte-identical to the previous tag.** Two real defects are fixed
— one memory-safety, one output-correctness — three constant-time
invariants that were documented but unenforced become link errors, and a
shared-primitive ownership claim this library could not honour is made
true. It also brings conformance up to `c64-lib-contract` **v1.1.0**,
across the release that cut seven eighths of that document.

`LIB_CHACHA20_POLY1305_ABI_VERSION` moves **3 → 4**. Semver: **MINOR**,
not MAJOR — contract §7 scopes the ABI counter's trigger to the
counter alone, and says so explicitly. See "The ABI bump" below.

The full per-change log is in [`CHANGELOG.md`](../CHANGELOG.md).

## Consumer migration

**Required reading if you call `aead_decrypt` and distinguish failure
modes.** Otherwise this is a drop-in.

**1. `aead_decrypt` gained a third return value.** It now returns
`A = $01` (`AEAD_ERR_DOMAIN`) alongside `$00` (ok) and `$ff` (auth
failure). Exhaustive handling of `{$00, $ff}` is now non-exhaustive —
which is exactly why the ABI counter moved. If you wrote

```asm
    jsr aead_decrypt
    bne @auth_failed        ; WRONG as of v0.10.0: $01 is not auth failure
```

change it to test the specific code:

```asm
    jsr aead_decrypt
    beq @ok
    cmp #$ff
    beq @auth_failed
    ; A = $01: your buffer ran off the top of memory; nothing was written
```

**2. `aead_encrypt` now returns a status where it previously left `A`
undefined.** `$00` on success, `$01` on domain rejection. A caller that
treated `A` as a don't-care is unaffected.

**3. `aead_encrypt` now writes the tag where the documentation always
said it does.** Through v0.9.0 it left the tag in `poly1305_tag` and not
in `aead_tag`, contradicting `docs/API.md`. If you worked around that by
reading `poly1305_tag`, both labels now hold the tag and your code keeps
working; move to `aead_tag` at your leisure.

**4. Pin the ABI generation** if you have not already:

```asm
.assert LIB_CHACHA20_POLY1305_ABI_VERSION = 4, lderror, "CCP surface changed; re-check the integration"
```

**5. Nothing else moves.** No slot address, no segment name, no archive
basename, no calling convention beyond the return values above.

## Fixed

### `aead_encrypt` / `aead_decrypt` rejected out-of-domain input (PR #98)

The data walkers advanced their pointer with 16-bit arithmetic and no
carry-out check, so a call with `aead_data_ptr + aead_data_len > $10000`
wrapped past `$FFFF` to `$0000` and the library read **and wrote** from
zero page upward: `$01` (the banking register, re-banking RAM/ROM
mid-loop), the stack, and I/O at `$D000-$DFFF`.

Both entry points now enforce

```
aead_data_ptr + aead_data_len <= $10000
aead_aad_ptr  + aead_aad_len  <= $10000
```

as the published domain, at 44 cycles on the accept path, ahead of every
`jsr` — so a rejected call writes nothing at all. A buffer ending exactly
at `$FFFF` is in domain.

### `aead_encrypt` wrote the tag to the wrong label (PR #93)

It populated `poly1305_tag` but not `aead_tag`, while `docs/API.md`
documented `aead_tag`. A consumer following the documentation read
whatever was in that buffer. Both are now written.

## Constant-time hardening

Three secret-indexed lookup tables carried `.align 256` with comments
calling the alignment a CT requirement, and **nothing enforced any of
them**. Each is now a deferred `.assert ... lderror`:

| Table | Secret index | Issue |
|---|---|---|
| `chacha_nibswap_hi_tab` | `X` from ChaCha20 work bytes | #100 |
| `chacha_nibswap_lo_tab` | same | #100 |
| `poly_reduce_shl6_tab` | `Y` from the Poly1305 accumulator | #102 |

The alignment depends on a file this library does not control — the
consumer's cfg declaring `LIB_CHACHA20_POLY1305_CODE` with
`align = $100` — and ld65 only **warns** when it is missing, then links
the tables misaligned and exits 0. A misaligned build passes every test,
because no test has a timing oracle.

**Demonstrated, not asserted.** Misaligning `poly_reduce_shl6_tab` alone,
against an otherwise correct cfg: `main` at v0.9.0 links a **17702-byte
PRG and exits 0**, with the table at `$1CFF`; v0.10.0 fails the link. The
asserts test the **resolved address**, proved in both directions — an
object-relative offset of 512 (`$00`) with a resolved address of `$1C0A`
fires, and an offset of 430 (`$AE`) with a resolved address of `$1B00`
passes.

`shoup_init`'s `r_tab_*-1, y` loads are the one indexed access whose base
is deliberately not page-aligned: `Y` there is the public loop counter, so
the page cross is unconditional rather than data-dependent. Now recorded
in-source so it is not mistaken for an oversight.

**No fourth instance exists.** Settled by enumerating every
absolute-indexed access in the library by secret-index reachability, not
by counting `.align` directives: `sqtab_lo`/`sqtab_hi` are equate-placed
with §8.1's own alignment assert, and `r_tab_lo`/`r_tab_hi` are fixed
literals at `$6000`/`$7000` with per-limb bases of `$6000 + j*256`.

## The §8.1 ownership claim this library could not honour (issue #105)

Every default Profile B build advertised
`LIB_CHACHA20_POLY1305_SHARED_PRIMITIVES = $0005`, claiming ownership of
the shared quarter-square table — while exporting the primitive's init
only under this library's historical name `sqtab_init`, never the
contract-canonical `mul_tables_init`. A sibling that read the bit,
deferred its own sqtab and imported the canonical name got

```
ld65: Error: Unresolved external 'mul_tables_init'
```

The asymmetry is the tell: this library's own `lib-app-owned` variant
**imports** a name its `lib` variant did not **export**. Both other §8.1
owners, `c64-x25519` and `c64-mlkem`, already exported it.

This is the same defect issue #47 fixed for §8.3 one clause over, left
behind when #47 landed — #47's own comment sits four lines above where
the §8.1 bug was, describing it. §8.3 got a checker then; §8.1 did not,
which is why this survived. `make lib-verify-shared` now covers both.

## Contract conformance — SPEC v0.17.0 → v1.1.1

v1.0.0 cut the contract from 40,737 words to 5,154, retiring §9, §12,
§13, §14, §15 and §6.3/§6.6/§6.7. **That was mostly a no-op here**, by
design: the contract's `RETIRED.md` says a record citing a retired
section stays valid at the tag it cites, so no citation was rewritten.

The cut did carry **two normative tightenings inside surviving clauses**,
unrecorded, in a release whose header said a v0.17.1-conformant library
needed no edits — §6.1 requiring `make lib` to emit a `.inc` header and
an example `.cfg`, and §4 making the example cfg's path normative.
Reported as
[c64-lib-contract#178](https://github.com/JC-000/c64-lib-contract/issues/178)
and **both withdrawn at contract v1.1.1**, the `.inc` clause on the
merits: it mandated an artifact while fixing neither a name nor a path
for it, and a library can see it ships no header from inside its own
build, so it failed the contract's scope rule on both prongs.

Our report also undercounted — we named this library and `c64-polyval`;
the contract's own measurement added `c64-nist-curves`, three of five
adopters — and missed the cleaner falsifier, that the cut also *dropped*
three §6.1 targets, so "no build target changed" was false in both
directions.

**This release ships the `.inc` header and example cfg anyway**, now as a
local choice rather than conformance. A consumer who fetches `build/lib/`
should get an interface rather than an archive to reverse-engineer, and
the cfg is where §4's load-bearing attributes and their consequences are
written down. `make lib` emits both.

Also new: `LIB_CHACHA20_POLY1305_AAD_LEN_MAX = 255`, per §5's rule that a
real input bound be a referenceable symbol rather than something the
consumer re-derives. Verified at the boundary, not reasoned about: 255 is
the largest value the one-byte field expresses, every path that reads it
handles 255 correctly, and the differential fuzz exercises 254 and 255
against the pyca oracle. The buffer domain stays unpublished, also per §5
— it is a *relation* over two caller-supplied values, so no scalar
expresses it.

### Not conformant: contract v1.2.0 §6.1 member isolation

**v1.2.0 was tagged during this release's preparation** and adds a
normative member-isolation rule: a symbol a consumer may displace must
not share an archive member with anything a consumer may import. Three of
this library's members violate it — `lib_manifest.o` (the bare
`LIB_PRECALC_*` triples beside the §5 equates), `poly1305_lib.o` (the
§8.1/§8.3 `APP_OWNED` bodies beside the Poly1305 entry points), and
arguably `lib_version.o`, whose arrangement §1 itself prescribes.

**This release does not fix them, and says so rather than claiming a span
it does not have.** The clause is hours old; the `poly1305_lib.s` split
is surgery on the crypto file rather than a move of equates; and the
`lib_version.o` case may be a contradiction with §1 whose resolution
changes what the other fixes should look like. The failure it guards is
real — the contract records that it "cost c64-https every shipped
configuration on `c64-nist-curves` v0.12.0" — and it is tracked, with the
full per-member audit, as
[issue #108](https://github.com/JC-000/c64-ChaCha20-Poly1305/issues/108).

Consumers linking this library **alone** are unaffected. Consumers
composing it with a sibling should keep building every library with
`-D LIB_NO_BARE_EXPORTS=1` and use `make lib-app-owned` where they supply
their own shared primitives, which is what the variants are for.

## The ABI bump

`main` carried `ABI_VERSION = 4` unreleased since PR #98, held pending a
ruling: §1 and §7 both said the counter increments on a breaking
**export** change, and this library's export list was byte-for-byte
unchanged. Contract v1.1.0 §7 settled it —

> Whether the counter moves turns on what the code does, not on whether
> the export list changed. It moves when a consumer conforming to the
> previously documented contract can be broken by the change — most often
> when an existing entry point's actual return set gains a value, since
> exhaustive handling silently becomes non-exhaustive.

A widened return set is the named case. The clause is **scoped to the
counter only**: such a change is not thereby MAJOR and owes no
deprecation cycle. So this is 0.10.0, not 1.0.0.

## Footprint (per profile × variant)

Measured as the library's own `LIB_CHACHA20_POLY1305_CODE + _DATA`
segment sum across the archive's member objects.

| Variant | v0.9.0 | v0.10.0 | Δ | Declared |
|---|---|---|---|---|
| Profile A full | 15 544 | 15 651 | **+107** | 15 872 |
| Profile A aead-only | 15 219 | 15 326 | **+107** | 15 360 |
| Profile B full | 16 838 | 16 945 | **+107** | 17 152 |
| Profile B aead-only | 16 513 | 16 620 | **+107** | 16 640 |
| Profile B app-owned | 16 582 | 16 689 | **+107** | 16 896 |

+107 B in every configuration: 96 B of §14.1 domain guards plus the 11 B
`aead_tag` fix. Every declared literal is ≥ measured (safe direction).

**Two of these are thin** — aead-only Profile B has 20 B of headroom and
Profile A 34 B — and **nothing checks them automatically**. The next
addition to a shared translation unit will breach them silently. The
`verify-resident-bytes` audit that would close this is still outstanding.

The three CT asserts and the §8.1 export cost **zero** resident bytes;
deferred asserts emit nothing, re-measured across all five variants
rather than assumed.

(Four distinct profile PRGs are built — `profile-a`, `profile-b`,
`profile-b-rolled`, `profile-b-rolled-outer` — plus the mirrored
`build/c64_chacha20_poly1305.prg` that the last target leaves. Earlier
drafts of these notes said "five PRGs", counting the copy.)

## Correctness

- `make test`: **215/215 passed on both profiles**, VICE, including the
  79-case AEAD cross-check against `pyca/cryptography` and the `aead_tag`
  regression.
- `make test-fuzz`: **1310 jsr calls, 0 mismatches on each profile**
  against the pyca oracle — 140 encrypt/decrypt pairs, 520 tamper cases,
  and the `wrap_guard` legs that exercise the new domain guard on target
  (50/50 discriminating, 23/23 tripwire). The AAD grid includes 254 and
  255, so the newly published `AAD_LEN_MAX` is checked at its boundary.
- `make verify-zp-usage`, `make lib-verify-shared`,
  `make verify-knob-staleness`: all pass.

## Performance

**Unchanged.** The domain guards add 44 cycles on the accept path of each
AEAD entry point — once per call, not per block — and nothing else on any
hot path moved. The three CT asserts and the §8.1 export emit no code.
