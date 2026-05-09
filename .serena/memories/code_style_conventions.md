# Code style & conventions

## Assembly style
- **Symbols**: `snake_case` with subsystem prefix — `chacha20_*`, `poly1305_*`, `word32_*`, `aead_*`.
- **ZP equates**: prefix-scoped (`cc20_round`, `poly_i`, `zp_ptr1`), defined in `src/lib/constants_lib.s` and gated by `.ifndef` so consumers can pre-define and override.
- **Local labels**: `@label` for within-function jumps.
- **Table base addresses**: page-aligned, hardcoded (Profile A): `sqtab_lo=$8000`, `sqtab_hi=$8200`, `r_tab_lo=$6000`. v0.4.0 will make these `-D`-configurable.

## File layout
- `.s` = source modules (assemble to `.o`).
- `.inc` = pure-header equates / macros, never produces `.o`.
- Each `.s` module has a block-comment header (purpose, entry points, CT contract) — see `src/lib/poly1305_lib.s:1`.
- Cross-module imports: `.import` for code/data, `.include` for equates. `.export` listed at end of each module.

## Comment style
- Module headers: `; ====` dividers (~70 char wide).
- Section headers: `; --- Section name ---`.
- Routine headers: block comment with purpose, signature, preconditions/postconditions, clobbers, **CT contract** (every routine must declare it).
- SMC sites: use `smc.inc` macros (`SMC { ... }`, `SMC_StoreLowByte`, `SMC_StoreHighByte`, `SMC_StoreValue`) — v0.3.1 converted all 5 inline-comment SMC sites to named macros (PR #17).

## Constant-time discipline
- Per-branch CT classification in `docs/CT_ANALYSIS.md` (F1/F2/F3 categories, all GREEN as of v0.3.0).
- Top-level audit verdict in `docs/AUDIT.md`.
- Profile B uses branchless `ct_mul_8x8`; Profile A uses Shoup tables (also CT by construction).
- New code touching secret data MUST document its CT contract in the routine header AND classify any new branches against `docs/CT_ANALYSIS.md`.

## Vendored deps (`src/include/`)
- `ca65hl/` — ca65hl macro package, MIT (Julian Terrell / Movax12).
- `smc.inc` — self-modifying-code macros, zlib (Christian Krüger).

## Public ABI
- `.export` per module lists public entry points; `.exportzp` in `src/main.s` re-exports ZP equates for the VICE label file.
- All public symbols documented in `docs/API.md` with cycle counts and clobbers.
- No CONTRIBUTING.md — style enforced by review.
