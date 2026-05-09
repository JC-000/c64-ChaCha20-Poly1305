# Codebase structure (top-level)

```
src/
  main.s                       BASIC stub + .exportzp re-exports for VICE labels
  c64.cfg                      ld65 linker config (MAIN=$0900..$9FFF; CODE/DATA/BSS/ZP segments)
  include/
    ca65hl/                    vendored ca65hl macro package (MIT)
    smc.inc                    vendored self-modifying-code helper macros (zlib)
  lib/
    constants_lib.s            ZP + table equates (no code); .ifndef-gated so consumers can override
    data_lib.s                 mutable state buffers (cc20_*, poly_*, aead_*) — DATA segment
    word32_lib.s               32-bit primitives: add32, xor32, rotl32/rotr32 (jump-table form)
    chacha20_lib.s             ChaCha20 stream cipher (8 QRs inlined, rot-8/16 as offset renames)
    poly1305_lib.s             Poly1305 MAC (Shoup tables on Profile A; quarter-square + ct_mul_8x8 on B)
    chacha20poly1305_lib.s     AEAD wrapper: encrypt/decrypt/derive_otk/setup_chacha

test/
  rfc7539_vectors.json         214 RFC 8439 KAT vectors

tools/
  test_chacha20_poly1305.py    214-test runner (VICE via c64-test-harness)
  benchmark_chacha20_poly1305.py   CIA-timer cycle benchmark, chain at $C080
  audit_cross_check.py         30,000 random AEAD vectors vs pyca/cryptography
  ct_mul_brute_check.py        65,536 (a,b) exhaustive Profile B multiply check
  step*.py                     deprecated, historical per-step cross-check tools

docs/
  API.md                       public symbol reference (signatures, clobbers, cycle counts)
  INTEGRATION.md               consumer wiring guide; memory map collision list; harness convention
  MEMORY_MAP.md                authoritative ZP + fixed-address audit (v0.3.0, dated 2026-04-13)
  AUDIT.md                     top-level constant-time verdict (GREEN)
  CT_ANALYSIS.md               per-branch CT classification (F1/F2/F3, all resolved in v0.3.0)
  REPRO_CHECK.md               build fingerprints + post-CT-fix benchmark table
  OPTIMIZATION_PLAN.md         S0–S13 sprint progression (per-step cycle counts)
  design/ct_mul_8x8.md         F3 branchless multiply design memo (Profile B fix)

examples/
  smoke_test/                  external-consumer integration template (RFC 7539 §2.8.2 KAT, both profiles)

build/                         (gitignored; populated by make)
  profile-a/  profile-b/       per-profile .o + PRG + labels.txt
  c64_chacha20_poly1305.prg    copy of active profile (test harness target)
  labels.txt                   copy of active profile (VICE format)

.claude/worktrees/             empty — intended for git-worktree isolation
```

No `CLAUDE.md`, no CONTRIBUTING.md, no .pre-commit-config.yaml, no settings.json under .claude.
