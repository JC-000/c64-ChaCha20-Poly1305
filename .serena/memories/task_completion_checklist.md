# What to run before declaring a task done

No CLAUDE.md sets this explicitly. Inferred from Makefile + docs:

1. **Both profiles build cleanly**:
   ```bash
   make clean && make profile-a && make profile-b
   ```
   Expect `build/profile-{a,b}/c64_chacha20_poly1305.prg` and a `labels.txt` (VICE-format).

2. **214 RFC 7539 vectors pass**:
   ```bash
   make profile-a && python3 tools/test_chacha20_poly1305.py
   ```

3. **Smoke test (external consumer template)**:
   ```bash
   cd examples/smoke_test && make both && python3 run_smoke_test.py both
   ```
   PASS = `$01` written to screen RAM `$0400`.

4. **Cross-check vs pyca/cryptography** (any cryptographic-logic change):
   ```bash
   python3 tools/audit_cross_check.py     # 30,000 random vectors, byte-identical
   ```

5. **Brute-check `ct_mul_8x8`** (any change to Profile B multiply):
   ```bash
   python3 tools/ct_mul_brute_check.py    # all 65,536 (a,b) pairs in [0,255]²
   ```

6. **Benchmark** (any perf-sensitive change):
   ```bash
   make profile-a && python3 tools/benchmark_chacha20_poly1305.py --seed 7539
   ```
   Compare against `docs/REPRO_CHECK.md` §4 baseline.

7. **Reproducibility check**: clean rebuild and md5 the PRG. v0.3.1 fingerprints:
   - Profile A: `313300ff4d86cefc6d3b195563c1383d`
   - Profile B: `a0e4b682fa454c6b8e2d8a04297333ab`
   Mismatch ⇒ investigate.

8. **Update docs if API or ABI changed**:
   - `docs/API.md` — symbols, signatures, clobbers, cycle counts
   - `docs/MEMORY_MAP.md` — ZP / table addresses
   - `docs/INTEGRATION.md` — consumer wiring
   - `CHANGELOG.md` — new entry under correct section (Added/Changed/Fixed/Security/Docs)

There is no linter / formatter to run.
