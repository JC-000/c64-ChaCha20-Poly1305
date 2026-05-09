# Suggested commands — c64-ChaCha20-Poly1305 (macOS)

## Build
```bash
make                 # alias for `make profile-a`
make profile-a       # Shoup-table profile (POLY1305_PROFILE_LONG=1) → build/profile-a/
make profile-b       # portable profile (no flag)                  → build/profile-b/
make clean           # rm -rf build
make run             # build profile-a + x64sc -autostart build/c64_chacha20_poly1305.prg
```
Active profile's PRG and `labels.txt` are copied to `build/` (root) so the test harness picks them up.

## Test (require pre-built PRG; harness does NOT auto-rebuild — Task #18)
```bash
make profile-a && python3 tools/test_chacha20_poly1305.py     # 214 RFC 7539 vectors
make profile-a && python3 tools/benchmark_chacha20_poly1305.py --seed 7539
python3 tools/audit_cross_check.py                            # 30k random vectors vs pyca/cryptography
python3 tools/ct_mul_brute_check.py                           # 65,536 (a,b) exhaustive check (Profile B mul)
```

## Smoke test (external-consumer integration template)
```bash
cd examples/smoke_test
make both                       # build both profiles
python3 run_smoke_test.py both  # PASS = $01 written to $0400 screen RAM
```

## Reproducibility — v0.3.1 PRG md5 fingerprints
- Profile A: `313300ff4d86cefc6d3b195563c1383d`
- Profile B: `a0e4b682fa454c6b8e2d8a04297333ab`
Mismatch ⇒ investigate before assuming a clean build.

## Lint / format
- **None.** No `.pre-commit-config.yaml`, no ruff/black, no automated style enforcement. Style is enforced by review.

## Toolchain prerequisites
- `cc65` (provides `ca65`, `ld65`) — `brew install cc65`
- VICE 3.x (`x64sc` on PATH) — `brew install --cask vice`
- Python 3 + `c64-test-harness` (`pip install c64-test-harness`)
- `cryptography` Python package (for `audit_cross_check.py`)
- Optional: Ultimate 64 hardware (auto-detected by UnifiedManager when reachable)

## macOS / BSD sed note
The Makefile's FIXLABELS macro uses portable temp-file form (`sed ... > $(1).tmp && mv $(1).tmp $(1)`) — do not "simplify" to `sed -i` (BSD sed treats the next arg as a backup suffix). See PR #21, commit `73e080e`.
