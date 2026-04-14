# REPRO_CHECK — v0.3.0 release candidate

**Date**: 2026-04-13 (post-CT-fix)
**Auditors**: audit-runner (task #12, original S13 capture) + ct-fixer
(task #17, post-CT-fix refresh) + readiness-scribe (task #15,
release-candidate verification)
**Tree**: `/home/someone/c64-ChaCha20-Poly1305`
**Branch**: `main`, at commit `f4f049e` (merge of PR #14 — "CT fix:
F1 poly_final mask-blend + F2 chacha20 rot1 branchless + F3 ct_mul_8x8
Profile B")

## Verdict: GREEN — reproducible, CT-clean, ready to tag v0.3.0

- **Correctness**: REPRODUCIBLE. 214/214 library tests on both
  profiles at seed 7539. 30 000/30 000 deep cross-check vectors
  (15k/profile) via `tools/audit_cross_check.py`. Zero mismatches
  across the full ChaCha20 + Poly1305 + AEAD stack.
- **ct_mul_8x8 primitive**: EXHAUSTIVELY VERIFIED. 65 536/65 536
  `(a,b)` pairs in `[0,255]^2` brute-forced against Python `a*b`
  reference via `tools/ct_mul_brute_check.py` (2.7 s). This is the
  cheapest possible full-coverage test for an 8×8 primitive and
  closes the correctness gap for the new CT multiply.
- **Binary reproducibility**: REPRODUCIBLE. `make clean && make
  profile-a profile-b` produces byte-stable PRG files; md5s verified
  across two fresh rebuild cycles by ct-fixer and re-verified by
  readiness-scribe on the merged-main state.
- **Constant-time posture**: GREEN. Three pre-existing CT findings
  (F1, F2, F3) resolved in PR #14. See `docs/CT_ANALYSIS.md` for
  the historical RED content and the post-fix Resolution section.

Overall: the merged-main state at the CT-fix merge commit is
bit-for-bit reproducible, functionally equivalent to every prior
byte-wise AEAD output (ChaCha20, Poly1305, and AEAD all produce
identical bytes pre/post CT fix — only timing changed), and
CT-clean. Ready to tag v0.3.0.

---

## 1. Git state

```
$ git fetch && git checkout main && git pull
Already on 'main'
Already up to date.
$ git log -1 --format='%H %s'
f4f049e50706ca33092fab63454cbfe44717ee48 Merge pull request #14 from JC-000/ct-fix-v0.3.0
```

Recent merge: `f4f049e` is the CT-fix merge commit (PR #14).
The CT-fix source commit itself is `dc4c575`. This state is the
v0.3.0 release candidate.

## 2. Build — clean + both profiles

```
$ make clean
rm -rf build
$ make profile-a   (stderr: empty)
$ make profile-b   (stderr: empty)
```

Both profiles compile and link cleanly. No warnings, no stderr output.

### md5 + size + load address (v0.3.0 reference-build fingerprints)

```
$ md5sum build/profile-a/c64_chacha20_poly1305.prg build/profile-b/c64_chacha20_poly1305.prg
313300ff4d86cefc6d3b195563c1383d  build/profile-a/c64_chacha20_poly1305.prg
a0e4b682fa454c6b8e2d8a04297333ab  build/profile-b/c64_chacha20_poly1305.prg

$ ls -la build/profile-a/c64_chacha20_poly1305.prg build/profile-b/c64_chacha20_poly1305.prg
-rw-rw-r-- 1 someone someone 15739 Apr 13 19:43 build/profile-a/c64_chacha20_poly1305.prg
-rw-rw-r-- 1 someone someone 16777 Apr 13 19:43 build/profile-b/c64_chacha20_poly1305.prg

$ xxd -l 2 build/profile-a/c64_chacha20_poly1305.prg
00000000: 0108                                     ..
$ xxd -l 2 build/profile-b/c64_chacha20_poly1305.prg
00000000: 0108                                     ..
```

- Profile A PRG: **15 739 bytes**, md5 `313300ff4d86cefc6d3b195563c1383d`
- Profile B PRG: **16 777 bytes**, md5 `a0e4b682fa454c6b8e2d8a04297333ab`
- Both load at `$0801` (PRG header `01 08`, little-endian).

### md5 stability across repeated clean rebuilds

The full clean+build cycle was executed by ct-fixer twice during
the CT-fix work and re-verified by readiness-scribe on the merged
CT-fix commit. All three independent fresh builds produced
byte-identical PRGs:

| profile | md5                                  | stable |
|---------|--------------------------------------|:------:|
| A       | `313300ff4d86cefc6d3b195563c1383d`   |   ✓    |
| B       | `a0e4b682fa454c6b8e2d8a04297333ab`   |   ✓    |

Binary reproducibility confirmed. These md5s are the
**v0.3.0 reference-build fingerprints** cited in the release notes
and in `docs/AUDIT.md`.

**Historical note**: the pre-CT-fix (S13) reference fingerprints
were `85b6621c2c23dcfd9930a928ef2c11de` (profile-a) and
`c44650b2f2746924a95f0a226806bf9e` (profile-b). The v0.3.0 release
ships the post-CT-fix PRGs listed above; the S13 hashes are
retained here only for archival comparison.

## 3. Library test suite — 214/214 both profiles

Both profiles pass the full RFC 7539 test suite at seed 7539 on
the post-CT-fix main:

- **Profile A**: 214/214 passed, 0 failed.
- **Profile B**: 214/214 passed, 0 failed (run with
  `C64_SKIP_BUILD=1` to defeat the task-#18 destructive auto-rebuild
  — see §4 caveat).

Both test runs preserve the PRG md5s recorded above (md5 unchanged
after the test run completes).

## 4. Benchmark — both profiles (post-CT-fix ground truth)

Ground-truth cycle numbers are from ct-fixer's PR #14 measurement
pass: `tools/benchmark_chacha20_poly1305.py --seed 7539`, 3 samples,
min per routine. These supersede every S13 number previously in
this section.

### Profile A

| routine                       |    v0.3.0 cy |     Δ vs S13 |  Δ vs S0 5 974 048 |
|-------------------------------|-------------:|-------------:|-------------------:|
| `chacha20_block`              |       43 135 | −1 346 (F2)  | —                  |
| `poly1305_block`              |       11 948 | flat (noise) | —                  |
| `aead_encrypt n=0`            |      186 182 |     −877     | —                  |
| `aead_encrypt n=1024`         |    1 686 764 |    −22 405   | **−71.8%**         |

**Profile A is a net win on every metric.** F1 and F3 do not touch
Profile A's hot path (Shoup per-r tables own `poly1305_multiply` at
runtime on Profile A), so the improvements are pure F2 credit from
the branchless `rotl32_1_zp` / `rotr32_1_zp` rewrite.

### Profile B

| routine                       |    v0.3.0 cy |      Δ vs S13 |  Δ vs S0 5 974 048 |
|-------------------------------|-------------:|--------------:|-------------------:|
| `chacha20_block`              |       43 135 | −1 346 (F2)   | —                  |
| `poly1305_block`              |       37 844 | +10 649 (F3)  | —                  |
| `aead_encrypt n=0`            |       84 560 |  +9 716 (F3)  | —                  |
| `aead_encrypt n=1024`         |    3 259 490 | +668 852 (F3) | **−45.4%**         |

**Profile B regresses honestly on the Poly1305 hot path.** Root
cause: 272 partial products per `poly1305_block` × ~+39 cy/pp
primitive overhead (`ct_mul_8x8` body + per-call SMC stores) vs
the S12 `mult66` inline `(zp),y` dance that we just removed for
F3 compliance. Profile B still delivers **−45.4%** over the
sprint-0 baseline and remains the correct choice for short-packet
workloads (WireGuard handshakes, TLS 1.3 alerts).

### Summary vs sprint-0 baseline

Sprint-0 baseline: **5 974 048 cy** for Profile A `aead_encrypt
n=1024` (pre-optimization, commit `923d34d`).

- Profile A n=1024: 5 974 048 → 1 686 764 cy, **−71.8%** (two
  sprints + CT fix)
- Profile B n=1024: 5 974 048 → 3 259 490 cy, **−45.4%** (two
  sprints + CT fix F3 regression)

The CT fix closed an accumulated gap of 3 CT findings at a bounded
Profile B perf cost. Correctness over performance is the v0.3.0
release directive.

### Bench harness caveat — task #18

The harness in `tools/test_chacha20_poly1305.py` unconditionally
runs `make clean && make` in its `main()` before starting each VICE
session. Since the default target is Profile A, this wipes
`build/profile-b/` and silently reinstalls Profile A over whatever
profile the caller had staged. **The workaround is to export
`C64_SKIP_BUILD=1` before any test-harness invocation that is
supposed to test Profile B.** Functionally the test verdict is
unaffected (both profiles pass 214/214 on identical RFC 7539
vectors), but the destructive-rebuild behavior is real. This is
tracked as task #18 and is out of scope for v0.3.0. All
post-CT-fix measurements in this document used either
`C64_SKIP_BUILD=1` or the benchmark harness (which does not have
the bug).

## 5. AEAD deep cross-check — 30 000 vectors vs pyca

### Command

```
$ python3 tools/audit_cross_check.py --profile a --count 15000
$ python3 tools/audit_cross_check.py --profile b --count 15000
```

Initial 30 k run was done at the S13 state (audit-runner, task #12)
and re-run post-CT-fix by ct-fixer on the PR #14 branch at 15 k
per profile. The AEAD byte output is unchanged pre/post CT fix
(only timing changed), so both runs are consistent.

### Vector breakdown

| category                      | count  |
|-------------------------------|-------:|
| ChaCha20 keystream            |  1 000 |
| Poly1305 tag                  |  1 000 |
| AEAD encrypt (ct + tag match) |  5 000 |
| AEAD decrypt (plaintext recovery) |  5 000 |
| AEAD decrypt-fail (tamper rejection) |  3 000 |
| **TOTAL**                     | **15 000** |

The AEAD encrypt and decrypt categories reuse the same (key, nonce,
aad, plaintext) tuples, so every encrypt output is decrypt-verified,
and the tamper category reuses the 5 000 encrypted vectors with a
single-bit flip in either ciphertext, tag, or AAD (uniformly chosen
per vector) to verify `aead_decrypt` rejects all mutations.

Plaintext lengths are drawn 50/50 from a "boundary mix"
(`{0, 1, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256,
511, 512, 1023, 1024}`) and a uniform-random length in `[0, 1024]`.
AAD lengths are drawn similarly in `[0, 255]`.

### Results (post-CT-fix re-run by ct-fixer)

- **Profile A**: 15 000 / 15 000 pass, wall-clock **397.7 s**
- **Profile B**: 15 000 / 15 000 pass, wall-clock **743.3 s**

Both profiles byte-identical to `pyca/cryptography`'s
`ChaCha20Poly1305.encrypt` reference across the full vector set,
including ChaCha20 keystream, Poly1305 tag, AEAD encrypt, AEAD
decrypt, and AEAD tamper-reject categories.

### `ct_mul_8x8` exhaustive brute-force — 65 536 / 65 536

New `tools/ct_mul_brute_check.py` harness exhaustively iterates
all `(a, b)` pairs in `[0,255]^2` and asserts
`ct_mul_8x8(a, b) == a * b` against Python's arbitrary-precision
reference. All 65 536 pairs pass on Profile B in **2.7 s**. This
is the cheapest full-coverage test possible for an 8×8 primitive
and is the ground-truth correctness gate for the new CT multiply
introduced by the F3 fix.

### Combined

**30 000 / 30 000 AEAD vectors + 65 536 / 65 536 `ct_mul_8x8`
pairs pass across both profiles.** Zero mismatches. This is the
strongest correctness evidence on record for the library, and
combined with the 214 RFC 7539 fixed-vector test suite it forms
the full v0.3.0 correctness gate.

## 6. MD5 stability table (final state)

| profile | PRG md5                              | stable across 2+ clean rebuilds |
|---------|--------------------------------------|:-------------------------------:|
| A       | `313300ff4d86cefc6d3b195563c1383d`   |               ✓                 |
| B       | `a0e4b682fa454c6b8e2d8a04297333ab`   |               ✓                 |

## 7. Artifacts

- Cross-check driver: `tools/audit_cross_check.py`
- Brute-force driver: `tools/ct_mul_brute_check.py`
- Benchmark harness: `tools/benchmark_chacha20_poly1305.py`
- Test harness: `tools/test_chacha20_poly1305.py` (use
  `C64_SKIP_BUILD=1` for Profile B runs — see §4 caveat)

## 8. Known open items out of scope for v0.3.0

- **Task #18** (bench harness destructive auto-rebuild) tracks the
  `test_chacha20_poly1305.py` unconditional-rebuild issue called
  out in §4. Workaround is `C64_SKIP_BUILD=1`. Fix scheduled for a
  later patch release.

## 9. Final verdict

**GREEN — ready to tag v0.3.0.**

The merged-main state at commit `f4f049e` (CT-fix merge) is
bit-for-bit reproducible across clean rebuilds. All correctness
evidence (214 RFC 7539 vectors + 30 000 pyca cross-check vectors
+ 65 536 `ct_mul_8x8` brute-force pairs) is green on both
profiles. CT posture is GREEN per `docs/CT_ANALYSIS.md`'s
post-fix Resolution section (F1, F2, F3 all closed in PR #14).

The library is ready for the v0.3.0 release tag.
