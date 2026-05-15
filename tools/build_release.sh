#!/bin/bash
# tools/build_release.sh -- build a reproducible source tarball for a tagged release.
#
# Usage:
#   tools/build_release.sh <tag>
#   e.g. tools/build_release.sh v0.5.0
#
# Output: c64-ChaCha20-Poly1305-<tag>.tar.gz in the repo root, plus the
# byte size and SHA256 printed to stdout. The script is location-aware
# and can be invoked from anywhere.
#
# Determinism: git archive is byte-deterministic for a given commit,
# and `gzip -n` drops the gzip timestamp/filename header. The same tag
# therefore always produces a byte-identical tarball. Re-running this
# script must reproduce the SHA256 recorded in the matching
# docs/RELEASE_NOTES_<tag>.md.
#
# File list: the canonical consumer-vendoring set. `src/lib/*.s` are
# the library modules consumers link; `src/main.s` is the library's
# own test/bench driver (consumers omit it per docs/INTEGRATION.md but
# it ships in the tarball so the upstream build is reproducible from
# the artifact). `src/include/` ships the vendored ca65hl macros and
# smc.inc helpers. `Makefile` + `src/c64.cfg` reproduce the reference
# PRG. `test/rfc7539_vectors.json` is included so consumers can write
# their own RFC 7539 cross-checks.
#
# Make convenience target: `make dist VERSION=v0.5.0`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: $0 <tag>" >&2
  exit 1
fi

if ! git rev-parse "$TAG" >/dev/null 2>&1; then
  echo "tag '$TAG' not found (run 'git fetch --tags' to refresh)" >&2
  exit 1
fi

NOTES="docs/RELEASE_NOTES_${TAG}.md"
if ! git cat-file -e "${TAG}:${NOTES}" 2>/dev/null; then
  echo "release notes '${NOTES}' not present at tag '${TAG}'" >&2
  exit 1
fi

OUT="c64-ChaCha20-Poly1305-${TAG}.tar.gz"

git archive \
  --prefix="c64-ChaCha20-Poly1305-${TAG}/" \
  --format=tar \
  "$TAG" \
  src/c64.cfg src/main.s \
  src/include/ca65hl src/include/smc.inc \
  src/lib/constants_lib.s src/lib/data_lib.s \
  src/lib/word32_lib.s src/lib/chacha20_lib.s \
  src/lib/poly1305_lib.s src/lib/chacha20poly1305_lib.s \
  Makefile README.md CHANGELOG.md LICENSE \
  docs/API.md docs/INTEGRATION.md docs/MEMORY_MAP.md \
  docs/AUDIT.md docs/CT_ANALYSIS.md \
  test/rfc7539_vectors.json \
  "$NOTES" \
  | gzip -n -9 > "$OUT"

SIZE=$(wc -c < "$OUT" | tr -d ' ')
SHA=$(shasum -a 256 "$OUT" | cut -d' ' -f1)

echo "Built ${OUT}"
echo "  Size:   ${SIZE} bytes"
echo "  SHA256: ${SHA}"
