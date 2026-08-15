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
# File list: the canonical consumer-vendoring set. `src/lib/*.s` plus
# `src/zp_config.s` / `src/lib_version.s` / `src/precalc_table.inc`
# are the modules consumers link (all mandatory on the v0.6.0+ link
# line per docs/INTEGRATION.md); `src/main.s` is the library's
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
  src/include/ca65hl src/include/smc.inc src/include/sqtab_base.inc \
  src/zp_config.s src/lib_version.s src/precalc_table.inc \
  src/lib/constants_lib.s src/lib/data_lib.s \
  src/lib/word32_lib.s src/lib/chacha20_lib.s \
  src/lib/poly1305_lib.s src/lib/chacha20poly1305_lib.s \
  src/lib/lib_manifest.s \
  Makefile README.md CHANGELOG.md LICENSE \
  docs/API.md docs/INTEGRATION.md docs/MEMORY_MAP.md \
  docs/AUDIT.md docs/CT_ANALYSIS.md \
  docs/precalc-tables.md docs/REPRO_CHECK.md \
  tools/verify_zp_usage.py \
  test/rfc7539_vectors.json \
  "$NOTES" \
  | gzip -n -9 > "$OUT"

# ---------------------------------------------------------------------------
# Manifest ratchet.
#
# The file list above is an explicit allowlist — the right shape for a
# reproducible tarball, but it fails SILENTLY when a source grows a new
# dependency: git archive omits the unlisted file, the tarball builds far
# enough to look fine, and the break surfaces only in whichever target needs
# it. That is exactly how src/include/sqtab_base.inc was omitted from the
# first v0.9.0 tarball — Profile A built clean and `make lib` failed, because
# only Profile B includes it.
#
# So verify the shipped tree closes over its own .include graph, and that
# every tools/ script a shipped make target invokes is present. Turns a silent
# omission into a named failure at packaging time.
# ---------------------------------------------------------------------------
CHECKDIR="$(mktemp -d)"
trap 'rm -rf "$CHECKDIR"' EXIT
tar xzf "$OUT" -C "$CHECKDIR"
ROOT_CHECK="$CHECKDIR/c64-ChaCha20-Poly1305-${TAG}"
missing=0

incs="$(find "$ROOT_CHECK/src" \( -name '*.s' -o -name '*.inc' \) -print0 \
        | xargs -0 grep -ho '\.include "[^"]*"' 2>/dev/null \
        | sed 's/.*"\(.*\)"/\1/' | sort -u)"
for inc in $incs; do
  if [ -z "$(find "$ROOT_CHECK/src" -name "$inc" -print -quit)" ]; then
    echo "MANIFEST ERROR: a shipped source .include's '$inc', which the tarball omits" >&2
    missing=1
  fi
done

# Scoped deliberately. The Makefile also invokes tools/bench_granular.py and
# tools/build_release.sh, and those are correctly ABSENT from a source tarball:
# the bench targets need the c64-test-harness (not shipped, and not a build
# dependency), and re-rolling a release from inside a release tarball is not a
# supported operation. Only tools a consumer needs to BUILD or VERIFY the
# library are required here.
REQUIRED_TOOLS="tools/verify_zp_usage.py"
for t in $REQUIRED_TOOLS; do
  if [ ! -f "$ROOT_CHECK/$t" ]; then
    echo "MANIFEST ERROR: the shipped Makefile invokes '$t', which the tarball omits" >&2
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  echo "tarball manifest incomplete — $OUT would not build from a clean extraction" >&2
  rm -f "$OUT"
  exit 1
fi

SIZE=$(wc -c < "$OUT" | tr -d ' ')
SHA=$(shasum -a 256 "$OUT" | cut -d' ' -f1)

echo "Built ${OUT}"
echo "  Size:   ${SIZE} bytes"
echo "  SHA256: ${SHA}"
