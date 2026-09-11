#!/usr/bin/env python3
"""verify_harness_routing.py — enforce single-choke-point device routing.

Invariant: our on-target tooling must route ALL device traffic through the
c64-test-harness *public* API, so the harness is the one place that decides
PUT vs POST, does the 84-byte chunking, and owns /Temp hygiene. Tools must
NOT reach into harness internals or hardcode their own chunking/threshold
mitigations — those defeat the single filter point and rot when the harness
moves (issue: writemem-wedge scrub 2026-09-10).

This is a static guard, red/green-able without touching a device. It flags:

  * ``<expr>._client`` — reaching the private client instead of the public
    ``transport.client`` / ``target.client`` accessor (c64-test skill core
    principle #20).
  * ``WRITE_MEM_QUERY_THRESHOLD`` — poking the client's PUT/POST split. It is
    a documented no-op (write_mem reads the lowercase instance attr), and even
    done right it is a local chunking mitigation the harness already owns.
  * assignment to ``write_mem_query_threshold`` — the same local override by
    its operative (lowercase) name. A constructor kwarg
    ``write_mem_query_threshold=128`` is flagged too, and deliberately: the
    directive is to not hardcode the threshold in *any* form.

Scope and limits (it is a regression TRIPWIRE, not a bypass-proof boundary):

  * It catches the exact forms this scrub removed and the plausible ways an
    honest edit would reintroduce them. It does NOT catch deliberately obscured
    reaches — ``getattr(x, '_client')``, ``x.__dict__['_client']``,
    ``setattr(c, 'write_mem_query_threshold', n)``, or a space-separated
    ``x . _client``. If you are writing those, you already know you are routing
    around the harness; the guard is not the thing stopping you.
  * It is a line-level grep, so it also fires on the literal patterns when they
    appear in comments or docstrings (only the space-separated ``. _client``
    form slips past). Keep prose about the anti-pattern from spelling
    ``<ident>._client`` or the uppercase constant verbatim — describe it
    instead (as this module's own prose does).

Run: ``python3 tools/verify_harness_routing.py`` (exit 0 clean, 1 on any hit).
"""

from __future__ import annotations

import pathlib
import re
import sys

# Repo root is the parent of tools/.
_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Directories whose .py files are consumer-facing device tooling.
_SCAN_DIRS = ("tools", "examples", "test_consumer")

# This file names the forbidden patterns in prose; never scan it.
_SELF = pathlib.Path(__file__).resolve()

# (regex, human explanation) — a match anywhere is a routing violation.
_FORBIDDEN = [
    (
        # Any attribute access of the private client: `<expr>._client`.
        # The lookbehind requires an identifier/closing char before the
        # dot, so this fires on transport._client, t._client, foo()._client,
        # x[0]._client — regardless of the variable name — but NOT on prose
        # that merely writes "._client" after a space (docstrings/comments).
        re.compile(r"(?<=[A-Za-z0-9_)\]])\._client\b"),
        "reaches the private ._client; use the public transport.client / "
        "target.client accessor (skill principle #20)",
    ),
    (
        re.compile(r"\bWRITE_MEM_QUERY_THRESHOLD\b"),
        "pokes WRITE_MEM_QUERY_THRESHOLD (a no-op) — do not hardcode a "
        "PUT/POST threshold; the harness owns chunking",
    ),
    (
        re.compile(r"\bwrite_mem_query_threshold\s*="),
        "assigns write_mem_query_threshold — do not hardcode a local "
        "chunking/threshold override; the harness owns it",
    ),
]


def _iter_py_files():
    for d in _SCAN_DIRS:
        base = _ROOT / d
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if ".claude/worktrees" in str(path):
                continue
            if path.resolve() == _SELF:
                continue
            yield path


def main() -> int:
    violations: list[str] = []
    for path in _iter_py_files():
        rel = path.relative_to(_ROOT)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:  # pragma: no cover
            print(f"WARN: could not read {rel}: {exc}", file=sys.stderr)
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for pattern, why in _FORBIDDEN:
                if pattern.search(line):
                    violations.append(f"{rel}:{lineno}: {why}\n    {line.strip()}")

    if violations:
        print("Harness-routing guard FAILED — device traffic must go through "
              "the harness public API:\n")
        for v in violations:
            print(v)
        print(f"\n{len(violations)} violation(s).")
        return 1

    print("Harness-routing guard OK: no private-client reach, no hardcoded "
          "chunking/threshold override.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
