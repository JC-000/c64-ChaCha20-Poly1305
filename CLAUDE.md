# Working agreement for this repo

Applies to every feature, bug fix and issue worked here, by a human or by Claude.
Two things are **mandatory**: a red/green cycle, and an adversarial review pass.
Neither is waived because a change "looks small" — the smallest changes here are
where the defects have actually been.

## 1. Red/green, always in that order

No behaviour change lands without a check that was **observed failing before the
fix and passing after**. Order matters: a check written after the fix has never
been shown capable of failing.

1. **Red.** Write or extend the check. Run it against the *unfixed* tree and
   record the failure output (paste it in the PR body).
2. **Green.** Make the change. Re-run the same check unmodified.
3. **Mutate.** Break the fixed thing on purpose — stash the guard, misalign the
   table, revert the one line — and confirm the check goes red again. Restore.

The mutation step is the one that catches the failure mode this repo keeps
producing: **a check that cannot fail.** It has five forms, and passing is not
evidence against any of them:

- **Absence asserted against an empty dump.** MEASURED on od65 V2.18, because
  the obvious guess is wrong: a **missing** object exits **1**, so that case
  protects itself. The three that really do give an empty dump at exit 0 are
  **no input file at all**, **an `.a` archive** (`od65` prints
  `(no xo65 object file)` and exits 0 — `Makefile:798` already knows this), and
  **a swallowed exit status** (see the substitution form below). Guard with a
  sentinel proving the dump is non-empty, and reconcile the extracted count
  against a raw `grep -c 'Name:'` on **both** sides of any before/after diff —
  a diff agrees wrongly when one extractor breaks symmetrically.
- **The check and the checked thing are the same artifact.** Never compare a
  built artifact against a transcribed copy of its own numbers. Derive both
  sides from the build.
- **The check exercises a configuration nobody builds.** Say which kind you
  have: a demonstration on a configuration no consumer builds is evidence
  about the **shipped surface**, not about any live integration — both are
  worth checking, and a wrong `RESIDENT_BYTES` literal is wrong whether or not
  anyone has adopted that variant yet. What this forbids is the narrow thing:
  **never invent a configuration that exists only to make the check pass.**
  Do NOT read this as licence to delete legs covering unadopted variants.
  The live-integration axis is separately weak here and known: `c64-wireguard`
  builds `make lib CONTRACT_DEFINES='-D SHARED_SQTAB_INIT=1 -D
  SHARED_CT_MUL_8X8=1 -D POLY1305_MULTIPLY_ROLLED_OUTER=1 -D
  LIB_NO_BARE_EXPORTS=1'`, and **no leg of any gate builds that combination**.
- **A failure leg that does not propagate.** `X || (echo FAIL; exit 1)` exits
  the *subshell*, not the recipe. Use `|| { …; exit 1; }` or set `fail=1` and
  check it at the end — and prove it by making the leg fire.
- **A command substitution that swallows the exit status.** `dump=$(od65 … |
  awk …)` takes awk's status, so a missing `od65` yields an empty string and
  every zero-count absence leg passes. This is contract #194, live in that
  repo's own `make verify` gate.

The bar is **"demonstrated capable of failing, for a configuration a real
consumer builds"** — not "can go red".

### Repo specifics that have bitten us

- **Rebuild before mutating.** The runners boot pre-built PRGs; a skipped
  `make profile-a`/`profile-b` gives a false PASS on the *old* binary.
  `make test` and `make test-fuzz` rebuild for you; a hand-run tool does not.
- **On-target tests go through the c64-test harness** (the `c64-test` skill,
  `UnifiedManager`/`ViceInstanceManager`/`DeviceLock`). Never drive VICE
  directly, never `pkill`. On an Ultimate 64, call `set_turbo_mhz(client, 1)`
  before any timing run — turbo survives `client.reset()`.
- **Footprint is measured, never inferred.** `make verify-resident-bytes`
  (`tools/measure_resident_bytes.py`) runs **eleven** legs as of v0.12.0 — the
  3 targets × 2 profiles matrix, plus the configuration `c64-wireguard`
  actually builds, each §8 deferral switch alone, and the two knob axes
  `lib_manifest.s` models nowhere (`POLY1305_MULTIPLY_ROLLED`,
  `CHACHA20_USE_WORD32`). They cover **five** `RESIDENT_BYTES` literal sites in
  `src/lib/lib_manifest.s`; legs and sites differ because several
  configurations resolve to the same branch. `verify-label-hygiene` covers
  **six** configurations — five shipped plus the consumer's — and examines
  eight inputs, since each profile contributes a label file *and* an object.
  **Count these by running the target, not from this list**: every one of these
  figures was stale within a day of being written. Do not read footprint off
  the linked PRG.
- **Never byte-compare `.o`/`.a` files** — ca65 stamps `OPT_DATETIME`. Compare
  linked PRGs or `od65` dumps.
- **Assert diff SCOPE, not just diff content.** `git diff <base> -- <file> |
  grep '^@@'`, then confirm every hunk falls inside the range you meant to
  touch. A scripted edit once deleted this repo's CHANGELOG title and format
  declaration; every check written for it was section-scoped and therefore
  blind to a hunk outside every section.
- **Exclude `precalc_table.inc` from every sweep.** The contract requires it be
  copied verbatim and its comments name `sqtab`, so any grep for the shared
  primitive macros or table names false-positives in every repo, forever.
- **`od65 --dump-exports` name parsing:** at name length exactly 24 the padding
  after `Name:` is zero width, so `awk '{print $2}'` and `Name:\s+"` silently
  drop the row. Use `\s*`, a quote-anchored sed, or a raw substring count.

### Which check to reach for

| Change touches | Red/green vehicle |
|---|---|
| Crypto behaviour | `make test` (RFC 7539 vectors, both profiles), `make test-fuzz` against pyca |
| A build/link invariant | a `.assert`/`lderror` — then stash it and confirm the link emits the bad artifact |
| Exported symbol sets | `make lib-verify-isolation` / `lib-verify-shared` + a raw row-count reconciliation |
| Footprint | `make verify-resident-bytes` |
| Knob handling | `make verify-knob-staleness` |

## 2. Adversarial review before merge

**This section binds this repo's own gates.** The `make verify-*` targets are
checks like any other and get the same treatment — that is precisely how a
vacuous `verify-addrsize` shipped in the sibling repo (contract #194) while its
own `make verify` reported green.

Every PR gets a pass from an adversarial reviewer (see
`.claude/agents/adversarial-reviewer.md`; launch it with the `Agent` tool, or
`/code-review high` for the code-only leg — a harness-provided skill with
effort levels `low`/`medium`/`high`/`max`/`ultra`; if your harness does not
list it, use the agent and say so rather than reporting a step you could not
run). It is briefed to **break the
claims**, not to review the code.

This is not ceremony. Across every review round run here, **essentially all
findings were in evidence, justification or docs — almost none in the code
change itself.** The code was right; the reasons given for it were not. What
recurs: asserting a toolchain mechanism without running it, conflating a knob
with the thing it controls, a negative test that proves coverage which already
existed, a guard that checks names when the invariant is addresses, conformance
bought by defanging a check, and a file quoting a superseded clause version.

Rules for the pass:

- **The reviewer must be fresh, not merely someone else.** In a
  single-maintainer repo "independent of the author" is unfollowable; the
  discriminator is context, not identity. The pass must come from an agent or
  context that did **not** draft the change.
- Give the reviewer the **exact claims and commit hashes** to attack. Vague
  briefs produce vague reviews.
- **Citation duty: grep every quote and every `file:line` an agent hands you.**
  Fabricated verbatim quotes have been produced on this fleet, attached to
  otherwise-sound substance — which is exactly what makes them hard to catch.
- **The churn test, as a count.** Before commissioning work that exists to
  discharge an obligation, answer two falsifiable questions: **what breaks if
  the obligation does not exist**, and **how many adopters does it move?**
  ("Easier integration", "a new capability", "a measurable improvement" is a
  disjunction every proponent can satisfy and names no measurand — it was
  rejected upstream for exactly that.) The model is the **contract repo's**
  ruling on its issue #188 — `c64-lib-contract/CHANGELOG.md:10`, not this
  repo's file: *"Measured before ruling: of the five adopters only
  c64-nist-curves is affected."*
- **Record the disposition.** A review that found things and left no record did
  not happen. Every finding gets an accepted/rejected verdict in the PR body or
  a PR comment, with the reason — including the rejections.
- Demand a **control** alongside every positive result.
- Never assert a mechanism you have not run. "ca65 does X" is a claim; the
  transcript is evidence.
- Prefer "build the artifact" over "add another list to keep in sync".
- Correct the record **loudly** in the PR body and commit message rather than
  quietly patching. A correction that replaces a true statement with a false
  one has happened here.
- Stop when a round returns **no finding that changes the artifact**. That is
  the signal the change is done, not a reason to have skipped the pass.

A PR body is expected to carry: the red output, the green output, the mutation
result, and what the adversarial pass tried and failed to break.

## 3. Process guards

- **Never open a stacked PR.** Merging one lands work on its base branch, not
  `main`, silently. After any merge, verify with
  `git merge-base --is-ancestor <sha> origin/main`.
- **Another session works these repos between turns.** Fetch every sibling repo
  and run `gh pr list` before opening a PR.
- **Count at symbol granularity**, never `grep -c`, when the question is *how
  many symbols*. This does **not** forbid the raw `grep -c 'Name:'` row count
  above: that one asks *how many rows did the dump emit*, which is exactly what
  reconciles an extractor, and a symbol-granular count cannot do that job. Row
  count to validate an instrument; symbol granularity to answer about symbols.
  No brace-shorthand overclaims, no "closed via PR X" without checking.
- **`gh` bodies go in a file** — `--body-file`, never `--body`. And re-read a
  review thread immediately before acting on it; it may have moved.
- **Never mark an adopter cell shipped** without reading that adopter's source
  at the tag.
- **Contract work:** act only on a **tagged** clause, never against an open
  arbitration issue, and re-fetch the contract immediately before implementing.
  One conformance record per release, not one PR per revision.
