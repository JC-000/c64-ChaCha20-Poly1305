# Darwin / macOS notes

System: macOS (Darwin). Use BSD-flavored utilities — do not assume GNU coreutils.

## BSD sed gotcha (FIXLABELS)
The Makefile post-processes ld65 label files into VICE format. The portable form is:
```makefile
define FIXLABELS
sed 's/^al \([0-9a-fA-F]*\)/al C:\1/' $(1) > $(1).tmp && mv $(1).tmp $(1)
endef
```
Do **not** "simplify" to `sed -i 'expr' file` — BSD sed treats the next arg as a backup suffix and emits "extra characters at the end of l command". History: PR #21, commit `73e080e` (issue: GNU/BSD divergence broke macOS builds).

## Other Darwin considerations
- `cc65` toolchain: `brew install cc65` provides `ca65` and `ld65`.
- VICE: `brew install --cask vice`; `x64sc` lands on PATH.
- No other Darwin-specific constraints documented in README/CHANGELOG/docs as of v0.3.1.

## Sibling repo c64-test-harness
The Python harness (`pip install c64-test-harness`) is dual-platform (Linux + macOS). Known macOS-26 VICE quirks are tracked in the harness repo's memories, not here.
