#!/usr/bin/env python3
"""Reject ca65-synthesised macro-local names in a linker label file (issue #117).

`.local` inside a macro makes ca65 synthesise `LOCAL-MACRO_SYMBOL-NNNN`, once
per expansion, and ld65 emits those into the `-Ln` label file a consumer links
against. The `-` is outside the character set a VICE label parser accepts, so
the label file is rejected downstream. The addresses are correct: this is
symbol-output noise, not a correctness defect.

WHY THIS IS A TOOL AND NOT A GREP IN THE MAKEFILE. A bare "grep finds nothing"
passes just as happily on an empty or missing file — the vacuous-absence shape
this fleet keeps finding. The absence assertion is therefore gated behind two
positive controls: the file must be non-empty, and it must contain a sentinel
label that has to be there. Those legs are only trustworthy if they can be
driven red, and they cannot be driven red through the Makefile: `profile-a`
and `profile-b` are .PHONY, so they re-link and regenerate labels.txt on every
invocation, erasing any mutation of the file. Pointing this tool straight at a
crafted file is what makes all three legs demonstrable:

    printf '' > /tmp/empty.txt          && python3 tools/verify_label_hygiene.py /tmp/empty.txt
    grep -v ' \\.aead_encrypt$' real.txt > /tmp/nosent.txt \\
                                        && python3 tools/verify_label_hygiene.py /tmp/nosent.txt

Both must exit 1. Exit 0 only ever means "I read a real label file for this
library and it carried no synthesised macro-local names".
"""
import sys

SENTINEL = ".aead_encrypt"
LEAK = "LOCAL-MACRO_SYMBOL"


def check(path):
    """Return (ok, message). ok is False for every reason including unreadable."""
    try:
        with open(path) as f:
            lines = [ln.rstrip("\n") for ln in f]
    except OSError as e:
        return False, f"FAIL: cannot read {path}: {e}\n      Nothing was examined."

    if not lines:
        return False, (f"FAIL: {path} is empty — an absence check against it would\n"
                       f"      pass vacuously. Nothing was examined.")

    if not any(ln.endswith(" " + SENTINEL) for ln in lines):
        return False, (f"FAIL: {path} has no '{SENTINEL}' sentinel label "
                       f"({len(lines)} lines).\n"
                       f"      This is not a label file for this library, so an\n"
                       f"      absence result from it means nothing.")

    leaked = [ln for ln in lines if LEAK in ln]
    if leaked:
        body = "\n".join("        " + ln for ln in sorted(leaked))
        return False, (f"FAIL: {path} leaks {len(leaked)} ca65-synthesised "
                       f"macro-local label(s) (issue #117):\n{body}\n"
                       f"      Use unnamed ':' labels in the macro, not '.local'.")

    return True, (f"ok — {path}: {len(lines)} labels, sentinel present, "
                  f"0 synthesised macro-locals")


def main(argv):
    if len(argv) < 2:
        sys.exit("usage: verify_label_hygiene.py <labels.txt> [labels.txt ...]")
    failed = 0
    for path in argv[1:]:
        ok, msg = check(path)
        print(("verify-label-hygiene: " if ok else "") + msg)
        if not ok:
            failed = 1
    return failed


if __name__ == "__main__":
    sys.exit(main(sys.argv))
