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

Both must exit 1. The tool's own exit code is 0 or 1 — a `2` seen at the shell
is make's code for a failed recipe, not this tool's.

Exit 0 means: every input named was read, each carried its sentinel, and none
carried a synthesised macro-local name. It covers label files AND objects,
because only two configurations produce a label file while consumers link the
archives -- see check_object() for the leak that fact allowed.
"""
import sys

SENTINEL = ".aead_encrypt"
LEAK = "LOCAL-MACRO_SYMBOL"

# Object-level sentinel and leak marker. The synthesised name is stored in the
# object's symbol table -- that is how ld65 has it to emit -- so a raw byte
# search finds it with no parser to break.
OBJ_SENTINEL = b"aead_encrypt"
OBJ_LEAK = b"LOCAL-MACRO_SYMBOL"


def check_object(path):
    """Scan a built .o for synthesised macro-local names.

    WHY OBJECTS AND NOT JUST LABEL FILES. Only profile-a and profile-b produce
    a label file, but consumers link the ARCHIVES, and the three archive
    variants are assembled with different defines (LIB_VARIANT_AEAD_ONLY,
    SHARED_SQTAB_INIT/SHARED_CT_MUL_8X8). A `.local` inside an `.ifdef` on one
    of those defines leaks into that archive and reaches a consumer's label
    file while both profiles stay clean -- demonstrated: a probe consumer
    linked against chacha20poly1305-aead-only.a carried
    `al 0045C5 .LOCAL-MACRO_SYMBOL-0000` while the profile-only check reported
    ok. No consumer links that variant today (c64-wireguard/Makefile:75 takes
    the full archive), so this closes the gap before it has a victim rather
    than after.
    """
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError as e:
        return False, f"FAIL: cannot read {path}: {e}\n      Nothing was examined."

    if not blob:
        return False, (f"FAIL: {path} is empty — an absence check against it would\n"
                       f"      pass vacuously. Nothing was examined.")

    if OBJ_SENTINEL not in blob:
        return False, (f"FAIL: {path} ({len(blob)} B) does not contain "
                       f"'{OBJ_SENTINEL.decode()}'.\n"
                       f"      This is not the AEAD translation unit, so an absence\n"
                       f"      result from it means nothing.")

    if OBJ_LEAK in blob:
        n = blob.count(OBJ_LEAK)
        return False, (f"FAIL: {path} carries {n} ca65-synthesised macro-local "
                       f"name(s) (issue #117).\n"
                       f"      This object goes into an archive a consumer links, so the\n"
                       f"      name reaches their label file even though no profile PRG\n"
                       f"      shows it. Use unnamed ':' labels in the macro, not '.local'.")

    return True, (f"ok — {path}: {len(blob)} B, sentinel present, "
                  f"0 synthesised macro-locals")


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
    args = argv[1:]
    if not args:
        sys.exit("usage: verify_label_hygiene.py <labels.txt|object.o> [...]\n"
                 "       .o arguments are scanned as objects, everything else as\n"
                 "       a linker label file.")
    failed = 0
    examined = 0
    for path in args:
        ok, msg = (check_object(path) if path.endswith(".o") else check(path))
        print(("verify-label-hygiene: " if ok else "") + msg)
        examined += 1
        if not ok:
            failed = 1
    # Reconciliation: refuse to report success for a run that examined nothing.
    if examined == 0:
        print("FAIL: no inputs examined — this run proves nothing.")
        return 1
    return failed


if __name__ == "__main__":
    sys.exit(main(sys.argv))
