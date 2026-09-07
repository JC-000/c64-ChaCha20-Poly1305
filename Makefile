PRG_NAME = c64_chacha20_poly1305.prg
LABELS_NAME = labels.txt

# Default (top-level) output paths. `make` / `make all` builds Profile A
# into these paths so existing tooling (test harness, benchmark) keeps
# working without any path flags.
PRG = build/$(PRG_NAME)
LABELS = build/$(LABELS_NAME)

# Per-profile output directories. `make profile-a` / `make profile-b`
# build into these so both profiles can coexist on disk, then mirror the
# resulting PRG+labels into build/ for the default tool paths.
PROFILE_A_DIR = build/profile-a
PROFILE_B_DIR = build/profile-b
PROFILE_BR_DIR = build/profile-b-rolled
PROFILE_BO_DIR = build/profile-b-rolled-outer

# Library archive outputs (c64-lib-contract SPEC §6). `make lib` builds
# the full Profile-B archive `build/lib/chacha20poly1305.a`. Each
# `make lib-<variant>` target builds a trimmed archive next to it as
# `build/lib/chacha20poly1305-<variant>.a`. Per-variant object
# files live in their own subdir (`build/lib/objs/`, `build/lib/objs-
# <variant>/`) so the variants' `.ifndef`-gated assembly results don't
# clobber Profile A/B's .o cache.
LIB_DIR        = build/lib
LIB_OBJS_DIR   = $(LIB_DIR)/objs
# Canonical archive basename per contract §6.1: <shortname>[-<variant>].a
# where <shortname> is the §1 prefix lowercased. v0.9.0 names our previous
# `c64-chacha20-poly1305` spelling a deprecated dialect.
LIB_NAME       = chacha20poly1305

# Deprecated basename, shipped alongside the canonical one for one MINOR
# release per the §6.5 rename window, dropped at the next MAJOR. Archives
# can dual-name (unlike archive members), so both are produced from the
# same objects and are byte-identical copies.
LIB_NAME_DEPRECATED = c64-chacha20-poly1305

LIB_FULL_AR    = $(LIB_DIR)/$(LIB_NAME).a
LIB_FULL_AR_DEPRECATED       = $(LIB_DIR)/$(LIB_NAME_DEPRECATED).a
LIB_AEAD_ONLY_AR_DEPRECATED  = $(LIB_DIR)/$(LIB_NAME_DEPRECATED)-aead-only.a
LIB_APP_OWNED_AR_DEPRECATED  = $(LIB_DIR)/$(LIB_NAME_DEPRECATED)-app-owned.a

# Per-variant archive paths. New variants get one line each here plus a
# build recipe below; the rule shape is generic.
LIB_AEAD_ONLY_AR        = $(LIB_DIR)/$(LIB_NAME)-aead-only.a
LIB_AEAD_ONLY_OBJS_DIR  = $(LIB_DIR)/objs-aead-only

# app-owned variant (contract §8.0 APP_OWNED, issue #74): the consumer's
# own modules provide BOTH shared primitives, and this library defers
# both. Built with SHARED_SQTAB_INIT + SHARED_CT_MUL_8X8, so the §8.1
# sqtab init and the §8.3 ct_mul_8x8 body are gated out and imported
# instead. Its manifest is truthful by construction as of issue #47 —
# SHARED_PRIMITIVES = $0000, SHARED_CONSUMES = $0005 — so a consumer
# gets a composable archive without ar65 member surgery.
LIB_APP_OWNED_AR        = $(LIB_DIR)/$(LIB_NAME)-app-owned.a
LIB_APP_OWNED_OBJS_DIR  = $(LIB_DIR)/objs-app-owned

# Consumer-facing header and example cfg, emitted alongside the archive so
# a consumer who fetches build/lib/ gets an interface and a starter linker
# config, not just an .a to reverse-engineer. They are copied, not
# generated: the canonical sources are src/chacha20poly1305.inc and
# cfg/chacha20poly1305-example.cfg, which is what the repo's own docs and
# examples reference.
#
# NOT contract-required. Contract v1.0.0's §6.1 briefly did require them;
# it was withdrawn at v1.1.1 (c64-lib-contract#178) on the merits — the
# clause mandated an artifact while naming neither a path nor a symbol for
# it. We keep them as a local choice. If you are removing them, that is
# permitted by the contract; docs/INTEGRATION.md and the README's
# conformance section both describe them, so update those too.
LIB_INC         = $(LIB_DIR)/$(LIB_NAME).inc
LIB_EXAMPLE_CFG = $(LIB_DIR)/cfg/$(LIB_NAME)-example.cfg

CA65 = ca65
LD65 = ld65

# Consumer-supplied assembler defines (contract §6 A.1 / issue #74).
# Appended to every ca65 invocation so a consumer can reach §8.1's
# LIB_SHARED_SQTAB_BASE, the §8 SHARED_* deferral switches, and
# LIB_NO_BARE_EXPORTS without clobbering the base flags:
#
#   make lib CONTRACT_DEFINES="-D LIB_SHARED_SQTAB_BASE=0x9000"
#   make lib-app-owned CONTRACT_DEFINES="-D LIB_NO_BARE_EXPORTS=1"
#
# USE 0x HEX, NOT $ HEX. `-D FOO=$9000` is mangled before ca65 ever sees
# it: the shell expands `$9` as a positional parameter, which is empty,
# leaving `-D FOO=000` — decimal zero. It does not error or warn. Pasted
# into a sqtab override that silently places the 1 KB table at $0000.
# ca65 accepts both spellings; only 0x survives shell and make unquoted.
#
# Do NOT override CA65FLAGS itself — that drops the -I include paths and
# fails with "Cannot open include file 'precalc_table.inc'". Overriding
# CA65 works but silently drops -t c64 -g unless you repeat them.
#
# NOTE ON ZP SLOTS: there is deliberately no CONTRACT_ZP_DEFINES here.
# This library ships no ZP-defining member in its archives — consumers
# assemble their own src/zp_config.s, so §2 slot overrides belong in
# that assembly, not in a define forwarded through these targets. See
# docs/INTEGRATION.md.
CONTRACT_DEFINES ?=

# Back-compat alias for the pre-ratification spelling. Both are appended,
# so an existing caller keeps working.
EXTRA_CA65FLAGS ?=

CA65FLAGS = -t c64 -g -I src/include -I src/lib -I src $(CONTRACT_DEFINES) $(EXTRA_CA65FLAGS)
CFG = src/c64.cfg

# --- §6.3 knob-staleness guard (contract SPEC v0.10.5, issue #86) ----------
# CONTRACT_DEFINES / EXTRA_CA65FLAGS reach every ca65 invocation through
# CA65FLAGS above, but they reach no make *prerequisite*: the object cache is
# keyed on source mtimes alone. So a re-invocation with different knobs reused
# every stale object and exited 0 with an artifact other than the one
# requested — the v0.10.5 §6.3 shape-3 "silent no-op" (measured on issue #86:
# `make lib CONTRACT_DEFINES="-D POLY1305_PROFILE_LONG=1"` over a default tree
# answered "Nothing to be done" and shipped the Profile B archive; the same
# command against a clean build/lib correctly ships Profile A).
#
# The stamp records the flattened knob string at parse time. When it changes,
# every object and archive is invalidated — the knobs reach every TU, so every
# object genuinely is stale — and the requested configuration is built.
# Unchanged knobs leave the tree alone, so same-knob incremental builds stay
# incremental. Pinned by `make verify-knob-staleness`.
#
# This is the c64-nist-curves CONTRACT_STAMP idiom, widened from that repo's
# flat `$(BUILD_DIR)/*.o` to a `find` because our objects live in seven
# per-profile and per-variant directories.
CONTRACT_STAMP := build/.contract-defines.stamp
CURRENT_KNOBS  := $(strip $(CONTRACT_DEFINES) @ $(EXTRA_CA65FLAGS))
STORED_KNOBS   := $(strip $(shell cat $(CONTRACT_STAMP) 2>/dev/null))
ifneq ($(CURRENT_KNOBS),$(STORED_KNOBS))
$(shell mkdir -p build $(LIB_DIR); \
        find build -name '*.o' -delete; \
        rm -f $(LIB_DIR)/*.a; \
        printf '%s' '$(CURRENT_KNOBS)' > $(CONTRACT_STAMP))
endif

# --- Module list -----------------------------------------------------------
# Each source file compiles to its own .o. Order matters only for the
# link line (ld65 resolves symbols regardless but segment packing
# reflects link order). Constants_lib is equates-only and is .include'd
# by the modules that need ZP equate values, so it has no .o of its own.
# zp_config is a standalone .s module that owns the .exportzp slot
# allocation; consumers can override addresses by pre-defining symbols
# before zp_config.s is assembled, or by swapping the file outright.
MODULES = main zp_config word32_lib chacha20_lib poly1305_lib shared_sqtab_init shared_prod_scratch mul_8x8_legacy shared_ct_mul poly1305_ripple poly1305_core chacha20poly1305_lib data_lib lib_version lib_manifest precalc_manifest

# Modules that go into the consumer-facing .a archive. `main.o` ships
# the standalone-PRG entry stub (`lib_entry: rts`) which a consumer
# does not need — they ship their own `main`. `zp_config.o` is also
# excluded: consumers commit to their own ZP layout via -D
# overrides at consumer-assemble time, so bundling the library's
# default-bound zp_config.o would either (a) silently re-bind their
# slots, or (b) cause duplicate-symbol errors if they assemble their
# own zp_config.s. Everything else (the actual library code, data,
# version/manifest equates) is included.
LIB_MODULES = word32_lib chacha20_lib poly1305_lib shared_sqtab_init shared_prod_scratch mul_8x8_legacy shared_ct_mul poly1305_ripple poly1305_core chacha20poly1305_lib data_lib lib_version lib_manifest precalc_manifest

SRCS_MAIN     = src/main.s
SRCS_LIB      = $(wildcard src/lib/*.s)
SRCS_INCLUDES = src/lib/constants_lib.s

# Object file list per profile (order matches MODULES).
A_OBJS = $(PROFILE_A_DIR)/main.o \
         $(PROFILE_A_DIR)/zp_config.o \
         $(PROFILE_A_DIR)/word32_lib.o \
         $(PROFILE_A_DIR)/chacha20_lib.o \
         $(PROFILE_A_DIR)/poly1305_lib.o \
         $(PROFILE_A_DIR)/shared_sqtab_init.o \
         $(PROFILE_A_DIR)/shared_prod_scratch.o \
         $(PROFILE_A_DIR)/mul_8x8_legacy.o \
         $(PROFILE_A_DIR)/shared_ct_mul.o \
         $(PROFILE_A_DIR)/poly1305_ripple.o \
         $(PROFILE_A_DIR)/poly1305_core.o \
         $(PROFILE_A_DIR)/chacha20poly1305_lib.o \
         $(PROFILE_A_DIR)/data_lib.o \
         $(PROFILE_A_DIR)/lib_version.o \
         $(PROFILE_A_DIR)/lib_manifest.o \
         $(PROFILE_A_DIR)/precalc_manifest.o

B_OBJS = $(PROFILE_B_DIR)/main.o \
         $(PROFILE_B_DIR)/zp_config.o \
         $(PROFILE_B_DIR)/word32_lib.o \
         $(PROFILE_B_DIR)/chacha20_lib.o \
         $(PROFILE_B_DIR)/poly1305_lib.o \
         $(PROFILE_B_DIR)/shared_sqtab_init.o \
         $(PROFILE_B_DIR)/shared_prod_scratch.o \
         $(PROFILE_B_DIR)/mul_8x8_legacy.o \
         $(PROFILE_B_DIR)/shared_ct_mul.o \
         $(PROFILE_B_DIR)/poly1305_ripple.o \
         $(PROFILE_B_DIR)/poly1305_core.o \
         $(PROFILE_B_DIR)/chacha20poly1305_lib.o \
         $(PROFILE_B_DIR)/data_lib.o \
         $(PROFILE_B_DIR)/lib_version.o \
         $(PROFILE_B_DIR)/lib_manifest.o \
         $(PROFILE_B_DIR)/precalc_manifest.o

# Profile B + rolled poly1305_multiply (issue #34 alternative 2).
# Identical to Profile B except poly1305_lib.o is built with
# -DPOLY1305_MULTIPLY_ROLLED=1, which switches poly1305_multiply
# from the 17x16 unrolled macro expansion to a runtime nested loop.
# All other objects are byte-identical to Profile B so they're
# rebuilt in this dir for hermeticity (no cross-dir .o sharing).
BR_OBJS = $(PROFILE_BR_DIR)/main.o \
          $(PROFILE_BR_DIR)/zp_config.o \
          $(PROFILE_BR_DIR)/word32_lib.o \
          $(PROFILE_BR_DIR)/chacha20_lib.o \
          $(PROFILE_BR_DIR)/poly1305_lib.o \
          $(PROFILE_BR_DIR)/shared_sqtab_init.o \
          $(PROFILE_BR_DIR)/shared_prod_scratch.o \
          $(PROFILE_BR_DIR)/mul_8x8_legacy.o \
          $(PROFILE_BR_DIR)/shared_ct_mul.o \
          $(PROFILE_BR_DIR)/poly1305_ripple.o \
          $(PROFILE_BR_DIR)/poly1305_core.o \
          $(PROFILE_BR_DIR)/chacha20poly1305_lib.o \
          $(PROFILE_BR_DIR)/data_lib.o \
          $(PROFILE_BR_DIR)/lib_version.o \
          $(PROFILE_BR_DIR)/lib_manifest.o \
          $(PROFILE_BR_DIR)/precalc_manifest.o

BO_OBJS = $(PROFILE_BO_DIR)/main.o \
          $(PROFILE_BO_DIR)/zp_config.o \
          $(PROFILE_BO_DIR)/word32_lib.o \
          $(PROFILE_BO_DIR)/chacha20_lib.o \
          $(PROFILE_BO_DIR)/poly1305_lib.o \
          $(PROFILE_BO_DIR)/shared_sqtab_init.o \
          $(PROFILE_BO_DIR)/shared_prod_scratch.o \
          $(PROFILE_BO_DIR)/mul_8x8_legacy.o \
          $(PROFILE_BO_DIR)/shared_ct_mul.o \
          $(PROFILE_BO_DIR)/poly1305_ripple.o \
          $(PROFILE_BO_DIR)/poly1305_core.o \
          $(PROFILE_BO_DIR)/chacha20poly1305_lib.o \
          $(PROFILE_BO_DIR)/data_lib.o \
          $(PROFILE_BO_DIR)/lib_version.o \
          $(PROFILE_BO_DIR)/lib_manifest.o \
          $(PROFILE_BO_DIR)/precalc_manifest.o

.PHONY: verify all clean run profile-a profile-b profile-b-rolled profile-b-rolled-outer dist lib lib-aead-only lib-app-owned lib-verify-shared bench bench-check verify-zp-usage verify-knob-staleness verify-label-hygiene lib-verify-isolation test test-fuzz test-fuzz-full

# --- Bench configuration (granular per-symbol benchmark) ------------------
# All bench variables are BENCH_-prefixed to avoid colliding with other
# Makefile work (e.g. the sibling `make lib` worktree that adds archive
# targets). Override at the make invocation, e.g.
#   make bench BENCH_PROFILE=A BENCH_BACKEND=u64 BENCH_SAMPLES=10
BENCH_PROFILE  ?= B
BENCH_BACKEND  ?= vice
BENCH_SAMPLES  ?= 5
BENCH_PYTHON   ?= /Users/someone/.local/share/c64-test-harness/venv/bin/python3
BENCH_TOOL     ?= tools/bench_granular.py
BENCH_REPORT   ?= docs/BENCH_REPORT.md
BENCH_BASELINE ?= docs/BENCH_REPORT.baseline.json
BENCH_TOLERANCE ?= 1.0

# --- Test configuration ----------------------------------------------------
# Same venv as the bench; the on-target tests need c64-test-harness and
# pyca/cryptography. C64_BACKEND / U64_HOST are read by the tools from
# the environment (default: VICE).
TEST_PYTHON    ?= $(BENCH_PYTHON)
TEST_SUITE     ?= tools/test_chacha20_poly1305.py
FUZZ_TOOL      ?= tools/hazmat_fuzz.py
FUZZ_SEED      ?= 20260828

# Default build == Profile A (POLY1305_PROFILE_LONG defined).
all: profile-a

# Convert ld65 label format (al XXXXXX .name) to VICE format (al C:XXXX .name)
define FIXLABELS
sed 's/^al \([0-9a-fA-F]*\)/al C:\1/' $(1) > $(1).tmp && mv $(1).tmp $(1)
endef

# ---- Profile A: POLY1305_PROFILE_LONG = 1 (default, "long message" path) ----
# Each .o depends on its source plus constants_lib.s (included for equates).
$(PROFILE_A_DIR)/main.o: src/main.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/zp_config.o: src/zp_config.s | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

profile-a: $(A_OBJS) $(CFG) | build
	$(LD65) -C $(CFG) -Ln $(PROFILE_A_DIR)/$(LABELS_NAME) \
	    $(A_OBJS) -o $(PROFILE_A_DIR)/$(PRG_NAME)
	$(call FIXLABELS,$(PROFILE_A_DIR)/$(LABELS_NAME))
	cp $(PROFILE_A_DIR)/$(PRG_NAME) $(PRG)
	cp $(PROFILE_A_DIR)/$(LABELS_NAME) $(LABELS)

# ---- Profile B: POLY1305_PROFILE_LONG undefined (stock C64 / portable) ----
$(PROFILE_B_DIR)/main.o: src/main.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/zp_config.o: src/zp_config.s | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

profile-b: $(B_OBJS) $(CFG) | build
	$(LD65) -C $(CFG) -Ln $(PROFILE_B_DIR)/$(LABELS_NAME) \
	    $(B_OBJS) -o $(PROFILE_B_DIR)/$(PRG_NAME)
	$(call FIXLABELS,$(PROFILE_B_DIR)/$(LABELS_NAME))
	cp $(PROFILE_B_DIR)/$(PRG_NAME) $(PRG)
	cp $(PROFILE_B_DIR)/$(LABELS_NAME) $(LABELS)

build:
	mkdir -p build

$(PROFILE_A_DIR):
	mkdir -p $(PROFILE_A_DIR)

$(PROFILE_B_DIR):
	mkdir -p $(PROFILE_B_DIR)

$(PROFILE_BR_DIR):
	mkdir -p $(PROFILE_BR_DIR)

# ---- Profile B-rolled: POLY1305_MULTIPLY_ROLLED=1 (Profile B base) ----
# Issue #34 alternative 2 prototype: rolled poly1305_multiply in lieu of
# the 17x16 unrolled macro expansion. All other build flags match
# Profile B (POLY1305_PROFILE_LONG undefined).
$(PROFILE_BR_DIR)/main.o: src/main.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/zp_config.o: src/zp_config.s | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED=1 $< -o $@

$(PROFILE_BR_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

profile-b-rolled: $(BR_OBJS) $(CFG) | build
	$(LD65) -C $(CFG) -Ln $(PROFILE_BR_DIR)/$(LABELS_NAME) \
	    $(BR_OBJS) -o $(PROFILE_BR_DIR)/$(PRG_NAME)
	$(call FIXLABELS,$(PROFILE_BR_DIR)/$(LABELS_NAME))
	cp $(PROFILE_BR_DIR)/$(PRG_NAME) $(PRG)
	cp $(PROFILE_BR_DIR)/$(LABELS_NAME) $(LABELS)

$(PROFILE_BO_DIR):
	mkdir -p $(PROFILE_BO_DIR)

# ---- Profile B-rolled-outer: outer-J rolled, inner-I unrolled. -------
# Issue #34 alternative 2 midpoint variant: rolls only the outer
# 16-iteration j loop; the 17 inner partial products for each row
# remain inlined macro expansions. Same CT contract as Profile B.
$(PROFILE_BO_DIR)/main.o: src/main.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/zp_config.o: src/zp_config.s | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_MULTIPLY_ROLLED_OUTER=1 $< -o $@

$(PROFILE_BO_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

profile-b-rolled-outer: $(BO_OBJS) $(CFG) | build
	$(LD65) -C $(CFG) -Ln $(PROFILE_BO_DIR)/$(LABELS_NAME) \
	    $(BO_OBJS) -o $(PROFILE_BO_DIR)/$(PRG_NAME)
	$(call FIXLABELS,$(PROFILE_BO_DIR)/$(LABELS_NAME))
	cp $(PROFILE_BO_DIR)/$(PRG_NAME) $(PRG)
	cp $(PROFILE_BO_DIR)/$(LABELS_NAME) $(LABELS)

run: profile-a
	x64sc -autostart $(PRG)

clean:
	rm -rf build

# ===========================================================================
# Library archive targets (c64-lib-contract SPEC §6).
#
# These produce consumer-ingestible `.a` archives via ar65, so downstream
# projects (c64-wireguard, c64-https, ...) can vendor the library as a
# single file and let ld65 pull in exactly the modules each consumer
# references — no mid-build `sed`, no copying intermediate .o files.
#
# Targets:
#   make lib              build/lib/chacha20poly1305.a (+ deprecated alias)
#                         Full Profile-B archive. Every public ABI
#                         export plus the test-only entry points
#                         (chacha20_quarter_round, mul_8x8, rotl32_1,
#                         rotl32_7, rotr32_7) so a downstream Python
#                         test harness can jsr() into the same labels
#                         the upstream harness does.
#
#   make lib-aead-only    build/lib/chacha20poly1305-aead-only.a (+ alias)
#                         Trimmed archive for consumers that only need
#                         the documented AEAD ABI (aead_encrypt,
#                         aead_decrypt, plus their poly1305_lib_init
#                         prerequisite and the AEAD I/O state symbols).
#                         The test-only entry points listed above are
#                         not exported, and the body of the JSR-driven
#                         chacha20_quarter_round is .ifndef'd out so
#                         a consumer linking only AEAD pulls
#                         strictly less code into its PRG.
#
# Both variants share the same per-module .s sources; the toggle lives
# in -DLIB_VARIANT_AEAD_ONLY=1 at ca65 time. Per-variant .o files live
# under their own subdir so the cache doesn't clash across variants.
# ===========================================================================

LIB_OBJS = $(LIB_OBJS_DIR)/word32_lib.o \
           $(LIB_OBJS_DIR)/chacha20_lib.o \
           $(LIB_OBJS_DIR)/poly1305_lib.o \
           $(LIB_OBJS_DIR)/shared_sqtab_init.o \
           $(LIB_OBJS_DIR)/shared_prod_scratch.o \
           $(LIB_OBJS_DIR)/mul_8x8_legacy.o \
           $(LIB_OBJS_DIR)/shared_ct_mul.o \
           $(LIB_OBJS_DIR)/poly1305_ripple.o \
           $(LIB_OBJS_DIR)/poly1305_core.o \
           $(LIB_OBJS_DIR)/chacha20poly1305_lib.o \
           $(LIB_OBJS_DIR)/data_lib.o \
           $(LIB_OBJS_DIR)/lib_version.o \
           $(LIB_OBJS_DIR)/lib_manifest.o \
           $(LIB_OBJS_DIR)/precalc_manifest.o

LIB_AEAD_ONLY_OBJS = $(LIB_AEAD_ONLY_OBJS_DIR)/word32_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/chacha20_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/shared_sqtab_init.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/shared_prod_scratch.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/mul_8x8_legacy.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/shared_ct_mul.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_ripple.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_core.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/chacha20poly1305_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/data_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/lib_version.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/lib_manifest.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/precalc_manifest.o

LIB_APP_OWNED_OBJS = $(LIB_APP_OWNED_OBJS_DIR)/word32_lib.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/chacha20_lib.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/poly1305_lib.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/shared_sqtab_init.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/shared_prod_scratch.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/mul_8x8_legacy.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/shared_ct_mul.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/poly1305_ripple.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/poly1305_core.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/chacha20poly1305_lib.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/data_lib.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/lib_version.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/lib_manifest.o \
                     $(LIB_APP_OWNED_OBJS_DIR)/precalc_manifest.o

# --- Full archive (Profile B, every export) --------------------------------
$(LIB_OBJS_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/lib_version.o: src/lib_version.s | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

# ar65 r appends; rebuild from a clean archive every time so we don't
# accumulate stale modules from a previous invocation.
lib: $(LIB_FULL_AR) $(LIB_INC) $(LIB_EXAMPLE_CFG)

$(LIB_INC): src/chacha20poly1305.inc | $(LIB_DIR)
	cp $< $@

$(LIB_EXAMPLE_CFG): cfg/$(LIB_NAME)-example.cfg | $(LIB_DIR)/cfg
	cp $< $@

$(LIB_DIR)/cfg:
	mkdir -p $@

$(LIB_FULL_AR): $(LIB_OBJS) | $(LIB_DIR)
	rm -f $@ $(LIB_FULL_AR_DEPRECATED)
	ar65 r $@ $(LIB_OBJS)
	cp $@ $(LIB_FULL_AR_DEPRECATED)	# §6.5 window: deprecated basename, drop at next MAJOR

# --- aead-only variant (test-only exports stripped) ------------------------
LIB_AEAD_ONLY_DEFINE = -DLIB_VARIANT_AEAD_ONLY=1

$(LIB_AEAD_ONLY_OBJS_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/lib_version.o: src/lib_version.s | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

lib-aead-only: $(LIB_AEAD_ONLY_AR)

$(LIB_AEAD_ONLY_AR): $(LIB_AEAD_ONLY_OBJS) | $(LIB_DIR)
	rm -f $@ $(LIB_AEAD_ONLY_AR_DEPRECATED)
	ar65 r $@ $(LIB_AEAD_ONLY_OBJS)
	cp $@ $(LIB_AEAD_ONLY_AR_DEPRECATED)	# §6.5 window: deprecated basename, drop at next MAJOR

# --- app-owned variant (contract §8.0 APP_OWNED, issue #74) ----------------
# Both shared primitives deferred to the consumer's own modules. The
# consumer must supply the §8.1 canonical `mul_tables_init` and the §8.3
# `ct_mul_8x8` (plus poly_prod_lo/hi and the two SMC bake sites) — see
# `make lib-verify-shared` for the exact imported surface.
LIB_APP_OWNED_DEFINE = -DSHARED_SQTAB_INIT=1 -DSHARED_CT_MUL_8X8=1

$(LIB_APP_OWNED_OBJS_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/shared_sqtab_init.o: src/lib/shared_sqtab_init.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/shared_prod_scratch.o: src/lib/shared_prod_scratch.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/mul_8x8_legacy.o: src/lib/mul_8x8_legacy.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/shared_ct_mul.o: src/lib/shared_ct_mul.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/poly1305_ripple.o: src/lib/poly1305_ripple.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/poly1305_core.o: src/lib/poly1305_core.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/precalc_manifest.o: src/lib/precalc_manifest.s src/precalc_table.inc | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

$(LIB_APP_OWNED_OBJS_DIR)/lib_version.o: src/lib_version.s | $(LIB_APP_OWNED_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_APP_OWNED_DEFINE) $< -o $@

lib-app-owned: $(LIB_APP_OWNED_AR)

$(LIB_APP_OWNED_AR): $(LIB_APP_OWNED_OBJS) | $(LIB_DIR)
	rm -f $@ $(LIB_APP_OWNED_AR_DEPRECATED)
	ar65 r $@ $(LIB_APP_OWNED_OBJS)
	cp $@ $(LIB_APP_OWNED_AR_DEPRECATED)	# §6.5 window: deprecated basename, drop at next MAJOR

$(LIB_APP_OWNED_OBJS_DIR):
	mkdir -p $(LIB_APP_OWNED_OBJS_DIR)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(LIB_OBJS_DIR):
	mkdir -p $(LIB_OBJS_DIR)

$(LIB_AEAD_ONLY_OBJS_DIR):
	mkdir -p $(LIB_AEAD_ONLY_OBJS_DIR)

# ===========================================================================
# lib-verify-shared — c64-lib-contract SPEC §8.1 + §8.3 linkage guard.
#
# Regression guard for issue #47: `-D SHARED_CT_MUL_8X8=1` used to flip only
# the manifest ownership bit while leaving the §8.3 export surface live, so
# a two-archive link against a sibling owning the same primitive died with
# `ld65: Error: Duplicate external identifier: 'poly_prod_hi'`. This target
# assembles poly1305_lib.s in both configurations and pins the symbol
# surface each one must present:
#
#   owner build (default)  MUST export every §8.3 name
#   deferral build         MUST export NONE of them, and MUST import the
#                          five it actually references
#
# Pure od65 symbol-table inspection — no VICE, no link, runs in ~1 s.
#
# Reads .o files, never .a archives: od65 cannot read archives — pointed at
# one it prints "<name>: (no xo65 object file)" AND EXITS 0, so a grep-based
# audit silently reports zero matches, indistinguishable from a clean pass
# (c64-lib-contract SPEC v0.7.2 / contract #52). Every "must NOT export"
# check below would pass vacuously on such an empty dump, so the sentinel
# check guards them: if a dump does not contain a symbol we know is always
# present, the dump itself is broken and the target fails loudly rather
# than reporting success.
# ===========================================================================
LIB_SHARED_VERIFY_DIR = $(LIB_DIR)/verify-shared

# The §8.3 surface now lives in three TUs rather than inside poly1305_lib.s
# (issue #108 member isolation). This target must FOLLOW THE SYMBOLS: point
# it at poly1305_lib.s alone and every "must NOT export" leg below passes
# vacuously against a file that no longer exports them, which is how
# c64-x25519 discovered its own equivalent target had only ever passed
# because of the defect it was meant to catch.
LIB_SHARED_SRCS = src/lib/shared_ct_mul.s src/lib/shared_prod_scratch.s \
                  src/lib/mul_8x8_legacy.s
# Names the owner build must publish (mul_8x8 is the legacy test-only
# alias body; it collides with the sibling's export just the same).
LIB_SHARED_OWNED_SYMS  = ct_mul_8x8 mul_8x8 poly_prod_lo poly_prod_hi \
                         smc_sum_a_imm smc_diff_a_imm
# Names the deferral build must resolve from the designated owner — and,
# since #108, that the OWNER build must import too: they live in another TU
# either way, and poly1305_core.s is the TU that references them.
LIB_SHARED_IMPORT_SYMS = ct_mul_8x8 poly_prod_lo poly_prod_hi \
                         smc_sum_a_imm smc_diff_a_imm

# --- §8.1 sqtab (issue #105) -----------------------------------------------
# The owner build MUST publish the canonical `mul_tables_init`, because that
# is the name §8.1 tells a deferring sibling to import. `sqtab_init` is this
# library's historical spelling, kept exported under §8.1's back-compat
# permission; both are the same address.
#
# Until #105 only `sqtab_init` was exported while the §5 manifest claimed the
# $0001 ownership bit, so the claim was unsatisfiable and a deferring sibling
# died on `Unresolved external 'mul_tables_init'`. The §8.3 half of this
# target existed because issue #47 was the identical defect one clause over;
# §8.1 had no leg, which is why this one survived #47.
LIB_SQTAB_OWNED_SYMS   = mul_tables_init sqtab_init
LIB_SQTAB_IMPORT_SYMS  = mul_tables_init

# R2 audit: the §5 ZP_USAGE_BYTES equate is hand-maintained, so nothing
# tied it to the actual .exportzp surface until this check. Deliberately
# NOT named lib-*: v0.17.1 §6.1 reserved that namespace for targets that
# produce archives. That sentence was DELETED from §6.1 at contract v1.0.0
# — deleted from a surviving section, so it is not in RETIRED.md, which
# lists only wholly retired sections. This is now a local naming
# convention rather than an obligation — kept because
# it still tells a reader which targets emit artifacts and which only
# check them.
# THE gate list. Defined once and used by `make verify` below AND, via that
# target, by tools/build_release.sh inside the extracted tarball. Before this,
# build_release.sh carried a hand-copied duplicate of this list and it had
# already drifted: verify-knob-staleness and verify-label-hygiene were absent,
# so a release tarball was checked with four of six gates. That is the exact
# omission class the script's own comment describes happening once already with
# verify_member_isolation.py. A second list is a second thing to forget.
VERIFY_TARGETS = verify-zp-usage verify-knob-staleness verify-resident-bytes \
                 verify-label-hygiene lib-verify-isolation lib-verify-shared

# SERIAL BY CONSTRUCTION. These are NOT prerequisites: as prerequisites `make -j`
# runs them concurrently, and several recursively build into the SAME
# build/lib/objs* directories, so two gates race on one archive —
# `ar65: Error: Problem deleting temporary library file`, reproducible 3/3 at
# -j8 while serial and `-j8 profile-a profile-b lib` both pass. Running them
# through a loop makes `make -j8 verify` safe without imposing .NOTPARALLEL on
# ordinary builds, which are parallel-safe and should stay that way.
verify:
	@set -e; for t in $(VERIFY_TARGETS); do \
	  $(MAKE) --no-print-directory $$t; \
	done
	@echo "verify: all $(words $(VERIFY_TARGETS)) gates green"

verify-zp-usage: lib
	python3 tools/verify_zp_usage.py

# §6.3 knob-staleness guard (contract SPEC v0.10.5, issue #86). Runs against
# a throwaway copy of Makefile + src/ + cfg/, so it does not cost the caller their
# per-profile object cache — the guard's invalidation leg deletes every
# object under build/ by design.
verify-knob-staleness:
	python3 tools/verify_knob_staleness.py

# verify-resident-bytes — the §5 footprint ratchet (issue #113, and the
# "wave 3 item F" the manifest has been asking for since v0.9.0).
#
# Until this existed the five RESIDENT_BYTES literals were hand-maintained
# with no check at all, and all five were 512 B BELOW the bound a consumer
# can reach — the direction §5 calls dangerous. Checks each variant's
# declared value against `od65 sum + 255 * page-aligned sections`.
#
# Not named lib-*: that is a local convention for archive-producing targets.
# NOTE: this target sets CONTRACT_DEFINES itself, once per profile, and so
# ignores one passed on the command line. That is deliberate — its job is to
# check EVERY shipped configuration, not the one you happened to ask for.
# Before this, three legs were hardcoded to Profile B values while the objects
# they measured followed whatever knob the caller passed, so
# `make verify-resident-bytes CONTRACT_DEFINES="-D POLY1305_PROFILE_LONG=1"`
# compared Profile A objects against Profile B literals and printed OK.
# The define set c64-wireguard actually builds with, verbatim from
# c64-wireguard/tools/integration/build_chacha20poly1305.sh:57 (it runs
# `make lib CONTRACT_DEFINES="$DEFS"` at :72). Issue #122.
#
# WHY THIS EXISTS. Until this variable, no leg of any gate here built the
# combination the only real consumer builds: verify-resident-bytes iterated
# 3 targets x 2 profiles passing the PROFILE define only, so target `lib`
# was never combined with the SHARED_* switches.
#
# WHAT IT PINS, precisely — this is narrower than issue #122 first claimed.
# The consumer's config declares 17664 against a measured bound near 9371,
# and that gap is DELIBERATE: lib_manifest.s:327-335 documents both SHARED_*
# switches as purely subtractive `.ifndef` gates, so declaring the un-deferred
# value is a safe superset and the large gap is the designed outcome. This leg
# is therefore NOT hunting a wrong number. It pins the SUBTRACTIVE INVARIANT
# the number depends on: if a future change ever makes one of these switches
# additive, the declared literal could stop covering what a consumer ships,
# and without this leg nothing would notice. It passes on the day it lands.
#
# Keep verbatim-synced with the consumer's script; a divergence here silently
# restores the gap this closes.
CONSUMER_DEFINES = -D SHARED_SQTAB_INIT=1 -D SHARED_CT_MUL_8X8=1 \
                   -D POLY1305_MULTIPLY_ROLLED_OUTER=1 -D LIB_NO_BARE_EXPORTS=1

# The multiply axis, which lib_manifest.s does not model AT ALL — `ROLLED`
# appears nowhere in it, at RESIDENT_BYTES, COLD_BYTES or the §8 masks.
# poly1305_core.s:176 SWAPS one multiply body for another rather than removing
# one, so nothing structural bounds the direction. Measured on target `lib`:
#
#   default (fully inlined)              sum 16841   bound 17861
#   POLY1305_MULTIPLY_ROLLED=1           sum  8072   bound  9092
#   POLY1305_MULTIPLY_ROLLED_OUTER=1     sum  8648   bound  9668
#
# The declared 17920 covers all three only because the DEFAULT happens to be
# the largest member of the axis. That is a property of today's code, not a
# guarantee: if an alternative body ever grows past the default, the declared
# literal stops covering an archive a consumer can build, and no manifest
# branch would notice. ROLLED_OUTER is pinned by CONSUMER_DEFINES above;
# this pins the other documented knob (docs/API.md:687), which until now was
# exercised only by the profile-b-rolled PRG target and by no archive leg.
ROLLED_DEFINES = -D POLY1305_MULTIPLY_ROLLED=1

# The SECOND unmodelled footprint axis, found by the #126 review. Same shape as
# the multiply one and worse in the respect that matters: `CHACHA20_USE_WORD32`
# is a documented consumer knob (docs/API.md, docs/INTEGRATION.md) that appears
# NOWHERE in lib_manifest.s, and src/lib/chacha20_lib.s swaps macro expansions
# between an inline form and a pointer-mode form — a SUBSTITUTION, not a
# subtraction, so nothing structural holds the sign. Measured uniformly -488 B
# across every target and both profiles (Profile B lib 17861 -> 17373, Profile A
# 16588 -> 16100), orthogonal to the other knobs. Safe-direction today; no
# consumer passes it. That is shipped-surface coverage, which CLAUDE.md §1 says
# still counts.
WORD32_DEFINES = -D CHACHA20_USE_WORD32=1

verify-resident-bytes:
	@set -e; \
	for prof in "" "-D POLY1305_PROFILE_LONG=1"; do \
	  if [ -z "$$prof" ]; then pname="Profile B"; else pname="Profile A"; fi; \
	  for t in lib lib-aead-only lib-app-owned; do \
	    case "$$t" in \
	      lib)            d=$(LIB_OBJS_DIR);; \
	      lib-aead-only)  d=$(LIB_AEAD_ONLY_OBJS_DIR);; \
	      lib-app-owned)  d=$(LIB_APP_OWNED_OBJS_DIR);; \
	    esac; \
	    $(MAKE) --no-print-directory $$t CONTRACT_DEFINES="$$prof" >/dev/null; \
	    echo "  --- $$pname $$t ---"; \
	    python3 tools/measure_resident_bytes.py $$d --check; \
	  done; \
	done; \
	echo "  --- consumer config (c64-wireguard): lib + CONSUMER_DEFINES ---"; \
	$(MAKE) --no-print-directory lib CONTRACT_DEFINES="$(CONSUMER_DEFINES)" >/dev/null; \
	python3 tools/measure_resident_bytes.py $(LIB_OBJS_DIR) --check; \
	for sw in "-D SHARED_SQTAB_INIT=1" "-D SHARED_CT_MUL_8X8=1"; do \
	  echo "  --- §8 deferral, one switch at a time: lib $$sw (issue #126) ---"; \
	  $(MAKE) --no-print-directory lib CONTRACT_DEFINES="$$sw" >/dev/null; \
	  python3 tools/measure_resident_bytes.py $(LIB_OBJS_DIR) --check; \
	done; \
	echo "  --- multiply axis: lib + ROLLED_DEFINES ---"; \
	$(MAKE) --no-print-directory lib CONTRACT_DEFINES="$(ROLLED_DEFINES)" >/dev/null; \
	python3 tools/measure_resident_bytes.py $(LIB_OBJS_DIR) --check; \
	echo "  --- word32 axis: lib + WORD32_DEFINES ---"; \
	$(MAKE) --no-print-directory lib CONTRACT_DEFINES="$(WORD32_DEFINES)" >/dev/null; \
	python3 tools/measure_resident_bytes.py $(LIB_OBJS_DIR) --check; \
	$(MAKE) --no-print-directory lib >/dev/null; \
	echo "  verify-resident-bytes: OK — every declared literal covers its bound, both profiles, plus the consumer's own config and the multiply axis"


# §6.1 member-isolation guard (contract SPEC v1.2.0/v1.2.1/v1.2.2, issue #108).
#
# Named lib-* because it consumes what `make lib*` produces: it builds the
# three shipped variants in a throwaway tree and inspects every archive
# member's export table.
#
# The displaceable set is MEASURED, never listed: the tool builds the same
# sources with and without each §6.1 suppression knob and differences the
# export tables, so a name is displaceable iff suppressing it actually
# removes it. It also reconciles per-member category counts against the
# member's total export count, which is what catches an od65 dump being
# mis-parsed rather than a category genuinely being empty.
#
# Prove it can fail before trusting it green:
#   python3 tools/verify_member_isolation.py --tree <a tree at v0.10.0>
# reports lib_manifest.o and poly1305_lib.o in all three variants.
lib-verify-isolation:
	python3 tools/verify_member_isolation.py

# verify-label-hygiene — issue #117. See tools/verify_label_hygiene.py for the
# mechanism and, importantly, for why the check lives in a tool: its two
# positive-control legs cannot be driven red through this target, because
# profile-a and profile-b are .PHONY and regenerate labels.txt on every
# invocation. The tool can be pointed at a crafted file; this target cannot.
#
# COVERS ALL FIVE SHIPPED CONFIGURATIONS, not just the two that produce a
# label file. Consumers link the ARCHIVES, and the three archive variants are
# assembled with different defines, so a `.local` behind an `.ifdef` on one of
# those leaks to a consumer while both profile PRGs stay clean. That was
# demonstrated against an earlier version of this target, not theorised.
#
# Prove it can fail before trusting it green: restore `.local ok` /
# `.local reject` in AEAD_DOMAIN_GUARD, `make clean` (do NOT rely on `touch` —
# make compares
# mtimes at one-second granularity — a git checkout landing in the same second
# as the object leaves a stale .o and this target then reads a stale link),
# rebuild, and it must report 8 leaked names per profile.
# BUILD-THEN-SCAN, ONE CONFIGURATION AT A TIME — not all-then-scan.
#
# The previous form listed the five configurations as prerequisites and scanned
# their objects afterwards.
#
# WHAT ACTUALLY BREAKS IT — measured, after two wrong first answers. NOT
# `profile-a`: its -DPOLY1305_PROFILE_LONG=1 is a per-recipe literal on the
# pattern rules, never reaches CURRENT_KNOBS and never trips invalidation. The
# wiper is `verify-resident-bytes`, whose recursive sub-makes DO pass
# CONTRACT_DEFINES and so change the stamp, deleting every *.o under build/.
#
# And NOT "under `make verify`": six gates in VERIFY_TARGETS order on a clean
# tree pass. The extra ingredient is the five build targets being PRIOR GOALS OF
# THE SAME MAKE PROCESS — make memoises them as already-updated and skips the
# phony rebuild after their objects are deleted. That is tools/build_release.sh's
# invocation shape (TARBALL_TARGETS + TARBALL_VERIFY in one make), which is why
# only the release path exposed it.
#
# The label FILES survived not because links re-ran — they did not; the only two
# ld65 lines in the failing transcript are the original goals — but because
# invalidation deletes only *.o and $(LIB_DIR)/*.a and never touches labels.txt.
# The conclusion stands either way: a check without the tool's non-empty
# positive control would have reported ok on a run that examined almost nothing.
verify-label-hygiene:
	@$(MAKE) --no-print-directory profile-a >/dev/null
	python3 tools/verify_label_hygiene.py \
	    build/profile-a/labels.txt build/profile-a/chacha20poly1305_lib.o
	@$(MAKE) --no-print-directory profile-b >/dev/null
	python3 tools/verify_label_hygiene.py \
	    build/profile-b/labels.txt build/profile-b/chacha20poly1305_lib.o
	@$(MAKE) --no-print-directory lib >/dev/null
	python3 tools/verify_label_hygiene.py build/lib/objs/chacha20poly1305_lib.o
	@$(MAKE) --no-print-directory lib-aead-only >/dev/null
	python3 tools/verify_label_hygiene.py build/lib/objs-aead-only/chacha20poly1305_lib.o
	@$(MAKE) --no-print-directory lib-app-owned >/dev/null
	python3 tools/verify_label_hygiene.py build/lib/objs-app-owned/chacha20poly1305_lib.o
	@echo "  --- consumer config (c64-wireguard), issue #122 ---"
	@$(MAKE) --no-print-directory lib CONTRACT_DEFINES="$(CONSUMER_DEFINES)" >/dev/null
	python3 tools/verify_label_hygiene.py build/lib/objs/chacha20poly1305_lib.o
	@$(MAKE) --no-print-directory lib >/dev/null

lib-verify-shared: | $(LIB_SHARED_VERIFY_DIR)
	@rm -f $(LIB_SHARED_VERIFY_DIR)/*.o $(LIB_SHARED_VERIFY_DIR)/*.exports \
	       $(LIB_SHARED_VERIFY_DIR)/*.imports
	@for f in $(LIB_SHARED_SRCS); do \
	    b=$$(basename $$f .s); \
	    $(CA65) $(CA65FLAGS) $$f -o $(LIB_SHARED_VERIFY_DIR)/$$b.owner.o || exit 1; \
	    $(CA65) $(CA65FLAGS) -D SHARED_CT_MUL_8X8=1 $$f \
	        -o $(LIB_SHARED_VERIFY_DIR)/$$b.defer.o || exit 1; \
	    od65 --dump-exports $(LIB_SHARED_VERIFY_DIR)/$$b.owner.o \
	        >> $(LIB_SHARED_VERIFY_DIR)/owner.exports; \
	    od65 --dump-exports $(LIB_SHARED_VERIFY_DIR)/$$b.defer.o \
	        >> $(LIB_SHARED_VERIFY_DIR)/defer.exports; \
	done
	@$(CA65) $(CA65FLAGS) -D SHARED_CT_MUL_8X8=1 src/lib/poly1305_core.s \
	    -o $(LIB_SHARED_VERIFY_DIR)/core_defer.o
	@$(CA65) $(CA65FLAGS) src/lib/poly1305_core.s \
	    -o $(LIB_SHARED_VERIFY_DIR)/core_owner.o
	@$(CA65) $(CA65FLAGS) src/lib/shared_sqtab_init.s \
	    -o $(LIB_SHARED_VERIFY_DIR)/sq_owner.o
	@$(CA65) $(CA65FLAGS) -D SHARED_SQTAB_INIT=1 src/lib/shared_sqtab_init.s \
	    -o $(LIB_SHARED_VERIFY_DIR)/sq_defer.o
	@$(CA65) $(CA65FLAGS) -D SHARED_SQTAB_INIT=1 src/lib/poly1305_lib.s \
	    -o $(LIB_SHARED_VERIFY_DIR)/lib_defer_sq.o
	@$(CA65) $(CA65FLAGS) src/lib/poly1305_lib.s \
	    -o $(LIB_SHARED_VERIFY_DIR)/lib_owner.o
	@od65 --dump-imports $(LIB_SHARED_VERIFY_DIR)/core_defer.o \
	    > $(LIB_SHARED_VERIFY_DIR)/core_defer.imports
	@od65 --dump-imports $(LIB_SHARED_VERIFY_DIR)/core_owner.o \
	    > $(LIB_SHARED_VERIFY_DIR)/core_owner.imports
	@od65 --dump-exports $(LIB_SHARED_VERIFY_DIR)/sq_owner.o \
	    > $(LIB_SHARED_VERIFY_DIR)/sq_owner.exports
	@od65 --dump-exports $(LIB_SHARED_VERIFY_DIR)/sq_defer.o \
	    > $(LIB_SHARED_VERIFY_DIR)/sq_defer.exports
	@od65 --dump-imports $(LIB_SHARED_VERIFY_DIR)/lib_defer_sq.o \
	    > $(LIB_SHARED_VERIFY_DIR)/lib_defer_sq.imports
	@od65 --dump-imports $(LIB_SHARED_VERIFY_DIR)/lib_owner.o \
	    > $(LIB_SHARED_VERIFY_DIR)/lib_owner.imports
	@fail=0; \
	for pair in "owner.exports:ct_mul_8x8" \
	            "sq_owner.exports:mul_tables_init" \
	            "core_defer.imports:poly_product" \
	            "core_owner.imports:poly_product" \
	            "lib_defer_sq.imports:sqtab_ready" \
	            "lib_owner.imports:sqtab_ready"; do \
	    f=$${pair%%:*}; sentinel=$${pair##*:}; \
	    grep -q "\"$$sentinel\"" $(LIB_SHARED_VERIFY_DIR)/$$f || { \
	        echo "FAIL: $$f lacks sentinel '$$sentinel' — od65 dump is empty or"; \
	        echo "      unreadable, so every check that reads it would pass"; \
	        echo "      vacuously (SPEC v0.7.2)"; \
	        fail=1; \
	    }; \
	done; \
	for f in defer.exports sq_defer.exports; do \
	    grep -q "Count:" $(LIB_SHARED_VERIFY_DIR)/$$f || { \
	        echo "FAIL: $$f has no od65 'Count:' row — the deferral object was"; \
	        echo "      not assembled or od65 could not read it. This dump is"; \
	        echo "      EMPTY BY DESIGN (a deferring TU exports nothing), so a"; \
	        echo "      name sentinel is impossible and this structural one is"; \
	        echo "      the only thing standing between the must-NOT-export"; \
	        echo "      legs below and a vacuous pass (issue #108)."; \
	        fail=1; \
	    }; \
	done; \
	for s in $(LIB_SHARED_OWNED_SYMS); do \
	    grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/owner.exports || { \
	        echo "FAIL: owner build does not export $$s"; fail=1; }; \
	    if grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/defer.exports; then \
	        echo "FAIL: SHARED_CT_MUL_8X8 build still exports $$s (issue #47)"; \
	        fail=1; \
	    fi; \
	done; \
	for s in $(LIB_SHARED_IMPORT_SYMS); do \
	    grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/core_defer.imports || { \
	        echo "FAIL: SHARED_CT_MUL_8X8 build does not import $$s"; fail=1; }; \
	    grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/core_owner.imports || { \
	        echo "FAIL: owner build does not import $$s from its own §8.3 TU —"; \
	        echo "      after the issue #108 member split poly1305_core.s must"; \
	        echo "      import the §8.3 surface in EVERY build. That import is"; \
	        echo "      what lets an APP_OWNED consumer's own definition win"; \
	        echo "      against the default archive (SPEC §6.1)"; \
	        fail=1; }; \
	done; \
	for s in $(LIB_SQTAB_OWNED_SYMS); do \
	    grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/sq_owner.exports || { \
	        echo "FAIL: owner build does not export $$s — the §5 manifest claims"; \
	        echo "      the \$$0001 sqtab ownership bit, so a deferring sibling"; \
	        echo "      importing the canonical name gets an unresolved external"; \
	        echo "      (issue #105)"; \
	        fail=1; }; \
	    if grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/sq_defer.exports; then \
	        echo "FAIL: SHARED_SQTAB_INIT build still exports $$s — two providers"; \
	        echo "      of a canonical name is a duplicate external in any"; \
	        echo "      composed link"; \
	        fail=1; \
	    fi; \
	done; \
	for s in $(LIB_SQTAB_IMPORT_SYMS); do \
	    grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/lib_defer_sq.imports || { \
	        echo "FAIL: SHARED_SQTAB_INIT build does not import $$s (§8.1"; \
	        echo "      import-never-stub rule)"; fail=1; }; \
	    grep -q "\"$$s\"" $(LIB_SHARED_VERIFY_DIR)/lib_owner.imports || { \
	        echo "FAIL: owner build does not import $$s — poly1305_lib.s must"; \
	        echo "      call the §8.1 primitive by its CANONICAL name in every"; \
	        echo "      build, so an APP_OWNED consumer's mul_tables_init"; \
	        echo "      satisfies it and our member is never pulled beside it"; \
	        fail=1; }; \
	done; \
	if [ $$fail -ne 0 ]; then \
	    echo "lib-verify-shared: FAILED"; exit 1; \
	fi; \
	echo "lib-verify-shared: OK — §8.1 and §8.3 surfaces owned in default build,"; \
	echo "                   each fully deferred under its own switch, and the"; \
	echo "                   canonical names imported in BOTH builds"

$(LIB_SHARED_VERIFY_DIR):
	mkdir -p $(LIB_SHARED_VERIFY_DIR)

# --- On-target test targets --------------------------------------------------
# test:           builds each profile in turn and runs the RFC/round-trip
#                 suite against it. tools/test_chacha20_poly1305.py reads
#                 build/c64_chacha20_poly1305.prg, which `profile-a` /
#                 `profile-b` refresh, so the profiles run sequentially.
# test-fuzz:      builds both profiles, then runs the adversarial
#                 differential fuzz (oracle: pyca/cryptography hazmat) in
#                 --quick mode (~1-2 min per profile on VICE) against
#                 build/profile-a/ and build/profile-b/.
# test-fuzz-full: same with the full corpus.
# Every recipe line is a separate shell and make stops at the first
# non-zero exit, so any failing tool fails the target.
test:
	$(MAKE) profile-a
	C64_BACKEND=$${C64_BACKEND:-vice} $(TEST_PYTHON) $(TEST_SUITE)
	$(MAKE) profile-b
	C64_BACKEND=$${C64_BACKEND:-vice} $(TEST_PYTHON) $(TEST_SUITE)

test-fuzz:
	$(MAKE) profile-a profile-b
	$(TEST_PYTHON) $(FUZZ_TOOL) --profile a --quick --seed $(FUZZ_SEED)
	$(TEST_PYTHON) $(FUZZ_TOOL) --profile b --quick --seed $(FUZZ_SEED)

test-fuzz-full:
	$(MAKE) profile-a profile-b
	$(TEST_PYTHON) $(FUZZ_TOOL) --profile a --seed $(FUZZ_SEED)
	$(TEST_PYTHON) $(FUZZ_TOOL) --profile b --seed $(FUZZ_SEED)

# Reproducible source tarball for a tagged release.
# Usage: make dist VERSION=v0.5.0
dist:
	@if [ -z "$(VERSION)" ]; then \
	  echo "usage: make dist VERSION=v0.5.0" >&2; \
	  exit 1; \
	fi
	@tools/build_release.sh $(VERSION)

# --- Granular bench targets ----------------------------------------------
# bench:        builds the requested profile, runs the granular bench, and
#               writes docs/BENCH_REPORT.md + docs/BENCH_REPORT.md.json.
# bench-check:  builds the requested profile, runs the granular bench, and
#               diffs against BENCH_BASELINE; exits non-zero on >1% drift
#               in any row. The committed baseline lives at
#               docs/BENCH_REPORT.baseline.json (refresh with `make bench`
#               then copy the resulting JSON sidecar to the baseline path
#               and commit; see docs/BENCH_GRANULAR.md).
bench:
	@if [ "$(BENCH_PROFILE)" = "A" ]; then $(MAKE) profile-a; \
	 else $(MAKE) profile-b; fi
	$(BENCH_PYTHON) $(BENCH_TOOL) \
	    --backend $(BENCH_BACKEND) \
	    --profile $(BENCH_PROFILE) \
	    --samples $(BENCH_SAMPLES) \
	    --md $(BENCH_REPORT)

bench-check:
	@if [ "$(BENCH_PROFILE)" = "A" ]; then $(MAKE) profile-a; \
	 else $(MAKE) profile-b; fi
	$(BENCH_PYTHON) $(BENCH_TOOL) \
	    --backend $(BENCH_BACKEND) \
	    --profile $(BENCH_PROFILE) \
	    --samples $(BENCH_SAMPLES) \
	    --md $(BENCH_REPORT) \
	    --check $(BENCH_BASELINE) \
	    --tolerance $(BENCH_TOLERANCE)
