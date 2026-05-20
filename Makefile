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
# the full Profile-B archive `build/lib/c64-chacha20-poly1305.a`. Each
# `make lib-<variant>` target builds a trimmed archive next to it as
# `build/lib/c64-chacha20-poly1305-<variant>.a`. Per-variant object
# files live in their own subdir (`build/lib/objs/`, `build/lib/objs-
# <variant>/`) so the variants' `.ifndef`-gated assembly results don't
# clobber Profile A/B's .o cache.
LIB_DIR        = build/lib
LIB_OBJS_DIR   = $(LIB_DIR)/objs
LIB_NAME       = c64-chacha20-poly1305
LIB_FULL_AR    = $(LIB_DIR)/$(LIB_NAME).a

# Per-variant archive paths. New variants get one line each here plus a
# build recipe below; the rule shape is generic.
LIB_AEAD_ONLY_AR        = $(LIB_DIR)/$(LIB_NAME)-aead-only.a
LIB_AEAD_ONLY_OBJS_DIR  = $(LIB_DIR)/objs-aead-only

CA65 = ca65
LD65 = ld65
CA65FLAGS = -t c64 -g -I src/include -I src/lib
CFG = src/c64.cfg

# --- Module list -----------------------------------------------------------
# Each source file compiles to its own .o. Order matters only for the
# link line (ld65 resolves symbols regardless but segment packing
# reflects link order). Constants_lib is equates-only and is .include'd
# by the modules that need ZP equate values, so it has no .o of its own.
# zp_config is a standalone .s module that owns the .exportzp slot
# allocation; consumers can override addresses by pre-defining symbols
# before zp_config.s is assembled, or by swapping the file outright.
MODULES = main zp_config word32_lib chacha20_lib poly1305_lib chacha20poly1305_lib data_lib lib_version lib_manifest

# Modules that go into the consumer-facing .a archive. `main.o` ships
# the standalone-PRG entry stub (`lib_entry: rts`) which a consumer
# does not need — they ship their own `main`. `zp_config.o` is also
# excluded: consumers commit to their own ZP layout via --asm-define
# overrides at consumer-assemble time, so bundling the library's
# default-bound zp_config.o would either (a) silently re-bind their
# slots, or (b) cause duplicate-symbol errors if they assemble their
# own zp_config.s. Everything else (the actual library code, data,
# version/manifest equates) is included.
LIB_MODULES = word32_lib chacha20_lib poly1305_lib chacha20poly1305_lib data_lib lib_version lib_manifest

SRCS_MAIN     = src/main.s
SRCS_LIB      = $(wildcard src/lib/*.s)
SRCS_INCLUDES = src/lib/constants_lib.s

# Object file list per profile (order matches MODULES).
A_OBJS = $(PROFILE_A_DIR)/main.o \
         $(PROFILE_A_DIR)/zp_config.o \
         $(PROFILE_A_DIR)/word32_lib.o \
         $(PROFILE_A_DIR)/chacha20_lib.o \
         $(PROFILE_A_DIR)/poly1305_lib.o \
         $(PROFILE_A_DIR)/chacha20poly1305_lib.o \
         $(PROFILE_A_DIR)/data_lib.o \
         $(PROFILE_A_DIR)/lib_version.o \
         $(PROFILE_A_DIR)/lib_manifest.o

B_OBJS = $(PROFILE_B_DIR)/main.o \
         $(PROFILE_B_DIR)/zp_config.o \
         $(PROFILE_B_DIR)/word32_lib.o \
         $(PROFILE_B_DIR)/chacha20_lib.o \
         $(PROFILE_B_DIR)/poly1305_lib.o \
         $(PROFILE_B_DIR)/chacha20poly1305_lib.o \
         $(PROFILE_B_DIR)/data_lib.o \
         $(PROFILE_B_DIR)/lib_version.o \
         $(PROFILE_B_DIR)/lib_manifest.o

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
          $(PROFILE_BR_DIR)/chacha20poly1305_lib.o \
          $(PROFILE_BR_DIR)/data_lib.o \
          $(PROFILE_BR_DIR)/lib_version.o \
          $(PROFILE_BR_DIR)/lib_manifest.o

BO_OBJS = $(PROFILE_BO_DIR)/main.o \
          $(PROFILE_BO_DIR)/zp_config.o \
          $(PROFILE_BO_DIR)/word32_lib.o \
          $(PROFILE_BO_DIR)/chacha20_lib.o \
          $(PROFILE_BO_DIR)/poly1305_lib.o \
          $(PROFILE_BO_DIR)/chacha20poly1305_lib.o \
          $(PROFILE_BO_DIR)/data_lib.o \
          $(PROFILE_BO_DIR)/lib_version.o \
          $(PROFILE_BO_DIR)/lib_manifest.o

.PHONY: all clean run profile-a profile-b profile-b-rolled profile-b-rolled-outer dist lib lib-aead-only

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

$(PROFILE_A_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_A_DIR)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(PROFILE_A_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_A_DIR)
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

$(PROFILE_B_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_B_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_B_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
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

$(PROFILE_BR_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_BR_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BR_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_BR_DIR)
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

$(PROFILE_BO_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/lib_version.o: src/lib_version.s | $(PROFILE_BO_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(PROFILE_BO_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(PROFILE_BO_DIR)
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
#   make lib              build/lib/c64-chacha20-poly1305.a
#                         Full Profile-B archive. Every public ABI
#                         export plus the test-only entry points
#                         (chacha20_quarter_round, mul_8x8, rotl32_1,
#                         rotl32_7, rotr32_7) so a downstream Python
#                         test harness can jsr() into the same labels
#                         the upstream harness does.
#
#   make lib-aead-only    build/lib/c64-chacha20-poly1305-aead-only.a
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
           $(LIB_OBJS_DIR)/chacha20poly1305_lib.o \
           $(LIB_OBJS_DIR)/data_lib.o \
           $(LIB_OBJS_DIR)/lib_version.o \
           $(LIB_OBJS_DIR)/lib_manifest.o

LIB_AEAD_ONLY_OBJS = $(LIB_AEAD_ONLY_OBJS_DIR)/word32_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/chacha20_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/chacha20poly1305_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/data_lib.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/lib_version.o \
                     $(LIB_AEAD_ONLY_OBJS_DIR)/lib_manifest.o

# --- Full archive (Profile B, every export) --------------------------------
$(LIB_OBJS_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/lib_version.o: src/lib_version.s | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

$(LIB_OBJS_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(LIB_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $< -o $@

# ar65 r appends; rebuild from a clean archive every time so we don't
# accumulate stale modules from a previous invocation.
lib: $(LIB_FULL_AR)

$(LIB_FULL_AR): $(LIB_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 r $@ $(LIB_OBJS)

# --- aead-only variant (test-only exports stripped) ------------------------
LIB_AEAD_ONLY_DEFINE = -DLIB_VARIANT_AEAD_ONLY=1

$(LIB_AEAD_ONLY_OBJS_DIR)/word32_lib.o: src/lib/word32_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/chacha20_lib.o: src/lib/chacha20_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/poly1305_lib.o: src/lib/poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/chacha20poly1305_lib.o: src/lib/chacha20poly1305_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/data_lib.o: src/lib/data_lib.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/lib_version.o: src/lib_version.s | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

$(LIB_AEAD_ONLY_OBJS_DIR)/lib_manifest.o: src/lib/lib_manifest.s $(SRCS_INCLUDES) | $(LIB_AEAD_ONLY_OBJS_DIR)
	$(CA65) $(CA65FLAGS) $(LIB_AEAD_ONLY_DEFINE) $< -o $@

lib-aead-only: $(LIB_AEAD_ONLY_AR)

$(LIB_AEAD_ONLY_AR): $(LIB_AEAD_ONLY_OBJS) | $(LIB_DIR)
	rm -f $@
	ar65 r $@ $(LIB_AEAD_ONLY_OBJS)

$(LIB_DIR):
	mkdir -p $(LIB_DIR)

$(LIB_OBJS_DIR):
	mkdir -p $(LIB_OBJS_DIR)

$(LIB_AEAD_ONLY_OBJS_DIR):
	mkdir -p $(LIB_AEAD_ONLY_OBJS_DIR)

# Reproducible source tarball for a tagged release.
# Usage: make dist VERSION=v0.5.0
dist:
	@if [ -z "$(VERSION)" ]; then \
	  echo "usage: make dist VERSION=v0.5.0" >&2; \
	  exit 1; \
	fi
	@tools/build_release.sh $(VERSION)
