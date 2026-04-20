# =============================================================================
# examples/smoke_test/Makefile
#
# Consumer-side build for the ChaCha20-Poly1305 smoke test. Pretends we are
# a downstream ca65 project that vendored the library under
# third_party/c64-chacha20poly1305-v0.3.0/ and now links its own main
# program (smoke_test.s) against the library modules.
#
# Deliberately does NOT reuse the library's own root Makefile — everything
# here is consumer-written, to flex the same surface a real consumer would
# have to flex.
#
# Targets:
#   make                 build profile A (default)
#   make profile-a       build profile A (Shoup tables, long-message optimized)
#   make profile-b       build profile B (portable, short-message optimized)
#   make both            build both profiles
#   make run             profile A in x64sc
#   make run-b           profile B in x64sc
#   make clean           remove build/
# =============================================================================

CA65 = ca65
LD65 = ld65

LIB_DIR     = third_party/c64-chacha20poly1305-v0.3.0
LIB_SRC     = $(LIB_DIR)/src/lib
LIB_INCLUDE = $(LIB_DIR)/src/include

# Consumer's own ca65 flags: -t c64, debug info, and include paths that
# reach into the vendored library's lib + include directories. Note that
# the library's own src/c64.cfg is NOT used — we link against our own
# smoke_test.cfg.
CA65FLAGS = -t c64 -g -I $(LIB_SRC) -I $(LIB_INCLUDE)
CFG       = smoke_test.cfg

# Library modules: assembled once per profile. constants_lib.s is equate-
# only (.include'd, no .o). Matching the upstream module list verbatim.
LIB_MODULES = word32_lib chacha20_lib poly1305_lib chacha20poly1305_lib data_lib

BUILD_A = build/profile-a
BUILD_B = build/profile-b

A_OBJS = $(BUILD_A)/smoke_test.o \
         $(BUILD_A)/word32_lib.o \
         $(BUILD_A)/chacha20_lib.o \
         $(BUILD_A)/poly1305_lib.o \
         $(BUILD_A)/chacha20poly1305_lib.o \
         $(BUILD_A)/data_lib.o

B_OBJS = $(BUILD_B)/smoke_test.o \
         $(BUILD_B)/word32_lib.o \
         $(BUILD_B)/chacha20_lib.o \
         $(BUILD_B)/poly1305_lib.o \
         $(BUILD_B)/chacha20poly1305_lib.o \
         $(BUILD_B)/data_lib.o

PRG_A    = $(BUILD_A)/smoke_test.prg
PRG_B    = $(BUILD_B)/smoke_test.prg
LABELS_A = $(BUILD_A)/labels.txt
LABELS_B = $(BUILD_B)/labels.txt

.PHONY: all profile-a profile-b both run run-b clean

all: profile-a

both: profile-a profile-b

# Convert ld65 label format to VICE format (cosmetic; harness reads either).
define FIXLABELS
sed 's/^al \([0-9a-fA-F]*\)/al C:\1/' $(1) > $(1).tmp && mv $(1).tmp $(1)
endef

# ------------------------------------------------------------------------
# Profile A: POLY1305_PROFILE_LONG = 1 (Shoup per-r tables, long messages)
# ------------------------------------------------------------------------
$(BUILD_A)/smoke_test.o: smoke_test.s | $(BUILD_A)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

$(BUILD_A)/%.o: $(LIB_SRC)/%.s | $(BUILD_A)
	$(CA65) $(CA65FLAGS) -DPOLY1305_PROFILE_LONG=1 $< -o $@

profile-a: $(PRG_A)

$(PRG_A): $(A_OBJS) $(CFG) | $(BUILD_A)
	$(LD65) -C $(CFG) -Ln $(LABELS_A) $(A_OBJS) -o $(PRG_A)
	$(call FIXLABELS,$(LABELS_A))

# ------------------------------------------------------------------------
# Profile B: POLY1305_PROFILE_LONG undefined (portable, short messages)
# ------------------------------------------------------------------------
$(BUILD_B)/smoke_test.o: smoke_test.s | $(BUILD_B)
	$(CA65) $(CA65FLAGS) $< -o $@

$(BUILD_B)/%.o: $(LIB_SRC)/%.s | $(BUILD_B)
	$(CA65) $(CA65FLAGS) $< -o $@

profile-b: $(PRG_B)

$(PRG_B): $(B_OBJS) $(CFG) | $(BUILD_B)
	$(LD65) -C $(CFG) -Ln $(LABELS_B) $(B_OBJS) -o $(PRG_B)
	$(call FIXLABELS,$(LABELS_B))

# ------------------------------------------------------------------------
# Directory rules + VICE runners
# ------------------------------------------------------------------------
$(BUILD_A):
	mkdir -p $(BUILD_A)

$(BUILD_B):
	mkdir -p $(BUILD_B)

run: profile-a
	x64sc -autostart $(PRG_A)

run-b: profile-b
	x64sc -autostart $(PRG_B)

clean:
	rm -rf build
