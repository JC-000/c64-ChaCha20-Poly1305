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

CA65 = ca65
LD65 = ld65
CA65FLAGS = -t c64 -g -I src/include -I src/lib
CFG = src/c64.cfg

# --- Module list -----------------------------------------------------------
# Each source file compiles to its own .o. Order matters only for the
# link line (ld65 resolves symbols regardless but segment packing
# reflects link order). Constants_lib is equates-only and is .include'd
# by the modules that need ZP equate values, so it has no .o of its own.
MODULES = main word32_lib chacha20_lib poly1305_lib chacha20poly1305_lib data_lib lib_version

SRCS_MAIN     = src/main.s
SRCS_LIB      = $(wildcard src/lib/*.s)
SRCS_INCLUDES = src/lib/constants_lib.s

# Object file list per profile (order matches MODULES).
A_OBJS = $(PROFILE_A_DIR)/main.o \
         $(PROFILE_A_DIR)/word32_lib.o \
         $(PROFILE_A_DIR)/chacha20_lib.o \
         $(PROFILE_A_DIR)/poly1305_lib.o \
         $(PROFILE_A_DIR)/chacha20poly1305_lib.o \
         $(PROFILE_A_DIR)/data_lib.o \
         $(PROFILE_A_DIR)/lib_version.o

B_OBJS = $(PROFILE_B_DIR)/main.o \
         $(PROFILE_B_DIR)/word32_lib.o \
         $(PROFILE_B_DIR)/chacha20_lib.o \
         $(PROFILE_B_DIR)/poly1305_lib.o \
         $(PROFILE_B_DIR)/chacha20poly1305_lib.o \
         $(PROFILE_B_DIR)/data_lib.o \
         $(PROFILE_B_DIR)/lib_version.o

.PHONY: all clean run profile-a profile-b dist

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

profile-a: $(A_OBJS) $(CFG) | build
	$(LD65) -C $(CFG) -Ln $(PROFILE_A_DIR)/$(LABELS_NAME) \
	    $(A_OBJS) -o $(PROFILE_A_DIR)/$(PRG_NAME)
	$(call FIXLABELS,$(PROFILE_A_DIR)/$(LABELS_NAME))
	cp $(PROFILE_A_DIR)/$(PRG_NAME) $(PRG)
	cp $(PROFILE_A_DIR)/$(LABELS_NAME) $(LABELS)

# ---- Profile B: POLY1305_PROFILE_LONG undefined (stock C64 / portable) ----
$(PROFILE_B_DIR)/main.o: src/main.s $(SRCS_INCLUDES) | $(PROFILE_B_DIR)
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

run: profile-a
	x64sc -autostart $(PRG)

clean:
	rm -rf build

# Reproducible source tarball for a tagged release.
# Usage: make dist VERSION=v0.5.0
dist:
	@if [ -z "$(VERSION)" ]; then \
	  echo "usage: make dist VERSION=v0.5.0" >&2; \
	  exit 1; \
	fi
	@tools/build_release.sh $(VERSION)
