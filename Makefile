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

SRC = $(wildcard src/*.asm) $(wildcard src/lib/*.asm)

.PHONY: all clean run profile-a profile-b

# Default build == Profile A (POLY1305_PROFILE_LONG defined).
all: profile-a

# ---- Profile A: POLY1305_PROFILE_LONG = 1 (default, "long message" path) ----
profile-a: $(SRC) | $(PROFILE_A_DIR) build
	cd src && acme -f cbm -DPOLY1305_PROFILE_LONG=1 \
	    -o ../$(PROFILE_A_DIR)/$(PRG_NAME) \
	    --vicelabels ../$(PROFILE_A_DIR)/$(LABELS_NAME) main.asm
	cp $(PROFILE_A_DIR)/$(PRG_NAME) $(PRG)
	cp $(PROFILE_A_DIR)/$(LABELS_NAME) $(LABELS)

# ---- Profile B: POLY1305_PROFILE_LONG undefined (stock C64 / portable) ----
profile-b: $(SRC) | $(PROFILE_B_DIR) build
	cd src && acme -f cbm \
	    -o ../$(PROFILE_B_DIR)/$(PRG_NAME) \
	    --vicelabels ../$(PROFILE_B_DIR)/$(LABELS_NAME) main.asm
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
