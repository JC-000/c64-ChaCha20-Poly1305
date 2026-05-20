# test_consumer/Makefile — link the minimal AEAD consumer against both
# library variants and dump map.txt for the size-delta measurement.

CA65       = ca65
LD65       = ld65
CA65FLAGS  = -t c64 -g -I ../src/include -I ../src/lib
CFG        = min_consumer.cfg

PROJECT_ROOT = ..

LIB_FULL = $(PROJECT_ROOT)/build/lib/c64-chacha20-poly1305.a
LIB_AEAD = $(PROJECT_ROOT)/build/lib/c64-chacha20-poly1305-aead-only.a

BUILD = build

.PHONY: all clean full aead_only smoke-full smoke-aead

all: full aead_only smoke-full smoke-aead

# The consumer side provides:
#   - min_aead_consumer.o   (its own program)
#   - zp_config.o           (assembled separately from the lib's
#                            src/zp_config.s; per SPEC §2 consumers
#                            either ship their own zp_config or
#                            override slots via --asm-define)
# and pulls every other module from the .a archive.

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/min_aead_consumer.o: min_aead_consumer.s | $(BUILD)
	$(CA65) $(CA65FLAGS) $< -o $@

$(BUILD)/zp_config.o: $(PROJECT_ROOT)/src/zp_config.s | $(BUILD)
	$(CA65) $(CA65FLAGS) $< -o $@

# --- Full archive link ---
full: $(BUILD)/min_aead_consumer-full.prg

$(BUILD)/min_aead_consumer-full.prg: $(BUILD)/min_aead_consumer.o $(BUILD)/zp_config.o $(LIB_FULL) | $(BUILD)
	$(LD65) -C $(CFG) -m $(BUILD)/full.map -Ln $(BUILD)/full.labels \
	    $(BUILD)/min_aead_consumer.o $(BUILD)/zp_config.o $(LIB_FULL) -o $@

# --- aead-only archive link ---
aead_only: $(BUILD)/min_aead_consumer-aead.prg

$(BUILD)/min_aead_consumer-aead.prg: $(BUILD)/min_aead_consumer.o $(BUILD)/zp_config.o $(LIB_AEAD) | $(BUILD)
	$(LD65) -C $(CFG) -m $(BUILD)/aead.map -Ln $(BUILD)/aead.labels \
	    $(BUILD)/min_aead_consumer.o $(BUILD)/zp_config.o $(LIB_AEAD) -o $@

$(BUILD)/aead_smoke.o: aead_smoke.s | $(BUILD)
	$(CA65) $(CA65FLAGS) $< -o $@

# --- Runnable smoke PRGs linked against each archive ---
smoke-full: $(BUILD)/aead_smoke-full.prg

$(BUILD)/aead_smoke-full.prg: $(BUILD)/aead_smoke.o $(BUILD)/zp_config.o $(LIB_FULL) | $(BUILD)
	$(LD65) -C $(CFG) -m $(BUILD)/smoke-full.map -Ln $(BUILD)/smoke-full.labels \
	    $(BUILD)/aead_smoke.o $(BUILD)/zp_config.o $(LIB_FULL) -o $@

smoke-aead: $(BUILD)/aead_smoke-aead.prg

$(BUILD)/aead_smoke-aead.prg: $(BUILD)/aead_smoke.o $(BUILD)/zp_config.o $(LIB_AEAD) | $(BUILD)
	$(LD65) -C $(CFG) -m $(BUILD)/smoke-aead.map -Ln $(BUILD)/smoke-aead.labels \
	    $(BUILD)/aead_smoke.o $(BUILD)/zp_config.o $(LIB_AEAD) -o $@

clean:
	rm -rf $(BUILD)
