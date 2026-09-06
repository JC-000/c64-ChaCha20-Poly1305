# test_consumer/Makefile — link the minimal AEAD consumer against both
# library variants and dump map.txt for the size-delta measurement.

CA65       = ca65
LD65       = ld65
CA65FLAGS  = -t c64 -g -I ../src/include -I ../src/lib
CFG        = min_consumer.cfg

PROJECT_ROOT = ..

# Canonical §6.1 basenames. The deprecated `c64-chacha20-poly1305*.a`
# copies are still produced during the §6.5 window; linking the canonical
# ones here is what proves a consumer can migrate off the old spelling.
LIB_FULL = $(PROJECT_ROOT)/build/lib/chacha20poly1305.a
LIB_AEAD = $(PROJECT_ROOT)/build/lib/chacha20poly1305-aead-only.a

BUILD = build

.PHONY: all clean full aead_only smoke-full smoke-aead app-owned-default-link

all: full aead_only smoke-full smoke-aead app-owned-default-link

# The consumer side provides:
#   - min_aead_consumer.o   (its own program)
#   - zp_config.o           (assembled separately from the lib's
#                            src/zp_config.s; per SPEC §2 consumers
#                            either ship their own zp_config or
#                            override slots via -D)
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

# --- SPEC §6.1 member isolation, demonstrated at the LINK (issue #108) -----
# The behavioural half of `make lib-verify-isolation`. That target reads
# symbol tables; this one links, which is where the clause's failure actually
# shows up.
#
# app_owned_consumer.s is a SPEC §8.0 APP_OWNED consumer: it supplies the
# §8.1 and §8.3 shared primitives from its own object and links the DEFAULT
# archive — no rebuild of the library, no deferral define. That is the
# configuration §6.1 exists for, and the one c64-wireguard would be in if it
# did not know to pass `-D SHARED_SQTAB_INIT=1 -D SHARED_CT_MUL_8X8=1`.
#
# MEASURED at v0.10.0, before the member split:
#
#     ld65: Error: Duplicate external identifier: 'sqtab_init'
#
# — because `poly1305_lib.o` held the eight displaceable names alongside the
# nine Poly1305 entry points, so importing `aead_encrypt` dragged the member
# in beside the consumer's own definitions. Post-split the consumer's object,
# being on the command line, is in the symbol table first, the library's
# imports resolve against it, and shared_ct_mul.o / shared_prod_scratch.o /
# mul_8x8_legacy.o / shared_sqtab_init.o are never pulled. Check
# build/app-owned.map to see that for yourself.
#
# If this target ever fails again with a duplicate external, a displaceable
# name has been merged back into a member that also exports something a
# consumer imports.
app-owned-default-link: $(BUILD)/app_owned-full.prg

$(BUILD)/app_owned_consumer.o: app_owned_consumer.s | $(BUILD)
	$(CA65) $(CA65FLAGS) $< -o $@

$(BUILD)/app_owned-full.prg: $(BUILD)/app_owned_consumer.o $(BUILD)/zp_config.o $(LIB_FULL) | $(BUILD)
	$(LD65) -C $(CFG) -m $(BUILD)/app-owned.map -Ln $(BUILD)/app-owned.labels \
	    $(BUILD)/app_owned_consumer.o $(BUILD)/zp_config.o $(LIB_FULL) -o $@

clean:
	rm -rf $(BUILD)
