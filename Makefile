PRG = build/c64_chacha20_poly1305.prg
LABELS = build/labels.txt

SRC = $(wildcard src/*.asm) $(wildcard src/lib/*.asm)

.PHONY: all clean run

all: $(PRG)

$(PRG): $(SRC) | build
	cd src && acme -f cbm -o ../$(PRG) --vicelabels ../$(LABELS) main.asm

build:
	mkdir -p build

run: $(PRG)
	x64sc -autostart $(PRG)

clean:
	rm -f $(PRG) $(LABELS)
