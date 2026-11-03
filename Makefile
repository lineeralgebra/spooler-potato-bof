###############################################################################
# Makefile — spooler-potato BOF
# Cross-compiles spooler_potato_bof.c (+ MIDL stubs) to a COFF object.
#
# Requirements: sudo apt install mingw-w64
#
# Usage:
#   make          — build x64 .o (default)
#   make clean    — remove compiled object
###############################################################################

CC64 = x86_64-w64-mingw32-gcc
SRC  = spooler_potato_bof.c

CFLAGS = -c -DBOF -O2 -Wall -Wno-unknown-pragmas -I.

.PHONY: all clean

all: spooler_potato_bof.o

spooler_potato_bof.o: $(SRC) ms-rprn_c.c ms-rprn_h.h beacon.h
	$(CC64) $(CFLAGS) -o $@ $<
	@echo "[+] Built $@"

clean:
	@echo "[*] Removing compiled object..."
	@rm -f spooler_potato_bof.o
	@echo "[+] Done."
