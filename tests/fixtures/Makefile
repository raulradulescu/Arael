# Makefile for building Arael test fixtures
# Run `make` to build all test binaries

CC = gcc
CFLAGS = -g -O0

BINARIES = hello_world recursive_calls

all: $(BINARIES)

hello_world: hello_world.c
	$(CC) $(CFLAGS) -o $@ $<

recursive_calls: recursive_calls.c
	$(CC) $(CFLAGS) -o $@ $<

# Stripped version (tests without symbols)
hello_stripped: hello_world.c
	$(CC) -O2 -s -o $@ $<

# Static linked version (larger binary)
hello_static: hello_world.c
	$(CC) -static -o $@ $<

clean:
	rm -f $(BINARIES) hello_stripped hello_static

.PHONY: all clean
