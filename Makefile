ARCH ?= x86

# BPF-specific
BPF_CLANG = clang
BPF_CFLAGS = -target bpf -Wall -O2 -g
BPF_STRIP = llvm-strip -g

# Include and Link flags for libbpf
CFLAGS += -I./libbpf/include/uapi -I./libbpf/include
CFLAGS += -I./libbpf/include/uapi -I./libbpf/include -D_POSIX_C_SOURCE=199309L
LDFLAGS += -L./libbpf/src -lbpf

# Architecture-dependent flags
ifeq ($(ARCH), x86)
    ARCH_FLAG = -D__x86_64__
    HOST_CC = gcc
else ifeq ($(ARCH), arm)
    ARCH_FLAG = -D__aarch64__
    HOST_CC = aarch64-linux-gnu-gcc
endif

# eBPF build artifacts
KPROBE_BPF_OBJ = kprobe.bpf.o
KRETPROBE_BPF_OBJ = kretprobe.bpf.o
KPROBE_SKEL = kprobe.skel.h
KRETPROBE_SKEL = kretprobe.skel.h
ALL_BPF_OBJS = $(KPROBE_BPF_OBJ) $(KRETPROBE_BPF_OBJ)
ALL_SKELS = $(KPROBE_SKEL) $(KRETPROBE_SKEL)

# Test file directories
TESTS_DIR := tests
TEST_BIN_DIR := $(TESTS_DIR)/bin

# Find all C test source files recursively
TEST_C_SRCS := $(shell find $(TESTS_DIR) -name '*.c')
# Generate corresponding binary paths in bin/
TEST_C_BINS := $(patsubst $(TESTS_DIR)/%.c, $(TEST_BIN_DIR)/%, $(TEST_C_SRCS))
TEST_CFLAGS := -std=c11 -Wall -O2

# Default target
all: khaos $(ALL_BPF_OBJS)

# Target to build all C test binaries
tests: $(TEST_C_BINS)

# Compile eBPF object files
$(KPROBE_BPF_OBJ): kprobe.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@

$(KRETPROBE_BPF_OBJ): kretprobe.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@

# Generate skeleton headers
$(KPROBE_SKEL): $(KPROBE_BPF_OBJ)
	bpftool gen skeleton $< > $@

$(KRETPROBE_SKEL): $(KRETPROBE_BPF_OBJ)
	bpftool gen skeleton $< > $@

# Compile host binary
khaos: khaos.c $(ALL_SKELS)
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) khaos.c -o $@ $(LDFLAGS) -static -lbpf -lelf -lz -lzstd

# Rule to compile each test binary from its source
$(TEST_BIN_DIR)/%: $(TESTS_DIR)/%.c
	@mkdir -p $(dir $@)
	$(HOST_CC) $(TEST_CFLAGS) -o $@ $^

# Clean up everything
clean:
	rm -f khaos *.o *.skel.h
	rm -rf $(TEST_BIN_DIR)

.PHONY: all tests clean
