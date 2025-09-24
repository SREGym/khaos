# =========================
# Architecture auto-detect
# =========================
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH ?= x86
    ARCH_FLAG = -D__x86_64__
    HOST_CC = gcc
else ifeq ($(UNAME_M),aarch64)
    ARCH ?= arm64
    ARCH_FLAG = -D__aarch64__
    HOST_CC = aarch64-linux-gnu-gcc
endif

# =========================
# BPF compiler settings
# =========================
BPF_CLANG = clang
BPF_CFLAGS = -target bpf -Wall -O2 -g $(ARCH_FLAG) -I.
BPF_STRIP = llvm-strip -g

# =========================
# libbpf settings
# =========================
CFLAGS += -I./libbpf/include/uapi -I./libbpf/include -D_POSIX_C_SOURCE=199309L
# Link against static libbpf instead of -lbpf shared object
LIBBPF_STATIC = ./libbpf/src/libbpf.a
LDFLAGS += -lelf -lz -lzstd

# =========================
# eBPF build artifacts
# =========================
KPROBE_BPF_OBJ = kprobe.bpf.o
KRETPROBE_BPF_OBJ = kretprobe.bpf.o
PACKET_LOSS_SENDTO_BPF_OBJ = kprobe_packet_loss_sendto.bpf.o
PACKET_LOSS_RECVFROM_BPF_OBJ = kprobe_packet_loss_recvfrom.bpf.o
BLOCK_READ_ERROR_BPF_OBJ = kprobe_block_read_error.bpf.o

KPROBE_SKEL = kprobe.skel.h
KRETPROBE_SKEL = kretprobe.skel.h
PACKET_LOSS_SENDTO_SKEL = kprobe_packet_loss_sendto.skel.h
PACKET_LOSS_RECVFROM_SKEL = kprobe_packet_loss_recvfrom.skel.h
BLOCK_READ_ERROR_SKEL = kprobe_block_read_error.skel.h

ALL_BPF_OBJS = $(KPROBE_BPF_OBJ) $(KRETPROBE_BPF_OBJ) \
               $(PACKET_LOSS_SENDTO_BPF_OBJ) $(PACKET_LOSS_RECVFROM_BPF_OBJ) \
               $(BLOCK_READ_ERROR_BPF_OBJ)
ALL_SKELS = $(KPROBE_SKEL) $(KRETPROBE_SKEL) \
            $(PACKET_LOSS_SENDTO_SKEL) $(PACKET_LOSS_RECVFROM_SKEL) \
            $(BLOCK_READ_ERROR_SKEL)

# =========================
# Test binaries
# =========================
TESTS_DIR := tests
TEST_BIN_DIR := $(TESTS_DIR)/bin

TEST_C_SRCS := $(shell find $(TESTS_DIR) -name '*.c')
TEST_C_BINS := $(patsubst $(TESTS_DIR)/%.c, $(TEST_BIN_DIR)/%, $(TEST_C_SRCS))
TEST_CFLAGS := -std=c11 -Wall -O2

# =========================
# Targets
# =========================
all: khaos $(ALL_BPF_OBJS)

tests: $(TEST_C_BINS)

# Generate vmlinux.h once (BTF required in kernel)
vmlinux.h:
	@if ! command -v bpftool >/dev/null; then \
		echo "Error: bpftool not found. Please install with 'sudo apt install bpftool'."; \
		exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile eBPF object files (depend on vmlinux.h)
$(KPROBE_BPF_OBJ): kprobe.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(KRETPROBE_BPF_OBJ): kretprobe.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(PACKET_LOSS_SENDTO_BPF_OBJ): network_faults/kprobe_packet_loss_sendto.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(PACKET_LOSS_RECVFROM_BPF_OBJ): network_faults/kprobe_packet_loss_recvfrom.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(BLOCK_READ_ERROR_BPF_OBJ): kprobe_block_read_error.bpf.c vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

# Generate skeleton headers
$(KPROBE_SKEL): $(KPROBE_BPF_OBJ)
	bpftool gen skeleton $< > $@

$(KRETPROBE_SKEL): $(KRETPROBE_BPF_OBJ)
	bpftool gen skeleton $< > $@

$(PACKET_LOSS_SENDTO_SKEL): $(PACKET_LOSS_SENDTO_BPF_OBJ)
	bpftool gen skeleton $< > $@

$(PACKET_LOSS_RECVFROM_SKEL): $(PACKET_LOSS_RECVFROM_BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BLOCK_READ_ERROR_SKEL): $(BLOCK_READ_ERROR_BPF_OBJ)
	bpftool gen skeleton $< > $@

# Compile host binary (static libbpf)
khaos: khaos.c $(ALL_SKELS)
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) khaos.c -o $@ $(LIBBPF_STATIC) $(LDFLAGS)

# Rule to compile each test binary
$(TEST_BIN_DIR)/%: $(TESTS_DIR)/%.c
	@mkdir -p $(dir $@)
	$(HOST_CC) $(TEST_CFLAGS) -o $@ $^

# Clean
clean:
	rm -f khaos *.o *.skel.h vmlinux.h
	rm -rf $(TEST_BIN_DIR)

.PHONY: all tests clean
