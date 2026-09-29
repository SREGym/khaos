# =========================
# Architecture auto-detect
# =========================
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
    ARCH ?= x86
    HOST_CC = gcc
else ifeq ($(UNAME_M),aarch64)
    ARCH ?= arm64
    HOST_CC = aarch64-linux-gnu-gcc
endif

ifeq ($(ARCH),x86)
    ARCH_FLAG = -D__TARGET_ARCH_x86
else ifneq ($(filter $(ARCH),arm arm64),)
    ARCH_FLAG = -D__TARGET_ARCH_arm64
else
    $(error Unsupported ARCH '$(ARCH)'; expected x86, arm, or arm64)
endif

# =========================
# BPF compiler settings
# =========================
BPF_CLANG = clang
MULTIARCH_INCLUDE = /usr/include/$(shell $(HOST_CC) -dumpmachine)
BPF_CFLAGS = -target bpf -Wall -O2 -g $(ARCH_FLAG) -I. -I$(MULTIARCH_INCLUDE)
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
LATENT_SECTOR_ERROR_BPF_OBJ = kprobe_latent_sector_error.bpf.o

KPROBE_SKEL = kprobe.skel.h
KRETPROBE_SKEL = kretprobe.skel.h
PACKET_LOSS_SENDTO_SKEL = kprobe_packet_loss_sendto.skel.h
PACKET_LOSS_RECVFROM_SKEL = kprobe_packet_loss_recvfrom.skel.h
LATENT_SECTOR_ERROR_SKEL = kprobe_latent_sector_error.skel.h

ALL_BPF_OBJS = $(KPROBE_BPF_OBJ) $(KRETPROBE_BPF_OBJ) \
               $(PACKET_LOSS_SENDTO_BPF_OBJ) $(PACKET_LOSS_RECVFROM_BPF_OBJ) \
               $(LATENT_SECTOR_ERROR_BPF_OBJ)
ALL_SKELS = $(KPROBE_SKEL) $(KRETPROBE_SKEL) \
            $(PACKET_LOSS_SENDTO_SKEL) $(PACKET_LOSS_RECVFROM_SKEL) \
            $(LATENT_SECTOR_ERROR_SKEL)

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
	@if [ ! -f vmlinux.h ]; then \
		if ! command -v bpftool >/dev/null; then \
			echo "Error: bpftool not found. Please install with 'sudo apt install bpftool'."; \
			exit 1; \
		fi; \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	else \
		echo "vmlinux.h already exists, skipping generation"; \
	fi

# Compile eBPF object files (depend on vmlinux.h)
$(KPROBE_BPF_OBJ): kprobe.bpf.c pid_filter.bpf.h pid_namespace.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(KRETPROBE_BPF_OBJ): kretprobe.bpf.c pid_filter.bpf.h pid_namespace.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(PACKET_LOSS_SENDTO_BPF_OBJ): network_faults/kprobe_packet_loss_sendto.bpf.c pid_filter.bpf.h pid_namespace.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@

$(PACKET_LOSS_RECVFROM_BPF_OBJ): network_faults/kprobe_packet_loss_recvfrom.bpf.c pid_filter.bpf.h pid_namespace.h vmlinux.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_STRIP) $@


$(LATENT_SECTOR_ERROR_BPF_OBJ): kprobe_latent_sector_error.bpf.c pid_filter.bpf.h pid_namespace.h vmlinux.h
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


$(LATENT_SECTOR_ERROR_SKEL): $(LATENT_SECTOR_ERROR_BPF_OBJ)
	bpftool gen skeleton $< > $@

# Compile host binary (using local shared libbpf for Docker)
khaos-dynamic: khaos.c pid_namespace.h $(ALL_SKELS)
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) khaos.c -o khaos ./libbpf/src/libbpf.so.1.6.0 $(LDFLAGS)

# Compile host binary (static libbpf)
khaos: khaos.c pid_namespace.h $(ALL_SKELS)
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
