ARCH ?= x86

BPF_CLANG = clang
BPF_CFLAGS = -target bpf -Wall -O2 -g
BPF_STRIP = llvm-strip -g

CFLAGS += -I./libbpf/include/uapi -I./libbpf/include
LDFLAGS += -L./libbpf/src -lbpf

ifeq ($(ARCH), x86)
    ARCH_FLAG = -D__x86_64__
    HOST_CC = gcc
else ifeq ($(ARCH), arm)
    ARCH_FLAG = -D__aarch64__
    HOST_CC = aarch64-linux-gnu-gcc
endif

FAULTS_DIR = faults
FAULT_PROGS = $(wildcard $(FAULTS_DIR)/*.bpf.c)
FAULT_BPF_OBJS = $(FAULT_PROGS:.bpf.c=.bpf.o)
FAULT_SKELS = $(FAULT_BPF_OBJS:.bpf.o=.skel.h)

all: khaos $(FAULT_BPF_OBJS)

$(FAULTS_DIR)/%.bpf.o: $(FAULTS_DIR)/%.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@

$(FAULTS_DIR)/%.skel.h: $(FAULTS_DIR)/%.bpf.o
	bpftool gen skeleton $< > $@

khaos: khaos.c $(FAULT_SKELS)
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) khaos.c -o $@ $(LDFLAGS) -static -lbpf -lelf -lz -lzstd

clean:
	rm -rf ebpf khaos *.o *.skel.h $(FAULTS_DIR)/*.o $(FAULTS_DIR)/*.skel.h
