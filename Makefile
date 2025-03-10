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

all: err_inject

%.bpf.o: %.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@

%.skel.h: %.bpf.o
	bpftool gen skeleton $< > $@

err_inject: err_inject.c err_inject.skel.h
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) $< -o $@ $(LDFLAGS) -static -lbpf -lelf -lz -lzstd

clean:
	rm -rf ebpf err_inject *.o *.skel.h
