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


# New file output for kprobe
KPROBE_BPF_OBJ = kprobe.bpf.o
KRETPROBE_BPF_OBJ = kretprobe.bpf.o
KPROBE_SKEL = kprobe.skel.h
KRETPROBE_SKEL = kretprobe.skel.h

# Added placeholders for all KPROBE's and KRETPROBE's SKEL and OBJ
ALL_BPF_OBJS = $(KPROBE_BPF_OBJ) $(KRETPROBE_BPF_OBJ)
ALL_SKELS = $(KPROBE_SKEL) $(KRETPROBE_SKEL)

all: khaos $(ALL_BPF_OBJS)


# RULES FOR SETTING UP KPROBE OBJ AND SKEL
$(KPROBE_BPF_OBJ): kprobe.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@


# RULES FOR SETTING UP KPROBE OBJ AND SKEL
$(KRETPROBE_BPF_OBJ): kretprobe.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@

$(KPROBE_SKEL): $(KPROBE_BPF_OBJ)
	bpftool gen skeleton $< > $@


khaos: khaos.c $(ALL_SKELS)
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) khaos.c -o $@ $(LDFLAGS) -static -lbpf -lelf -lz -lzstd

clean:
	rm -f khaos *.o *.skel.h
