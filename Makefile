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

# # MARKED: TO BE EDITED + MARKED AS REMOVED LATER
# KHAOS_BPF_OBJ = khaos.bpf.o
# KHAOS_SKEL = khaos.skel.h

# New file output for kprobe
KPROBE_BPF_OBJ = kprobe.bpf.c
KPROBE_SKEL = kprobe.skel.h

# Added placeholders for all KPROBE's and KRETPROBE's SKEL and OBJ
ALL_BPF_OBJS = $(KPROBE_BPF_OBJ)
ALL_SKELS = $(KPROBE_SKEL)

all: khaos $(ALL_BPF_OBJS)

# # MARKED: TO BE REPLACED BY SEPARATE KPROBE AND KRETPROBE RULES
# $(KHAOS_BPF_OBJ): khaos.bpf.c
# 	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
# 	$(BPF_STRIP) $@
#
# $(KHAOS_SKEL): $(KHAOS_BPF_OBJ)
# 	bpftool gen skeleton $< > $@

# RULES FOR SETTING UP KPROBE OBJ AND SKEL
$(KPROBE_BPF_OBJ): kprobe.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) $(ARCH_FLAG) -c $< -o $@
	$(BPF_STRIP) $@

$(KPROBE_SKEL): $(KPROBE_BPF_OBJ)
	bpftool gen skeleton $< > $@


khaos: khaos.c $(KHAOS_SKEL)
	$(HOST_CC) -std=c11 -Wall -O2 $(CFLAGS) khaos.c -o $@ $(LDFLAGS) -static -lbpf -lelf -lz -lzstd

clean:
	rm -f khaos *.o *.skel.h
