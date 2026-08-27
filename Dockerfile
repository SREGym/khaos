FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    gcc \
    make \
    pkg-config \
    build-essential \
    libelf-dev \
    zlib1g-dev \
    libzstd-dev \
    libssl-dev \
    linux-headers-generic \
    linux-tools-common \
    linux-tools-generic \
    git \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install a working bpftool
RUN ln -sf /usr/lib/linux-tools/*/bpftool /usr/local/bin/bpftool || \
    (wget -O /usr/local/bin/bpftool https://github.com/libbpf/bpftool/releases/download/v7.3.0/bpftool && \
     chmod +x /usr/local/bin/bpftool)

WORKDIR /build

# Copy source code (excluding any pre-built artifacts)
COPY *.c *.h ./
COPY network_faults/ ./network_faults/
COPY tests/ ./tests/
COPY Makefile ./
COPY .gitmodules ./
COPY libbpf/ ./libbpf/

# Build libbpf for the target architecture and install everything
RUN cd libbpf/src && make clean && make && make install

# Remove generated artifacts before creating the vmlinux.h used by this build.
RUN make clean

# Generate vmlinux.h from kernel BTF or use Linux's architecture-neutral BPF skeleton header
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h 2>/dev/null || \
    wget -O vmlinux.h https://raw.githubusercontent.com/torvalds/linux/master/tools/perf/util/bpf_skel/vmlinux/vmlinux.h

# Build eBPF objects and skeletons first
RUN make kprobe.bpf.o kretprobe.bpf.o kprobe_packet_loss_sendto.bpf.o kprobe_packet_loss_recvfrom.bpf.o kprobe_latent_sector_error.bpf.o && \
    make kprobe.skel.h kretprobe.skel.h kprobe_packet_loss_sendto.skel.h kprobe_packet_loss_recvfrom.skel.h kprobe_latent_sector_error.skel.h && \
    ldconfig && \
    make khaos-dynamic

# Runtime stage
FROM ubuntu:24.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libelf1 \
    zlib1g \
    libzstd1 \
    ca-certificates \
    curl \
    jq \
    linux-tools-common \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /khaos

# Copy built artifacts from builder stage
COPY --from=builder /build/khaos ./khaos
COPY --from=builder /build/*.bpf.o ./
COPY --from=builder /build/*.skel.h ./
COPY --from=builder /build/libbpf/src/libbpf.so* /usr/lib/
COPY docker-entrypoint.sh ./docker-entrypoint.sh
RUN chmod +x ./docker-entrypoint.sh

# Ensure library path is set
ENV LD_LIBRARY_PATH=/usr/lib

ENTRYPOINT ["./docker-entrypoint.sh"]
