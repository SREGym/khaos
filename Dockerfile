FROM ubuntu:24.04

# Runtime deps + tools
RUN apt-get update && apt-get install -y \
      libelf1 zlib1g ca-certificates curl jq \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /khaos

# Your prebuilt artifacts
COPY ./khaos .
COPY ./kprobe.bpf.o .
COPY ./kretprobe.bpf.o .
COPY ./kprobe.skel.h .
COPY ./kretprobe.skel.h .
COPY ./libbpf/src/libbpf.so.1 /usr/lib/

ENV LD_LIBRARY_PATH=/usr/lib

ENTRYPOINT ["./khaos"]

