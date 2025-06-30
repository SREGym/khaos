FROM ubuntu:24.04

RUN apt update && apt install -y \
    libelf1 zlib1g \
    && apt clean

WORKDIR /khaos

COPY ./khaos .
COPY ./kprobe.bpf.o .
COPY ./kretprobe.bpf.o .
COPY ./kprobe.skel.h .
COPY ./kretprobe.skel.h .
COPY ./libbpf/src/libbpf.so.1 /usr/lib/

ENV LD_LIBRARY_PATH=/usr/lib

ENTRYPOINT ["./khaos"]
