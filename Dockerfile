FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
      libelf1 zlib1g ca-certificates curl jq \
  && rm -rf /var/lib/apt/lists/*

# Install crictl (v1.30.1 supports CRI v1)
ARG CRICTL_VERSION=1.30.1
RUN set -eux; \
  arch="$(dpkg --print-architecture)"; \
  case "$arch" in amd64) cri_arch=amd64 ;; arm64) cri_arch=arm64 ;; *) echo "unsupported arch: $arch" >&2; exit 1 ;; esac; \
  curl -fsSL -o /tmp/crictl.tgz "https://github.com/kubernetes-sigs/cri-tools/releases/download/v${CRICTL_VERSION}/crictl-v${CRICTL_VERSION}-linux-${cri_arch}.tar.gz"; \
  tar -C /usr/local/bin -xzf /tmp/crictl.tgz crictl; \
  mv /usr/local/bin/crictl /usr/local/bin/crictl.real; \
  printf '%s\n' '#!/bin/sh' \
    'set -eu' \
    'EP="${CRI_ENDPOINT_OVERRIDE:-}"' \
    'if [ -z "$EP" ]; then' \
    '  for p in unix:///run/containerd/containerd.sock unix:///var/run/containerd/containerd.sock unix:///var/run/crio/crio.sock unix:///var/run/cri-dockerd.sock; do' \
    '    s=${p#unix://}; [ -S "$s" ] && EP="$p" && break' \
    '  done' \
    'fi' \
    'exec /usr/local/bin/crictl.real ${CRICTL_CONFIG:+--config "$CRICTL_CONFIG"} ${EP:+--runtime-endpoint "$EP" --image-endpoint "$EP"} "$@"' \
    > /usr/local/bin/crictl; \
  chmod +x /usr/local/bin/crictl; \
  rm -f /tmp/crictl.tgz

WORKDIR /khaos
COPY ./khaos .
COPY ./kprobe.bpf.o .
COPY ./kretprobe.bpf.o .
COPY ./kprobe.skel.h .
COPY ./kretprobe.skel.h .
COPY ./libbpf/src/libbpf.so.1 /usr/lib/
ENV LD_LIBRARY_PATH=/usr/lib
ENTRYPOINT ["./khaos"]
