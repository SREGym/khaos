#!/bin/sh
set -eu

if [ "$(stat -f -c %t /sys/fs/bpf 2>/dev/null || true)" != "cafe4a11" ]; then
    mount -t bpf bpf /sys/fs/bpf
fi

exec /khaos/khaos "$@"
