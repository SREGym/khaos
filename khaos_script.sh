#!/bin/sh

apt-get update

apt install git gcc libelf-dev libbpf-dev libzstd-dev pkg-config clang gcc-multilib linux-tools-$(uname -r) llvm build-essential

# Assuming that BPF Syscalls are already supported, this script cannot change that

echo "kernel.unprivileged_bpf_disabled=0" | sudo tee -a /etc/sysctl.conf
sudo sysctl --system

# Building khaos
git clone https://github.com/xlab-uiuc/khaos.git
cd khaos
git submodule update --init --recursive

pushd libbpf/src
sudo make install
popd
make

# TODO: Disabling Apparmor (Only necessary for Ubuntu)

