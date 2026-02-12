# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Khaos is an eBPF-based fault injection tool for Linux systems that simulates hardware failures by intercepting system calls at the kernel level. It allows injecting failures like disk I/O errors, network packet loss, memory issues, and more to test application resilience.

## Architecture

### Core Components

- **khaos.c** - Main C program that manages fault injection campaigns
- **eBPF Programs** - Kernel-space programs that hook system calls:
  - `kprobe.bpf.c` - Generic kprobe for syscall interception
  - `kretprobe.bpf.c` - Return probe for syscall exit points
  - `kprobe_path_read_error.bpf.c` - Path-based read error injection
  - `kprobe_block_read_error.bpf.c` - Block-level read error injection
  - `network_faults/` - Network-specific fault injection programs
- **Fault Registry** - Table in `khaos.c` mapping fault names to syscalls and error codes
- **libbpf** - Git submodule providing eBPF loading and management

### Build System

- Uses a sophisticated Makefile with architecture auto-detection (x86/arm64)
- Generates `vmlinux.h` from kernel BTF for type definitions
- Compiles eBPF programs to `.bpf.o` objects, then generates `.skel.h` skeleton headers
- Links against static libbpf for portability

## Common Commands

### Build Commands
```bash
# Full build (auto-detects architecture)
make

# Clean build artifacts
make clean

# Build for ARM64 specifically
make ARCH=arm

# Build test programs
make tests
```

### Prerequisites
```bash
# Install dependencies
sudo apt update && sudo apt install -y clang llvm gcc make pkg-config build-essential libelf-dev zlib1g-dev libzstd-dev libssl-dev linux-headers-$(uname -r) linux-tools-$(uname -r)

# Initialize libbpf submodule
git submodule update --init --recursive

# Build and install libbpf
cd libbpf/src && sudo make install && cd ../..
```

### Usage Commands
```bash
# Inject a fault
sudo ./khaos <fault_type> <pid>

# Recover from a fault
sudo ./khaos --recover <fault_type>

# Example: Block read() syscalls for PID 1234
sudo ./khaos read_error 1234
```

### Testing
```bash
# Run all tests
make tests

# Test programs are in tests/ directory:
# - tests/test_programs/ - Simple fault testing programs
# - tests/network_tests/ - Network-specific tests
# - tests/memory_tests/ - Memory-related tests
```

## Code Architecture Details

### Fault Registration System
Faults are registered in the `fault_registry[]` array in `khaos.c`. Each entry maps:
- Fault name (e.g., "read_error")
- Target syscall (e.g., "read")
- Error code to inject (e.g., -5 for EIO)

### eBPF Program Structure
eBPF programs use several map types:
- `BPF_MAP_TYPE_HASH` - For PID tracking and file descriptor mapping
- `BPF_MAP_TYPE_ARRAY` - For configuration and pattern storage
- Pattern matching system for path-based fault injection

### Error Code Injection
The system injects negative error codes corresponding to standard errno values:
- `-5` (EIO) - I/O errors
- `-28` (ENOSPC) - No space left on device
- `-12` (ENOMEM) - Out of memory

## System Requirements

- Linux kernel with eBPF support (CONFIG_BPF_SYSCALL=y)
- Root privileges for eBPF program loading
- DebugFS mounted at `/sys/kernel/debug`
- Adequate memory lock limits (`ulimit -l unlimited`)
- Kernel headers matching running kernel version

## Development Notes

- Use `strace` to identify target syscalls for new fault types
- Consult syscall man pages for appropriate error codes
- eBPF programs are compiled with clang targeting BPF architecture
- Static linking with libbpf ensures portability across systems
- Architecture-specific compilation handles x86_64 and ARM64/AArch64