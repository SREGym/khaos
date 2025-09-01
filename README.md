### 🔧 Build Dependencies

To compile `khaos` and its eBPF components, make sure your system has the following dependencies:

```bash
sudo apt update && sudo apt install -y \
    clang \
    llvm \
    gcc \
    make \
    libelf-dev \
    zlib1g-dev \
    linux-headers-$(uname -r) \
    build-essential \
    pkg-config
```

Next, make sure the `libbpf` submodule is initialized:

```bash
git submodule update --init --recursive
```

Build and install `libbpf`:

```bash
cd libbpf/src
sudo make install
```

Setup headers (amd64/x86):
```bash
sudo apt install linux-headers-`uname -r`
```

Create a symlink for headers:
```bash
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
```

Setup headers (arm):
Use the `setup_arm64_headers.sh` script. 

You can then compile the full project:

```bash
cd ../..  # return to root if in libbpf
make # or make ARCH=arm for ARM builds
```

### **Usage**

```bash
sudo ./khaos <fault_type> <pid>
```
You may also recover a fault:
```bash
sudo ./khaos --recover <fault_type>
```

🐳 Docker Image (Quick Start)

If you prefer to run Khaos inside a container, we've provided a Docker image setup.
Build the Docker Image Locally
```bash
docker build -t jacksonarthurclark/khaos-arm:latest .
```
Make sure you have compiled the Khaos binary and required .bpf.o and .skel.h files in the build context.
Run the Container

To inject a fault:
```bash
sudo docker run --rm -it \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /proc:/host/proc:ro \
  jacksonarthurclark/khaos-arm:latest <fault_type> <pid>
```
To recover:
```bash
sudo docker run --rm -it \
  --privileged \
  --pid=host \
  --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /proc:/host/proc:ro \
  jacksonarthurclark/khaos-arm:latest --recover <fault_type>
```
    ⚠️ You must run the container with --privileged and proper mounts to enable eBPF functionality.

### **Testing**
```bash
make tests
```
You'll find a mixture of Python and C programs that are used for testing the various faults.

#### **Example: Block `read()` System Call for Process 1234**
```sh
sudo ./khaos read_error 1234
```
- Hooks into `read()` (`__arm64_sys_write`).
- Injects error `-5` (`EIO`, Input/Output error).
- Affects process **1234**—any `read()` calls from this process will fail.

You can run the demo program `python3 read_demo.py` and test with it's PID.

---

## **System Requirements & Setup**
Before running `khaos`, ensure your system is properly configured to allow BPF programs to execute.

### **1. Enable BPF System Calls**
Verify that your kernel supports BPF by checking:
```sh
grep CONFIG_BPF_SYSCALL /boot/config-$(uname -r)
```
Expected output:
```sh
CONFIG_BPF_SYSCALL=y
```
If this is not set, you may need to recompile your kernel with BPF support.

### **2. Enable DebugFS & Tracing**
BPF relies on **DebugFS** and **Tracing** for attaching probes. Ensure DebugFS is mounted:
```sh
sudo mount -t debugfs none /sys/kernel/debug
```
Check for available tracing functions:
```sh
ls /sys/kernel/debug/tracing/
```

### **3. Adjust Memory Lock Limits**
BPF programs require a sufficient **locked memory limit**. Increase it:
```sh
ulimit -l unlimited
```
To make this persistent, add the following line to `/etc/security/limits.conf`:
```
* soft memlock unlimited
* hard memlock unlimited
```

### **4. Allow Unprivileged BPF Execution**
By default, Linux may **restrict unprivileged BPF usage**. Check the current setting:
```sh
cat /proc/sys/kernel/unprivileged_bpf_disabled
```
If the output is `1` or `2`, allow unprivileged BPF by running:
```sh
sudo sysctl -w kernel.unprivileged_bpf_disabled=0
```
To make this persistent:
```sh
echo "kernel.unprivileged_bpf_disabled=0" | sudo tee -a /etc/sysctl.conf
sudo sysctl --system
```

### **5. Ensure Required Kernel Headers Are Installed**
Your system needs kernel headers that match your running kernel. Install them with:
```sh
sudo apt install linux-headers-$(uname -r)
```
If you're on **ARM64**, make sure the correct headers are linked:
```sh
sudo ln -s /usr/src/linux-headers-$(uname -r)/arch/arm64/include/generated/uapi/asm /usr/include/asm
```

### **6. Cloning And Building Khaos On Your Machine**

Prompt the following command into your shell to clone the repository and its submodules:

```sh
git clone https://github.com/xlab-uiuc/khaos.git
cd khaos
git submodule update --init --recursive
```

To build both static libbpf.a and shared libbpf.so:
```bash
pushd libbpf/src
sudo make install
```

Then compile khaos:
Problems with aarch64 and arm64 architecture? Try **the guide** below then ```make ARCH=arm``` command again

```bash
popd
make #ARCH=arm for arm compilation, default is x86
```
You will get a `khaos` binary file.

### For Windows User: WSL2 Disclaimer
WSL2 does not support eBPF by default, you will have to [compile a custom kernel](https://dev.to/wiresurfer/unleash-the-forbidden-enabling-ebpfxdp-for-kernel-tinkering-on-wsl2-43fj) if you intend to continue using it. 

### For Ubuntu User: Disable AppArmor
If you're running Ubuntu like I am, you might have to [disable AppArmor](https://documentation.ubuntu.com/server/how-to/security/apparmor/index.html) for the program to work.


### For ARM-64: Kernel Headers And Symlinks Problems
If you're into problems using ```make ARCH=arm``` with one of the following errors:

```bash

In file included from khaos.bpf.c:1:
In file included from /usr/include/linux/bpf.h:11:
In file included from /usr/include/linux/types.h:5:
In file included from /usr/include/asm/types.h:1:
In file included from /usr/include/asm-generic/types.h:7:
/usr/include/asm-generic/int-ll64.h:12:10: fatal error: 'asm/bitsperlong.h' file not found
   12 | #include <asm/bitsperlong.h>
      |          ^~~~~~~~~~~~~~~~~~~

1 error generated.
make: *** [Makefile:24: khaos.bpf.o] Error 1 
```

You might want to run the sh script below to resolve the problem:

```bash

sudo apt update
sudo apt install linux-headers-$(uname -r) libc6-dev build-essential
chmod +x setup_arm64_headers.sh
./setup_arm64_headers.sh
```

### **7. Run the Program as Root**
Most BPF operations require **root privileges**. Always run `khaos` with `sudo`:
```sh
sudo ./khaos <syscall_name> <error_code> <pid>
```
---

## How to add a new fault
The first step to adding a new fault is to identify the syscall we want to inject a fault on. You can find relevant syscalls by using the `strace` tool to see the syscalls used by a particular program:

Here’s a polished and expanded version of your `README.md` section on adding new faults, including examples and detailed steps:

---

## 🔧 How to Add a New Fault

Adding a new fault to **Khaos** involves identifying the target syscall, choosing the appropriate error code, and registering the fault in the Khaos fault registry. Here's a step-by-step guide:

---

### 1️Identify the Target Syscall

To determine which syscall a program is using (and might fail on), use [`strace`](https://man7.org/linux/man-pages/man1/strace.1.html) to trace its system calls.

#### Example: Using `strace`

If you have a Python script `read_demo.py` that reads a file:

```bash
strace -e trace=read,open,write -p <PID>
```

Or, to launch the program with tracing from the start:

```bash
strace -e trace=all python3 read_demo.py
```

You will see output like:

```
openat(AT_FDCWD, "test_file.txt", O_RDONLY) = 3
read(3, "Hello world\n", 1024)             = 12
```

This tells you the program uses the `openat` and `read` syscalls — candidates for fault injection.

---

### Look Up Syscall Error Codes

Once you identify the syscall, consult its manual page to learn what error codes it may return.

Run:

```bash
man 2 read
```

Look for the `ERRORS` section. Example for `read(2)`:

```
EAGAIN      The file descriptor refers to a file other than a socket and has been marked nonblocking...
EIO         A low-level I/O error occurred while reading from the disk.
EBADF       fd is not a valid file descriptor or is not open for reading.
```

Pick an error code that meaningfully simulates a hardware-related fault. For example:

* `EIO (-5)` simulates a disk read failure
* `ENOSPC (-28)` simulates a full disk
* `ENOMEM (-12)` simulates memory exhaustion

---

### Register the New Fault

Open `khaos.c` and locate the `fault_registry[]` struct:

```c
static struct fault_entry fault_registry[] = {
    {"read_error", "read", -5},       // Injects EIO
    {"write_error", "write", -28},    // Injects ENOSPC
    ...
};
```

Add a new line for your fault:

```c
{"open_error", "openat", -13},   // Injects EACCES
```

Make sure:

* The name is unique (e.g., `open_error`)
* The syscall name matches exactly what’s used in the kernel (`strace` output will guide this)
* The error code is **negative**
