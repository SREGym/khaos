### **Building**
To build both static libbpf.a and shared libbpf.so:
```bash
pushd libbpf/src
make
```

Then compile khaos:
```bash
popd
make #ARCH=arm for arm compilation, default is x86
```

You will get a `khaos` binary file.

---

### **Usage**
Usage
```bash
sudo ./khaos <fault_type> <pid>
```
You may also recover a fault:
```bash
sudo ./khaos --recover <fault_type>
```


#### **Example: Block `read()` System Call for Process 1234**
```sh
sudo ./khaos read 5 1234
```
- Hooks into `read()` (`__arm64_sys_write`).
- Injects error `-5` (`EIO`, Input/Output error).
- Affects process **1234**—any `read()` calls from this process will fail.

You can run the demo program `python3 read_demo.py` and test with it's PID.

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

### **6. Run the Program as Root**
Most BPF operations require **root privileges**. Always run `khaos` with `sudo`:
```sh
sudo ./khaos <syscall_name> <error_code> <pid>
```

### **7. Disable AppArmor**
If you're running Ubuntu like I am, you might have to [disable AppArmor](https://documentation.ubuntu.com/server/how-to/security/apparmor/index.html) for the program to work.

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
