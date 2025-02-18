### **Building**
To build both static libbpf.a and shared libbpf.so:
```bash
$ pushd libbpf/src
$ make
```

Then compile the BPF injector here:
```bash
$ popd
$ make
```

You will get a `err_inject` binary file.

---

### **Usage**
```sh
sudo ./err_inject <syscall_name> <error_code> <pid> [<pid> ...]
```

#### **Example: Block `write()` System Call for Process 1234**
```sh
sudo ./err_inject __arm64_sys_write 5 1234
```
- Hooks into `write()` (`__arm64_sys_write`).
- Injects error `-5` (`EIO`, Input/Output error).
- Affects process **1234**—any `write()` calls from this process will fail.

#### **Example: Prevent a Process from Forking**
```sh
sudo ./err_inject __arm64_sys_fork 1 5678
```
- Hooks into `fork()` (`__arm64_sys_fork`).
- Injects error `-1` (`EPERM`, Operation Not Permitted).
- Prevents process **5678** from creating child processes.

---

Here are the **system configuration steps** you had to modify in order to run your program. You can add these to your README under a **"System Requirements & Setup"** section.

---

## **System Requirements & Setup**
Before running `err_inject`, ensure your system is properly configured to allow BPF programs to execute.

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
Most BPF operations require **root privileges**. Always run `err_inject` with `sudo`:
```sh
sudo ./err_inject <syscall_name> <error_code> <pid>
```

---
