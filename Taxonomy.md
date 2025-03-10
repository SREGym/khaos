## **Identify Failure Categories**

Failures are inspired by this [paper](https://ieeexplore.ieee.org/document/8023108).

Ideally, we will have a yaml based interface similar to [ChaosMesh](https://chaos-mesh.org/). There's an example at the end that shows the kind of interface we should use.

### **Disk Failures (I/O & Storage)**

| Failure Mode      | Impact                           | Relevant Syscalls                                   |
| ----------------- | -------------------------------- | --------------------------------------------------- |
| Disk Unavailable  | Reads/Writes fail                | `open()`, `read()`, `write()`, `fsync()`, `ioctl()` |
| Slow Disk         | Latency increases                | `fsync()`, `sync_file_range()`                      |
| Corrupted Data    | Mismatched reads/writes          | Hook `read()` and inject bit flips                  |
| Filesystem Errors | Filesystem unmounts unexpectedly | `mount()`, `statfs()`, `unlink()`                   |
| I/O Errors (bad sectors)  | Partial read/write failures with `EIO` errors | `pread()`, `pwrite()`, `fsync()`, `ioctl()` |
| Disk Partition Corruption | Certain disk partitions become unreadable     | `mount()`, `umount()`, `fdisk()`            |
| RAID Degraded Mode        | Data redundancy is lost, performance drops    | `ioctl()`, `read()`, `write()`              |
| SSD Wear-Leveling Issues  | Increased latency, inconsistent read speeds   | `sync_file_range()`, `fsync()`              |
| Disk Read-Only Mode       | Writes are blocked, only reads allowed        | `write()`, `truncate()`, `rename()`         |


### **Memory Failures (RAM & Cache)**

| Failure Mode         | Impact                   | Relevant Syscalls            |
| -------------------- | ------------------------ | ---------------------------- |
| Bit Flip Corruptions | Random memory corruption | Modify `mmap()` pages        |
| Out of Memory (OOM)  | Process killed           | `brk()`, `mmap()`, `mlock()` |
| Memory Leaks         | Progressive slowdowns    | `malloc()`, `free()`         |
|Heap Fragmentation|Memory allocations become slow over time|`malloc()`, `free()`, `mmap()`|
|Stack Corruption|Causes random segmentation faults|`mprotect()`, `setrlimit(RLIMIT_STACK)`|
|Swap Storm (Thrashing)|System constantly swaps memory to disk, causing slowdowns|`swapoff()`, `swapon()`, `madvise()`|
|Page Table Corruption|Random invalid memory accesses|`getpagesize()`, `mprotect()`, `mlock()`|

### **CPU Failures (Compute & Scheduling)**

|Failure Mode|Impact|Relevant Syscalls|
|---|---|---|
|High CPU Load|Starvation|`sched_yield()`, `getrusage()`|
|Random Crashes|Process terminates|`kill()`, `segfault()`|
|Throttling|Execution slows|Hook `nanosleep()` to inject delays|
|Core Starvation|One or more CPU cores become unavailable|`sched_setaffinity()`, `sched_getaffinity()`|
|Pipeline Stalls|Execution pauses randomly for some instructions|`perf_event_open()`|
|Clock Drift|The system clock shifts unexpectedly|`clock_gettime()`, `gettimeofday()`|
|Instruction Set Corruption|Some CPU instructions cause crashes|`execve()`, `ptrace()`|

### **Network Failures (Connectivity)**

|Failure Mode|Impact|Relevant Syscalls|
|---|---|---|
|Packet Loss|Some connections drop|`sendto()`, `recvfrom()`|
|Latency Spikes|Increased response times|`connect()`, `setsockopt(SO_RCVBUF)`|
|Total Disconnection|No network access|`socket()`, `bind()`, `accept()`|
|DNS Resolution Failure|Hostnames fail to resolve, affecting external connectivity|`getaddrinfo()`, `res_query()`|
|Port Blockage|Certain ports are inaccessible due to firewall rules|`bind()`, `listen()`, `connect()`|
|Intermittent Network Failures|Network connection cuts out randomly|`sendto()`, `recvfrom()`|
|Bandwidth Throttling|Slow data transfer, high RTT|`setsockopt(SO_RCVBUF, SO_SNDBUF)`, `tc qdisc`|
|Packet Duplication|Some packets are duplicated randomly|`sendto()`, `recvfrom()`|

### **Power & Hardware Failures**

| Failure Mode            | Impact                  | Relevant Syscalls        |
| ----------------------- | ----------------------- | ------------------------ |
| Power Loss              | Entire machine shutdown | `reboot()`, `poweroff()` |
| CPU Voltage Instability | Unpredictable slowdowns | `perf_event_open()`      |
|Temperature Overload|System slows down due to thermal throttling|`perf_event_open()`, `sched_yield()`|
|Battery Backup Failure|Unexpected shutdowns due to battery faults|`reboot()`, `poweroff()`|
|Fan Failure|System components overheat, leading to instability|`ioctl()` (fan speed control)|
|Memory Bus Errors|Causes random memory corruption|`mmap()`, `memcpy()`|
|Peripheral Bus Failure|USB, PCI devices disappear|`ioctl()`, `read()`, `write()`|


### **Kernel & OS-Level Failures**

|Failure Mode|Impact|Relevant Syscalls|
|---|---|---|
|Kernel Panic Simulation|System halts with a forced panic|`sysctl()` (trigger `kernel.panic`)|
|Process Table Exhaustion|No new processes can be spawned|`fork()`, `execve()`, `clone()`|
|File Descriptor Leak|No new files or sockets can be opened|`open()`, `socket()`, `dup()`|
|Syscall Hook Failure|Some system calls return unexpected values|Modify `bpf_trace_printk()` logs|
|Deadlock Simulation|Two or more processes get stuck waiting for each other|`flock()`, `pthread_mutex_lock()`|

---

### **Virtualization & Container Failures**

|Failure Mode|Impact|Relevant Syscalls|
|---|---|---|
|Container Namespace Isolation Failure|Containers see each other’s processes|`setns()`, `unshare()`|
|Cgroup Throttling|CPU/memory limits reduce process performance|`prlimit()`, `setrlimit()`|
|Container Crash Loop|Container keeps restarting unexpectedly|`kill()`, `prctl(PR_SET_PDEATHSIG)`|
|Filesystem OverlayFS Corruption|Layered filesystems break, causing read-only issues|`mount()`, `umount()`, `unlink()`|

---

### **Security & Access Failures**

|Failure Mode|Impact|Relevant Syscalls|
|---|---|---|
|Permission Errors|Processes suddenly lose access to files|`chmod()`, `chown()`, `access()`|
|SELinux/AppArmor Denial|Security policies block system calls|`execve()`, `ptrace()`, `mmap()`|
|Cryptographic Failure|TLS handshakes fail due to missing entropy|`getrandom()`, `read(/dev/random)`|
|Process Injection Failure|Attempts to inject code into processes fail|`ptrace()`, `mmap()`|
|User Authentication Failure|System doesn’t accept valid passwords|`pam_authenticate()`, `getpwnam()`|

---
### **Simulating GPU Faults for Khaos**

The Llama Herd [paper](https://arxiv.org/abs/2407.21783) mentions over **400 GPU errors**, showing how failures impact model training.

---

### **Common GPU Failures in LLM Training & HPC**

Based on failures observed in large-scale GPU clusters (e.g., NVIDIA DGX, A100/H100 clusters), we need to revist the literature:

| **Failure Type**                   | **Impact**                                      | **Cause**                           |     |
| ---------------------------------- | ----------------------------------------------- | ----------------------------------- | --- |
| **Memory ECC Errors**              | Corrupts tensor data, causing model instability | VRAM bit flips, hardware defects    |     |
| **CUDA Out-of-Memory (OOM)**       | Training job crashes                            | Insufficient VRAM, fragmentation    |     |
| **PCIe Bus Errors**                | GPU disconnects mid-job                         | Bad PCIe lanes, cable issues        |     |
| **Thermal Throttling**             | Training slows down drastically                 | Fan failure, overheating            |     |
| **Power Limit Throttling**         | GPU clocks drop, affecting training speed       | PSU degradation, overdraw           |     |
| **Tensor Core Failure**            | Loss of precision in matrix multiplications     | Silicon degradation                 |     |
| **Driver Crash (NVIDIA/Xorg)**     | Entire GPU resets, killing training             | Driver/kernel bugs                  |     |
| **NVLink Errors**                  | Multi-GPU training stalls                       | NVLink degradation, firmware issues |     |
| **Warp Divergence Bugs**           | Random deadlocks in CUDA kernels                | Compiler or hardware bug            |     |
| **FP32/FP16 Precision Corruption** | Model loss explodes due to precision errors     | Tensor core instability             |     |
| **Fan Failure**                    | GPU overheats, eventually shuts down            | Physical failure                    |     |


## **Mapping GPU Failures to Syscalls & APIs**

Since most GPU interactions happen via **ioctl() calls to device drivers**, we can intercept these at the **eBPF level**.

|**Failure Mode**|**Relevant Syscalls/APIs**|**Fault Injection Method**|
|---|---|---|
|VRAM ECC Errors|`cudaMemcpy()`, `mmap()`, `read()`|Bit flips in GPU memory|
|CUDA OOM|`cudaMalloc()`, `cudaMemcpy()`|Inject `ENOMEM` on memory allocation|
|PCIe Bus Errors|`ioctl(/dev/nvidia0)`, `read()`|Block `ioctl()` for PCIe device|
|Thermal Throttling|`nvidia-smi`, `sysfs`|Modify `/sys/class/hwmon/temp` values|
|Power Limit Throttling|`ioctl()`, `perf_event_open()`|Block GPU frequency scaling|
|Tensor Core Failure|`cudaLaunchKernel()`|Randomly alter FP16/FP32 results|
|Driver Crash (Xorg Reset)|`kill(Xorg)`, `modprobe -r nvidia`|Force unload NVIDIA module|
|NVLink Errors|`nvidia-smi topo --query-gpu`|Block NVLink communication|
|Warp Divergence Bugs|`cudaLaunchKernel()`|Inject `sleep()` in execution|
|Fan Failure|`ioctl(/dev/nvidia0)`, `pwmconfig`|Block fan control syscalls|

---

## **Implementing GPU Fault Injection in Khaos**

### **eBPF Hook on `ioctl()`**

Most GPU interactions happen through **`ioctl()` calls to `/dev/nvidia0`** (or AMD’s `/dev/dri/card0`). We can hook `ioctl()` via eBPF:

```c
SEC("kprobe/ioctl")
int bpf_prog(struct pt_regs *ctx) {
    int fd = PT_REGS_PARM1(ctx);
    int request = PT_REGS_PARM2(ctx);

    // Check if this is a GPU device
    char filename[64];
    bpf_get_fd_path(fd, filename, sizeof(filename));
    if (strstr(filename, "/dev/nvidia") || strstr(filename, "/dev/dri/card0")) {
        if (request == NVIDIA_IOCTL_MEM_ALLOC) {
            return -ENOMEM;  // Simulate OOM error
        }
        if (request == NVIDIA_IOCTL_POWER_LIMIT) {
            return -EPERM;  // Block power scaling
        }
    }
    return 0;
}
```

### **Using `sysfs` for Throttling Faults**

Many GPU properties (temperature, power limits, clock speeds) can be manipulated via **`/sys/class/hwmon/`**.

To **inject fake overheating**:

```sh
echo 105 > /sys/class/hwmon/hwmon0/temp1_input  # Fake 105°C
```

To **reduce GPU frequency artificially**:

```sh
echo 300 > /sys/class/hwmon/hwmon0/freq  # Reduce to 300MHz
```

### **Option 3: Killing the GPU Driver**

To simulate **GPU resets**, force an **NVIDIA driver crash**:

```sh
modprobe -r nvidia  # Unloads the driver
```

Or block the driver from loading:

```sh
echo "blacklist nvidia" > /etc/modprobe.d/blacklist-nvidia.conf
```

### *CUDA Hooking for Fault Injection**

For CUDA-specific failures, **intercept CUDA API calls** using `LD_PRELOAD`:

1. **Create a fake CUDA malloc failure:**

```c
void *cudaMalloc(void **devPtr, size_t size) {
    return cudaErrorMemoryAllocation;  // Always fail malloc
}
```

2. **Inject fake bit flips in tensor data:**

```c
cudaMemcpy(fake_tensor, real_tensor, size, cudaMemcpyDeviceToDevice);
fake_tensor[0] ^= 0x1;  // Corrupt one bit
```

Compile and use:

```sh
gcc -shared -fPIC -o fakecuda.so fakecuda.c -ldl
LD_PRELOAD=./fakecuda.so python train_llm.py
```

---

## **Fault Injection Scenarios for LLM Training**

### **Example YAML for Khaos GPU Fault Injection**

We don't have this yaml based interface yet, but I would like this project to eventually utilize a yaml based interface similar to chaos-mesh to support easy experimentation.

```yaml
failures:
  - type: "gpu"
    mode: "memory_corruption"
    target: "cudaMemcpy"
    probability: 0.1  # 10% chance per call
    inject_bitflip: true

  - type: "gpu"
    mode: "thermal_throttling"
    sysfs_path: "/sys/class/hwmon/hwmon0/temp1_input"
    set_value: 105000  # Fake 105°C

  - type: "gpu"
    mode: "pci_disconnect"
    syscalls: ["ioctl"]
    block: true
    device: "/dev/nvidia0"

  - type: "gpu"
    mode: "cuda_oom"
    target: "cudaMalloc"
    return_error: "cudaErrorMemoryAllocation"
```

