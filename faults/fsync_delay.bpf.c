#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
} pid_map SEC(".maps");

SEC("kprobe/fsync")
int fsync_delay(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;

    // Only apply fault if the PID is in our target map
    if (!bpf_map_lookup_elem(&pid_map, &pid))
        return 0;

    // Simulate a delay (not directly possible in BPF, just logging)
    bpf_printk("Injected fsync() delay fault for PID %d\n", pid);

    // Returning an error to simulate a failure (EIO = 5)
    return -5;  // EIO
}

char LICENSE[] SEC("license") = "GPL";
