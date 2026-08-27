#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pid_filter.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} err_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
} pid_map SEC(".maps");

SEC("kprobe/sys_open")  /* replace sys_open with the function you want */
int kprobe_handler(struct pt_regs *ctx)
{
    int pid = khaos_current_pid();
    int key = 0;
    int *err;
    unsigned char *pid_exists;

    bpf_printk("[khaos_kprobe] Syscall from PID: %d\n", pid);

    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        bpf_printk("[khaos_kprobe] PID %d NOT in target map. Skipping.\n", pid);
        return 0; 
    }

    bpf_printk("[khaos_kprobe] PID %d IS in target map. Value: %u\n", pid, *pid_exists);

    err = bpf_map_lookup_elem(&err_map, &key);
    if (!err || !*err) {
        bpf_printk("[khaos_kprobe] No error code or 0. Skipping for PID %d.\n", pid);
        return 0;
    }

    bpf_printk("[khaos_kprobe] Injecting error %d for PID %d\n", *err, pid);
    bpf_override_return(ctx, *err);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
