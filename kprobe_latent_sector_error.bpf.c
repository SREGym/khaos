#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "pid_filter.bpf.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
} pid_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} err_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} error_rate_map SEC(".maps");

SEC("kprobe/sys_read")
int kprobe_read_handler(struct pt_regs *ctx) {
    int pid = khaos_current_pid();
    unsigned char *pid_exists;
    int key = 0;
    int *err;

    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists)
        return 0;

    unsigned int random_val = bpf_get_prandom_u32();
    int *rate = bpf_map_lookup_elem(&error_rate_map, &key);
    int effective_rate = rate ? *rate : 50;

    if ((random_val % 100U) < (unsigned int)effective_rate) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (err) {
            bpf_printk("[khaos_lse] PID %d failing read err=%d rate=%d%%",
                       pid, *err, effective_rate);
            bpf_override_return(ctx, *err);
            return 0;
        }
    }

    return 0;
}

SEC("kprobe/sys_pread64")
int kprobe_pread_handler(struct pt_regs *ctx) {
    int pid = khaos_current_pid();
    unsigned char *pid_exists;
    int key = 0;
    int *err;

    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists)
        return 0;

    unsigned int random_val = bpf_get_prandom_u32();
    int *rate = bpf_map_lookup_elem(&error_rate_map, &key);
    int effective_rate = rate ? *rate : 50;

    if ((random_val % 100U) < (unsigned int)effective_rate) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (err) {
            bpf_printk("[khaos_lse] PID %d failing pread64 err=%d rate=%d%%",
                       pid, *err, effective_rate);
            bpf_override_return(ctx, *err);
            return 0;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
