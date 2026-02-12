#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

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
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;
    int key = 0;
    int *err;

    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists)
        return 0;

#if defined(__TARGET_ARCH_x86)
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
#elif defined(__TARGET_ARCH_arm64)
    int fd;
    __u64 count;
    bpf_probe_read_kernel(&fd, sizeof(fd), (void *)&ctx->regs[0]);
    bpf_probe_read_kernel(&count, sizeof(count), (void *)&ctx->regs[2]);
#else
    // Fallback for other architectures
    int fd = 0;
    __u64 count = 0;
#endif

    unsigned int random_val = bpf_get_prandom_u32();
    int *rate = bpf_map_lookup_elem(&error_rate_map, &key);
    int effective_rate = rate ? *rate : 50;

    if ((random_val % 100U) < (unsigned int)effective_rate) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (err) {
            bpf_printk("[khaos_lse] PID %d failing read (fd=%d, count=%lu) err=%d rate=%d%%",
                       pid, fd, count, *err, effective_rate);
            bpf_override_return(ctx, *err);
            return 0;
        }
    }

    return 0;
}

SEC("kprobe/sys_pread64")
int kprobe_pread_handler(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;
    int key = 0;
    int *err;

    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists)
        return 0;

#if defined(__TARGET_ARCH_x86)
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    __u64 offset = (__u64)PT_REGS_PARM4(ctx);
#elif defined(__TARGET_ARCH_arm64)
    int fd;
    __u64 count;
    __u64 offset;
    bpf_probe_read_kernel(&fd, sizeof(fd), (void *)&ctx->regs[0]);
    bpf_probe_read_kernel(&count, sizeof(count), (void *)&ctx->regs[2]);
    bpf_probe_read_kernel(&offset, sizeof(offset), (void *)&ctx->regs[3]);
#else
    // Fallback for other architectures
    int fd = 0;
    __u64 count = 0;
    __u64 offset = 0;
#endif

    unsigned int random_val = bpf_get_prandom_u32();
    int *rate = bpf_map_lookup_elem(&error_rate_map, &key);
    int effective_rate = rate ? *rate : 50;

    if ((random_val % 100U) < (unsigned int)effective_rate) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (err) {
            bpf_printk("[khaos_lse] PID %d failing pread64 (fd=%d, count=%lu, off=%lld) err=%d rate=%d%%",
                       pid, fd, count, offset, *err, effective_rate);
            bpf_override_return(ctx, *err);
            return 0;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
