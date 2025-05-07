#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
} pid_map SEC(".maps");

SEC("kprobe/fsync")
int fsync_error(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;

    if (!bpf_map_lookup_elem(&pid_map, &pid))
        return 0;

    bpf_override_return(ctx, -5); // EIO
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
