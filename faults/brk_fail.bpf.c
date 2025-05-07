#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

#ifdef __aarch64__
#define BRK_SYSCALL "kprobe/__arm64_sys_brk"
#else
#define BRK_SYSCALL "kprobe/__x64_sys_brk"
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
} pid_map SEC(".maps");

SEC(BRK_SYSCALL)
int brk_fail(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (!bpf_map_lookup_elem(&pid_map, &pid))
        return 0;

    return -12; // ENOMEM
}

char LICENSE[] SEC("license") = "GPL";
