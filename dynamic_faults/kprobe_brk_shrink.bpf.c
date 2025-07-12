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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} err_map SEC(".maps");

// Map to track current brk values per process
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);  // PID
    __type(value, unsigned long);  // Current brk address
    __uint(max_entries, 1024);
} brk_tracker SEC(".maps");

// Map to store the user-space brk address from the tracepoint
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);  // PID
    __type(value, unsigned long);  // User-space brk address
    __uint(max_entries, 1024);
} brk_addr_map SEC(".maps");

// Tracepoint struct for sys_enter_brk
struct sys_enter_brk_args {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    unsigned long brk;
};

// Tracepoint handler: store the user-space address in brk_addr_map
SEC("tracepoint/syscalls/sys_enter_brk")
int trace_brk(struct sys_enter_brk_args *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned long addr = ctx->brk;
    bpf_map_update_elem(&brk_addr_map, &pid, &addr, BPF_ANY);
    return 0;
}

// Kprobe handler: use the address from brk_addr_map for blocking
SEC("kprobe/ys_brk")
int kprobe_brk_shrink_handler(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;
    unsigned long *addr_ptr;
    unsigned long *current_brk;
    int key = 0;
    int *err;

    // Look up the user-space address from the tracepoint
    addr_ptr = bpf_map_lookup_elem(&brk_addr_map, &pid);
    if (!addr_ptr) {
        bpf_printk("[KPROBE] PID %d no user-space address found in brk_addr_map", pid);
        return 0;
    }
    unsigned long addr = *addr_ptr;

    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0;
    }

    if (addr == 0) {
        return 0;
    }

    current_brk = bpf_map_lookup_elem(&brk_tracker, &pid);
    if (!current_brk) {
        bpf_printk("[KPROBE] PID %d first brk, storing 0x%lx", pid, addr);
        bpf_map_update_elem(&brk_tracker, &pid, &addr, BPF_ANY);
        return 0;
    }

    bpf_printk("[KPROBE] PID %d current=0x%lx requested=0x%lx", pid, *current_brk, addr);

    if (addr < *current_brk) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (!err || !*err) {
            bpf_printk("[KPROBE] No error code in err_map or error code is 0. Skipping for PID %d.\n", pid);
            return 0;
        }

        if (*err) {
            bpf_printk("[KPROBE] PID %d BLOCKING shrink 0x%lx->0x%lx", pid, *current_brk, addr);
            bpf_override_return(ctx, *err);
        } else {
            bpf_printk("[KPROBE] PID %d ALLOWING shrink 0x%lx->0x%lx", pid, *current_brk, addr);
            bpf_map_update_elem(&brk_tracker, &pid, &addr, BPF_ANY);
        }
    } else {
        bpf_printk("[KPROBE] PID %d ALLOWING expand 0x%lx->0x%lx", pid, *current_brk, addr);
        bpf_map_update_elem(&brk_tracker, &pid, &addr, BPF_ANY);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 