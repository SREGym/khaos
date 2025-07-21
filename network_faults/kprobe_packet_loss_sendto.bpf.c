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

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} drop_rate_map SEC(".maps");

// Kprobe handler: intercept sendto syscall for packet loss simulation
SEC("kprobe/sys_sendto")
int kprobe_sendto_handler(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;
    int key = 0;
    int *err;
    
    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0;
    }
    
    // Get sendto parameters
    int sockfd = (int)PT_REGS_PARM1(ctx);
    unsigned long len = (unsigned long)PT_REGS_PARM3(ctx);
    
    // Simulate packet loss: randomly drop packets based on drop_rate
    unsigned int random_val = bpf_get_prandom_u32();
    int *drop_rate = bpf_map_lookup_elem(&drop_rate_map, &key);
    int effective_drop = drop_rate ? *drop_rate : 30;
    if ((random_val % 100U) < effective_drop) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (err) {
            bpf_printk("[PACKET_LOSS_SENDTO] PID %d randomly dropping packet (sockfd=%d, len=%lu) with error %d (drop_rate=%d)",
                      pid, sockfd, len, *err, effective_drop);
            bpf_override_return(ctx, *err);
            return 0;
        }
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 