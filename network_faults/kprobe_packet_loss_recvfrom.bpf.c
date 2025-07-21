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

// Kprobe handler: intercept recvfrom syscall for packet loss simulation
SEC("kprobe/sys_recvfrom")
int kprobe_recvfrom_handler(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;
    int key = 0;
    int *err;
    
    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0;
    }
    
    // Get recvfrom parameters
    int sockfd = (int)PT_REGS_PARM1(ctx);
    unsigned long len = (unsigned long)PT_REGS_PARM3(ctx);
    
    // Simulate packet loss: randomly drop 30% of packets
    // Use BPF's random number generator for proper randomization
    unsigned int random_val = bpf_get_prandom_u32();
    
    // 30% chance of dropping (random_val % 10 < 3)
    if ((random_val % 10U) < 3U) {
        err = bpf_map_lookup_elem(&err_map, &key);
        if (err) {
            bpf_printk("[PACKET_LOSS_RECVFROM] PID %d randomly dropping packet (sockfd=%d, len=%lu) with error %d", 
                      pid, sockfd, len, *err);
            bpf_override_return(ctx, *err);
            return 0;
        }
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL"; 