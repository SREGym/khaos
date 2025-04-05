#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_READ_SIZE 256

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
} pid_map SEC(".maps");

SEC("ksyscall/read")
int read_corruption(struct pt_regs *ctx) {
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    void *user_buf;
    char buf[MAX_READ_SIZE] = {0};
    long err;

    /* Check if PID is being targeted */
    if (!bpf_map_lookup_elem(&pid_map, &pid))
        return 0;

    /* Extract syscall argument (buffer pointer) */
    user_buf = (void *)PT_REGS_PARM2(ctx);

    /* Read from user buffer */
    if (bpf_probe_read_user(buf, MAX_READ_SIZE, user_buf) < 0)
        return 0;

    /* Inject corruption by flipping the first byte */
    buf[0] ^= 0xFF;

    /* Attempt to write back (may fail if permissions are restricted) */
    err = bpf_probe_write_user(user_buf, buf, MAX_READ_SIZE);
    
    if (err == 0) {
        bpf_printk("Corrupted read() data for PID %d\n", pid);
    } else {
        bpf_printk("Failed to write corrupted data for PID %d\n", pid);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
