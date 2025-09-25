#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum number of block ranges that can be stored
#define MAX_BLOCK_RANGES 32

// Structure to represent a block range
struct block_range {
    __u64 start;
    __u64 end;
};

// BPF maps
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

// Map to store block ranges - key is index, value is block_range struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct block_range);
    __uint(max_entries, MAX_BLOCK_RANGES);
} block_ranges_map SEC(".maps");

// Map to store the number of active block ranges
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} num_ranges_map SEC(".maps");

// Helper function to check if a block falls within any configured range
static inline int is_block_in_ranges(loff_t offset, size_t count) {
    int key = 0;
    int *num_ranges;
    struct block_range *range;

    // Get the number of configured ranges
    num_ranges = bpf_map_lookup_elem(&num_ranges_map, &key);
    if (!num_ranges || *num_ranges == 0) {
        return 0;  // No ranges configured
    }

    // Calculate block start and end from offset and count
    // Assuming 512-byte blocks (standard disk block size)
    __u64 block_start = offset / 512;
    __u64 block_end = (offset + count - 1) / 512;

    // Check each configured range
    for (int i = 0; i < MAX_BLOCK_RANGES && i < *num_ranges; i++) {
        range = bpf_map_lookup_elem(&block_ranges_map, &i);
        if (!range) {
            continue;
        }

        // Check if the read operation overlaps with this range
        if (block_start <= range->end && block_end >= range->start) {
            return 1;  // Block range overlap detected
        }
    }

    return 0;  // No overlap with any configured ranges
}

SEC("kprobe/sys_read")
int kprobe_read_handler(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    int key = 0;
    int *err;
    unsigned char *pid_exists;

    bpf_printk("[khaos_block_read_error] Read syscall intercepted from PID: %d\n", pid);

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        bpf_printk("[khaos_block_read_error] PID %d not in target map - allowing\n", pid);
        return 0; // PID not targeted
    }

    // Get read parameters from syscall arguments
    // For read(): read(int fd, void *buf, size_t count)
    int fd = (int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    bpf_printk("[khaos_block_read_error] Read syscall: fd=%d, count=%lu from PID %d\n", fd, count, pid);

    // For regular read, we can't easily determine the file offset from the syscall arguments
    // However, we can still check if any block ranges are configured and inject errors
    // This allows the fault to work with regular read() calls that might hit bad sectors

    int zero_key = 0;
    int *num_ranges = bpf_map_lookup_elem(&num_ranges_map, &zero_key);
    if (!num_ranges || *num_ranges == 0) {
        bpf_printk("[khaos_block_read_error] No block ranges configured - allowing\n");
        return 0;  // No ranges configured, allow syscall
    }

    // Get the error code to inject
    err = bpf_map_lookup_elem(&err_map, &key);
    if (!err || !*err) {
        bpf_printk("[khaos_block_read_error] No error code configured - allowing\n");
        return 0;
    }

    // For read() syscall, inject error regardless of specific block ranges
    // since we can't determine the offset. This matches the behavior of read_error
    // but includes the block range checking framework for future enhancements
    bpf_printk("[khaos_block_read_error] Injecting EIO error %d for read() from PID %d\n", *err, pid);

    // Override the syscall return with the configured error
    bpf_override_return(ctx, *err);

    return 0;
}

SEC("kprobe/sys_pread64")
int kprobe_pread_handler(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    int key = 0;
    int *err;
    unsigned char *pid_exists;

    bpf_printk("[khaos_block_read_error] pread64 syscall from PID: %d\n", pid);

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0; // PID not targeted
    }

    // Get pread64 parameters from syscall arguments
    // For pread64(): pread64(int fd, void *buf, size_t count, off_t offset)
    int fd = (int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);
    loff_t offset = (loff_t)PT_REGS_PARM4(ctx);

    bpf_printk("[khaos_block_read_error] pread64: fd=%d, count=%lu, offset=%lld\n", fd, count, offset);

    // Check if the read operation hits any configured block ranges
    if (!is_block_in_ranges(offset, count)) {
        bpf_printk("[khaos_block_read_error] Read does not hit configured block ranges - allowing\n");
        return 0; // Allow the syscall to proceed
    }

    // Get the error code to inject
    err = bpf_map_lookup_elem(&err_map, &key);
    if (!err || !*err) {
        bpf_printk("[khaos_block_read_error] No error code configured - allowing\n");
        return 0;
    }

    bpf_printk("[khaos_block_read_error] Injecting EIO error %d for PID %d (block range hit)\n", *err, pid);

    // Override the syscall return with the configured error
    bpf_override_return(ctx, *err);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";