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

// Structure to track file position per file descriptor per process
struct fd_pos_key {
    int pid;
    int fd;
};

struct fd_pos_value {
    __u64 pos;
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

// Map to track file positions for file descriptors
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_pos_key);
    __type(value, struct fd_pos_value);
    __uint(max_entries, 1024);
} fd_pos_map SEC(".maps");

// Helper function to check if a block falls within any configured range
static inline int is_block_in_ranges(loff_t offset, size_t count, int pid) {
    int key = 0;
    int *num_ranges;
    struct block_range *range;

    bpf_printk("[khaos_block_read_error] [PID %d] Checking block ranges for offset=%lld, count=%lu", pid, offset, count);

    // Get the number of configured ranges
    num_ranges = bpf_map_lookup_elem(&num_ranges_map, &key);
    if (!num_ranges || *num_ranges == 0) {
        bpf_printk("[khaos_block_read_error] [PID %d] No ranges configured", pid);
        return 0;  // No ranges configured
    }

    bpf_printk("[khaos_block_read_error] [PID %d] Found %d configured ranges", pid, *num_ranges);

    // Calculate block start and end from offset and count
    // Assuming 512-byte blocks (standard disk block size)
    __u64 block_start = offset / 512;
    __u64 block_end = (offset + count - 1) / 512;

    bpf_printk("[khaos_block_read_error] [PID %d] Read spans blocks %llu-%llu (offset %lld, count %lu)",
               pid, block_start, block_end, offset, count);

    // Check each configured range
    for (int i = 0; i < MAX_BLOCK_RANGES && i < *num_ranges; i++) {
        range = bpf_map_lookup_elem(&block_ranges_map, &i);
        if (!range) {
            bpf_printk("[khaos_block_read_error] [PID %d] Failed to lookup range %d", pid, i);
            continue;
        }

        bpf_printk("[khaos_block_read_error] [PID %d] Checking against target range %d: blocks %llu-%llu",
                   pid, i, range->start, range->end);

        // Check if the read operation overlaps with this range
        // Overlap occurs if: read_start <= range_end AND read_end >= range_start
        int overlaps = (block_start <= range->end && block_end >= range->start);

        bpf_printk("[khaos_block_read_error] [PID %d] Range %d overlap check: read_blocks[%llu-%llu] vs target[%llu-%llu] = %s",
                   pid, i, block_start, block_end, range->start, range->end,
                   overlaps ? "OVERLAP" : "no_overlap");

        if (overlaps) {
            bpf_printk("[khaos_block_read_error] [PID %d] BLOCK RANGE HIT! Read overlaps with target range %d", pid, i);
            return 1;  // Block range overlap detected
        }
    }

    bpf_printk("[khaos_block_read_error] [PID %d] No overlap with any configured ranges - allowing read", pid);
    return 0;  // No overlap with any configured ranges
}

SEC("kprobe/sys_read")
int kprobe_read_handler(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    int key = 0;
    int *err;
    unsigned char *pid_exists;

    bpf_printk("[khaos_block_read_error] Read syscall intercepted from PID: %d", pid);

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        bpf_printk("[khaos_block_read_error] PID %d not in target map - allowing", pid);
        return 0; // PID not targeted
    }

    // Get read parameters from syscall arguments
    // For read(): read(int fd, void *buf, size_t count)
    int fd = (int)PT_REGS_PARM1(ctx);
    size_t count = (size_t)PT_REGS_PARM3(ctx);

    bpf_printk("[khaos_block_read_error] Read syscall: fd=%d, count=%lu from PID %d", fd, count, pid);

    // Try to get current file position for this fd
    struct fd_pos_key pos_key = {.pid = pid, .fd = fd};
    struct fd_pos_value *pos_val = bpf_map_lookup_elem(&fd_pos_map, &pos_key);

    loff_t current_offset = 0;
    if (pos_val) {
        current_offset = pos_val->pos;
        bpf_printk("[khaos_block_read_error] [PID %d] Found tracked position for fd %d: %lld", pid, fd, current_offset);
    } else {
        bpf_printk("[khaos_block_read_error] [PID %d] No tracked position for fd %d, assuming offset 0", pid, fd);
        // Initialize position tracking for this fd
        struct fd_pos_value new_pos = {.pos = 0};
        bpf_map_update_elem(&fd_pos_map, &pos_key, &new_pos, BPF_ANY);
    }

    // Check if the read operation hits any configured block ranges
    if (!is_block_in_ranges(current_offset, count, pid)) {
        bpf_printk("[khaos_block_read_error] [PID %d] Read at offset %lld does not hit configured block ranges - allowing", pid, current_offset);
        return 0; // Allow the syscall to proceed
    }

    // Get the error code to inject
    err = bpf_map_lookup_elem(&err_map, &key);
    if (!err || !*err) {
        bpf_printk("[khaos_block_read_error] [PID %d] No error code configured - allowing", pid);
        return 0;
    }

    bpf_printk("[khaos_block_read_error] [PID %d] INJECTING EIO error %d for read() at offset %lld (block range hit)", pid, *err, current_offset);

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