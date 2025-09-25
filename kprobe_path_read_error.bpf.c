#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Maximum number of file path patterns that can be stored
#define MAX_PATH_PATTERNS 32
// Maximum length for each file path pattern
#define MAX_PATH_LEN 256

// Structure to represent a file path pattern
struct path_pattern {
    char pattern[MAX_PATH_LEN];
    int len;  // Length of the pattern for optimization
};

// Structure to track file descriptors and their paths per process
struct fd_path_key {
    int pid;
    int fd;
};

struct fd_path_value {
    char path[MAX_PATH_LEN];
    int path_len;
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

// Map to store file path patterns - key is index, value is path_pattern struct
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct path_pattern);
    __uint(max_entries, MAX_PATH_PATTERNS);
} path_patterns_map SEC(".maps");

// Map to store the number of active path patterns
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, 1);
} num_patterns_map SEC(".maps");

// Map to track file paths for file descriptors
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct fd_path_key);
    __type(value, struct fd_path_value);
    __uint(max_entries, 1024);
} fd_path_map SEC(".maps");

// Helper function to perform simple pattern matching
// Supports basic wildcards: * (matches any characters) and ? (matches single character)
static inline int pattern_match(const char *pattern, int pattern_len, const char *str, int str_len) {
    if (pattern_len == 0) return str_len == 0;
    if (str_len == 0) return pattern_len == 1 && pattern[0] == '*';

    // Handle * wildcard at the beginning
    if (pattern[0] == '*') {
        if (pattern_len == 1) return 1;  // "*" matches everything

        // Try matching the rest of the pattern at each position in the string
        for (int i = 0; i <= str_len; i++) {
            if (pattern_match(pattern + 1, pattern_len - 1, str + i, str_len - i)) {
                return 1;
            }
        }
        return 0;
    }

    // Handle ? wildcard or exact character match
    if (pattern[0] == '?' || pattern[0] == str[0]) {
        return pattern_match(pattern + 1, pattern_len - 1, str + 1, str_len - 1);
    }

    return 0;
}

// Helper function to check if a file path matches any configured pattern
static inline int is_path_in_patterns(const char *path, int path_len, int pid) {
    int key = 0;
    int *num_patterns;
    struct path_pattern *pattern;

    bpf_printk("[khaos_path_read_error] [PID %d] Checking path patterns for: %.64s", pid, path);

    // Get the number of configured patterns
    num_patterns = bpf_map_lookup_elem(&num_patterns_map, &key);
    if (!num_patterns || *num_patterns == 0) {
        bpf_printk("[khaos_path_read_error] [PID %d] No patterns configured", pid);
        return 0;  // No patterns configured
    }

    bpf_printk("[khaos_path_read_error] [PID %d] Found %d configured patterns", pid, *num_patterns);

    // Check each configured pattern
    for (int i = 0; i < MAX_PATH_PATTERNS && i < *num_patterns; i++) {
        pattern = bpf_map_lookup_elem(&path_patterns_map, &i);
        if (!pattern || pattern->len == 0) {
            bpf_printk("[khaos_path_read_error] [PID %d] Failed to lookup pattern %d", pid, i);
            continue;
        }

        bpf_printk("[khaos_path_read_error] [PID %d] Checking against pattern %d: %.64s", pid, i, pattern->pattern);

        // Check if the file path matches this pattern
        int matches = pattern_match(pattern->pattern, pattern->len, path, path_len);

        bpf_printk("[khaos_path_read_error] [PID %d] Pattern %d match check: path=%.32s vs pattern=%.32s = %s",
                   pid, i, path, pattern->pattern, matches ? "MATCH" : "no_match");

        if (matches) {
            bpf_printk("[khaos_path_read_error] [PID %d] PATH PATTERN HIT! Path matches pattern %d", pid, i);
            return 1;  // Path pattern match detected
        }
    }

    bpf_printk("[khaos_path_read_error] [PID %d] No match with any configured patterns - allowing read", pid);
    return 0;  // No match with any configured patterns
}

// Helper function to get file path from file descriptor
static inline int get_fd_path(int pid, int fd, char *path_buf, int buf_size) {
    struct fd_path_key path_key = {.pid = pid, .fd = fd};
    struct fd_path_value *path_val = bpf_map_lookup_elem(&fd_path_map, &path_key);

    if (path_val && path_val->path_len > 0) {
        int copy_len = path_val->path_len < buf_size ? path_val->path_len : buf_size - 1;
        bpf_probe_read_str(path_buf, copy_len + 1, path_val->path);
        return copy_len;
    }

    // If we don't have the path cached, we can't get it reliably from a kprobe
    // on the read syscall. The path would need to be captured during open().
    bpf_printk("[khaos_path_read_error] [PID %d] No cached path for fd %d", pid, fd);
    return 0;
}

SEC("kprobe/sys_openat")
int kprobe_openat_handler(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0; // PID not targeted
    }

    // Get openat parameters
    // openat(int dirfd, const char *pathname, int flags, mode_t mode)
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);

    char path_buf[MAX_PATH_LEN];
    int path_len = bpf_probe_read_str(path_buf, sizeof(path_buf), pathname);
    if (path_len <= 0) {
        return 0;
    }

    bpf_printk("[khaos_path_read_error] [PID %d] openat() called for path: %.64s", pid, path_buf);

    // We'll store the path when the open succeeds in the kretprobe
    return 0;
}

SEC("kretprobe/sys_openat")
int kretprobe_openat_handler(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    unsigned char *pid_exists;
    long ret = PT_REGS_RC(ctx);

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0; // PID not targeted
    }

    // Only track successful opens (positive file descriptor)
    if (ret < 0) {
        return 0;
    }

    int fd = (int)ret;

    // Get the pathname from the original syscall (stored in ctx during kprobe)
    // Note: This is a simplified approach. In practice, getting the pathname
    // in kretprobe is complex and might require storing it during kprobe.
    // For now, we'll use a simpler approach by capturing it in the read syscall.

    bpf_printk("[khaos_path_read_error] [PID %d] openat() returned fd %d", pid, fd);
    return 0;
}

SEC("kprobe/sys_read")
int kprobe_read_handler(struct pt_regs *ctx)
{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    int key = 0;
    int *err;
    unsigned char *pid_exists;

    bpf_printk("[khaos_path_read_error] Read syscall intercepted from PID: %d", pid);

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        bpf_printk("[khaos_path_read_error] PID %d not in target map - allowing", pid);
        return 0; // PID not targeted
    }

    // Get read parameters from syscall arguments
    // For read(): read(int fd, void *buf, size_t count)
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);

    bpf_printk("[khaos_path_read_error] Read syscall: fd=%d, count=%lu from PID %d", fd, count, pid);

    // Try to get the file path for this file descriptor
    char path_buf[MAX_PATH_LEN];
    int path_len = get_fd_path(pid, fd, path_buf, sizeof(path_buf));

    if (path_len <= 0) {
        // For this implementation, we'll try to get the path via procfs
        // This is a limitation - in a real implementation, we'd need to track
        // paths during open() calls more carefully
        char proc_path[64];
        bpf_snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", (__u64)pid, (__u64)fd);

        // In eBPF, we can't easily resolve symlinks, so we'll use a placeholder approach
        // A production implementation would need better path resolution
        bpf_probe_read_str(path_buf, sizeof(path_buf), proc_path);
        path_len = bpf_probe_read_str(path_buf, sizeof(path_buf), proc_path);

        bpf_printk("[khaos_path_read_error] [PID %d] Using proc path for fd %d: %.64s", pid, fd, path_buf);
    }

    if (path_len <= 0) {
        bpf_printk("[khaos_path_read_error] [PID %d] Could not determine path for fd %d - allowing", pid, fd);
        return 0; // Can't determine path, allow the read
    }

    // Check if the file path matches any configured patterns
    if (!is_path_in_patterns(path_buf, path_len, pid)) {
        bpf_printk("[khaos_path_read_error] [PID %d] Path does not match configured patterns - allowing", pid);
        return 0; // Allow the syscall to proceed
    }

    // Get the error code to inject
    err = bpf_map_lookup_elem(&err_map, &key);
    if (!err || !*err) {
        bpf_printk("[khaos_path_read_error] [PID %d] No error code configured - allowing", pid);
        return 0;
    }

    bpf_printk("[khaos_path_read_error] [PID %d] INJECTING EIO error %d for read() on path %.64s", pid, *err, path_buf);

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

    bpf_printk("[khaos_path_read_error] pread64 syscall from PID: %d", pid);

    // Check if this PID is in our target map
    pid_exists = bpf_map_lookup_elem(&pid_map, &pid);
    if (!pid_exists) {
        return 0; // PID not targeted
    }

    // Get pread64 parameters from syscall arguments
    // For pread64(): pread64(int fd, void *buf, size_t count, off_t offset)
    int fd = (int)PT_REGS_PARM1(ctx);
    __u64 count = (__u64)PT_REGS_PARM3(ctx);
    __u64 offset = (__u64)PT_REGS_PARM4(ctx);

    bpf_printk("[khaos_path_read_error] pread64: fd=%d, count=%lu, offset=%lld", fd, count, offset);

    // Try to get the file path for this file descriptor
    char path_buf[MAX_PATH_LEN];
    int path_len = get_fd_path(pid, fd, path_buf, sizeof(path_buf));

    if (path_len <= 0) {
        char proc_path[64];
        bpf_snprintf(proc_path, sizeof(proc_path), "/proc/%d/fd/%d", (__u64)pid, (__u64)fd);
        path_len = bpf_probe_read_str(path_buf, sizeof(path_buf), proc_path);

        bpf_printk("[khaos_path_read_error] [PID %d] Using proc path for fd %d: %.64s", pid, fd, path_buf);
    }

    if (path_len <= 0) {
        bpf_printk("[khaos_path_read_error] [PID %d] Could not determine path for fd %d - allowing", pid, fd);
        return 0; // Can't determine path, allow the read
    }

    // Check if the file path matches any configured patterns
    if (!is_path_in_patterns(path_buf, path_len, pid)) {
        bpf_printk("[khaos_path_read_error] Path does not match configured patterns - allowing");
        return 0; // Allow the syscall to proceed
    }

    // Get the error code to inject
    err = bpf_map_lookup_elem(&err_map, &key);
    if (!err || !*err) {
        bpf_printk("[khaos_path_read_error] No error code configured - allowing");
        return 0;
    }

    bpf_printk("[khaos_path_read_error] Injecting EIO error %d for PID %d on path %.64s", *err, pid, path_buf);

    // Override the syscall return with the configured error
    bpf_override_return(ctx, *err);

    return 0;
}

char LICENSE[] SEC("license") = "GPL";