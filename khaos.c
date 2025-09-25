#include <stdio.h>
#include <sys/utsname.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>      // For strerror
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kprobe.skel.h"
#include "kretprobe.skel.h" // UNCOMMENT/ADD this line
#include "kprobe_packet_loss_sendto.skel.h"
#include "kprobe_packet_loss_recvfrom.skel.h"
#include "kprobe_block_read_error.skel.h"

// Define probe types
enum probe_type {
  PT_KPROBE,
  PT_KRETPROBE,
  PT_KPROBE_PACKET_LOSS_SENDTO,
  PT_KPROBE_PACKET_LOSS_RECVFROM,
  PT_KPROBE_BLOCK_READ_ERROR
};

struct fault_entry {
    const char *name;
    const char *syscall; // Syscall/kernel function name to target
    enum probe_type type; 
    union {
      int kprobe_ERRN; 
      long kretprobe_RETV;
    } params;
};

const char* get_syscall_prefix() {
    static char prefix[16] = {0}; // Static buffer to hold the prefix
    struct utsname u;

    if (prefix[0] != 0) {
        return prefix;
    }

    // Get system information
    if (uname(&u) < 0) {
        perror("uname failed");
        strcpy(prefix, "sys_"); // Fallback
        return prefix;
    }

    if (strcmp(u.machine, "x86_64") == 0) {
        strcpy(prefix, "__x64_sys_");
    } else if (strcmp(u.machine, "aarch64") == 0) {
        strcpy(prefix, "__arm64_sys_");
    } else {
        strcpy(prefix, "sys_");
    }

    return prefix;
}

static struct fault_entry fault_registry[] = {
    // ----------------- GENERAL SYSCALL INJECTION -----------------------------------
    // KPROBE FAULTS
    {"read_error",          "read",          PT_KPROBE, .params.kprobe_ERRN=-5},
    {"pread_error",         "pread64",       PT_KPROBE, .params.kprobe_ERRN=-5},
    {"write_error",         "write",         PT_KPROBE, .params.kprobe_ERRN=-28},
    {"pwrite_error",        "pwrite64",      PT_KPROBE, .params.kprobe_ERRN=-28},
    {"fsync_error",         "fsync",         PT_KPROBE, .params.kprobe_ERRN=-5},
    {"open_error",          "openat",        PT_KPROBE, .params.kprobe_ERRN=-13},
    {"close_fail",          "close",         PT_KPROBE, .params.kprobe_ERRN=-9},
    {"dup_fail",            "dup",           PT_KPROBE, .params.kprobe_ERRN=-24},
    {"getrandom_fail",      "getrandom",     PT_KPROBE, .params.kprobe_ERRN=-11},
    {"gettimeofday_fail",   "gettimeofday",  PT_KPROBE, .params.kprobe_ERRN=-1},
    {"ioctl_fail",          "ioctl",         PT_KPROBE, .params.kprobe_ERRN=-25},
    {"cuda_malloc_fail",    "ioctl",         PT_KPROBE, .params.kprobe_ERRN=-12},
    {"getaddrinfo_fail",    "recvfrom",      PT_KPROBE, .params.kprobe_ERRN=-1},
    {"nanosleep_throttle",  "nanosleep",     PT_KPROBE, .params.kprobe_ERRN=-5},
    {"nanosleep_interrupt", "nanosleep",     PT_KPROBE, .params.kprobe_ERRN=-4},
    {"fork_fail",           "fork",          PT_KPROBE, .params.kprobe_ERRN=-11},
    {"clock_drift",         "clock_gettime", PT_KPROBE, .params.kprobe_ERRN=-5},
    {"setns_fail",          "setns",         PT_KPROBE, .params.kprobe_ERRN=-1},
    {"prlimit_fail",        "prlimit64",     PT_KPROBE, .params.kprobe_ERRN=-1},
    {"socket_block",        "socket",        PT_KPROBE, .params.kprobe_ERRN=-1},
    {"mmap_fail",           "mmap",          PT_KPROBE, .params.kprobe_ERRN=-12},
    {"mmap_oom",            "mmap",          PT_KPROBE, .params.kprobe_ERRN=-12},
    {"brk_fail",            "brk",           PT_KPROBE, .params.kprobe_ERRN=-12},
    {"mlock_fail",          "mlock",         PT_KPROBE, .params.kprobe_ERRN=-12},
    {"bind_enetdown",       "bind",          PT_KPROBE, .params.kprobe_ERRN=-100},
    {"mount_io_error",      "mount",         PT_KPROBE, .params.kprobe_ERRN=-5},
    
    // ADD KRETPROBE FAULTS HERE
    {"force_close_ret_err", "close",         PT_KRETPROBE, .params.kretprobe_RETV=-1L},
    {"force_read_ret_ok",   "read",          PT_KRETPROBE, .params.kretprobe_RETV=0L},
    {"force_open_ret_eperm","openat",        PT_KRETPROBE, .params.kretprobe_RETV=(long)-EPERM}, // Example
    {"force_mmap_eagain",   "mmap",          PT_KRETPROBE, .params.kretprobe_RETV=-11L},
    {"force_brk_eagain",    "brk",           PT_KRETPROBE, .params.kretprobe_RETV=-11L},    
    {"force_mlock_eperm",   "mlock",         PT_KRETPROBE, .params.kretprobe_RETV=-1L},
    {"force_mprotect_eacces", "mprotect",    PT_KRETPROBE, .params.kretprobe_RETV=-13L},
    {"force_swapon_einval", "swapon",        PT_KRETPROBE, .params.kretprobe_RETV=-22L},

    // ---------------------------- SPECIFIC FAULTS ----------------------------------

    // MEMORY CORRUPTION FAULTS
    {"oom_memchunk",             "mmap",          PT_KPROBE,    .params.kprobe_ERRN=-12},
    {"oom_heapspace",            "brk",           PT_KPROBE,    .params.kprobe_ERRN=-12},
    {"oom_nonswap",              "mlock",         PT_KPROBE,    .params.kprobe_ERRN=-12},
    {"hfrag_memchunk",           "mmap",          PT_KRETPROBE, .params.kretprobe_RETV=-11L},
    {"hfrag_heapspace",          "brk",           PT_KRETPROBE, .params.kretprobe_RETV=-11L},
    {"ptable_permit",            "mlock",         PT_KRETPROBE, .params.kretprobe_RETV=-1L},
    {"stack_rndsegfault",        "mprotect",      PT_KRETPROBE, .params.kretprobe_RETV=-13L},
    {"thrash_swapon",            "swapon",        PT_KRETPROBE, .params.kretprobe_RETV=-22L},
    {"thrash_swapoff",           "swapoff",       PT_KPROBE,    .params.kprobe_ERRN=-1}, // -EPERM
    {"memleak_munmap",           "munmap",        PT_KRETPROBE, .params.kretprobe_RETV=-22L}, // -EINVAL

     // NETWORK FAULTS
    {"packet_loss_sendto",  "sendto",        PT_KPROBE_PACKET_LOSS_SENDTO, .params.kprobe_ERRN=-ECONNREFUSED},
    {"packet_loss_recvfrom", "recvfrom",     PT_KPROBE_PACKET_LOSS_RECVFROM, .params.kprobe_ERRN=-ECONNREFUSED},

    // BLOCK-SPECIFIC READ ERROR FAULTS
    {"block_read_error",    "read",          PT_KPROBE_BLOCK_READ_ERROR, .params.kprobe_ERRN=-5}, // -EIO
};

#define NUM_FAULTS (sizeof(fault_registry) / sizeof(fault_registry[0]))

const struct fault_entry* find_fault(const char *name) {
    for (size_t i = 0; i < NUM_FAULTS; ++i) { 
        if (strcmp(name, fault_registry[i].name) == 0)
            return &fault_registry[i];
    }
    return NULL;
}

// Structure to represent a block range (matching eBPF structure)
struct block_range {
    unsigned long long start;
    unsigned long long end;
};

// Function to parse block ranges in format "start1:end1,start2:end2,..."
int parse_block_ranges(const char *range_str, struct block_range *ranges, int max_ranges) {
    if (!range_str || !ranges || max_ranges <= 0) {
        return -1;
    }

    size_t len = strlen(range_str);
    char *str_copy = malloc(len + 1);
    if (!str_copy) {
        fprintf(stderr, "ERROR: Failed to allocate memory for block range parsing\n");
        return -1;
    }
    strcpy(str_copy, range_str);

    int count = 0;
    char *token = strtok(str_copy, ",");

    while (token != NULL && count < max_ranges) {
        // Trim whitespace
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }

        // Parse start:end format
        char *colon = strchr(token, ':');
        if (!colon) {
            fprintf(stderr, "ERROR: Invalid block range format '%s' - expected 'start:end'\n", token);
            free(str_copy);
            return -1;
        }

        *colon = '\0';  // Split the string
        char *start_str = token;
        char *end_str = colon + 1;

        // Parse start and end values
        char *endptr;
        unsigned long long start = strtoull(start_str, &endptr, 10);
        if (*endptr != '\0' || endptr == start_str) {
            fprintf(stderr, "ERROR: Invalid start block '%s' in range '%s:%s'\n", start_str, start_str, end_str);
            free(str_copy);
            return -1;
        }

        unsigned long long range_end = strtoull(end_str, &endptr, 10);
        if (*endptr != '\0' || endptr == end_str) {
            fprintf(stderr, "ERROR: Invalid end block '%s' in range '%s:%s'\n", end_str, start_str, end_str);
            free(str_copy);
            return -1;
        }

        if (start > range_end) {
            fprintf(stderr, "ERROR: Invalid block range %llu:%llu - start must be <= end\n", start, range_end);
            free(str_copy);
            return -1;
        }

        ranges[count].start = start;
        ranges[count].end = range_end;
        count++;

        token = strtok(NULL, ",");
    }

    free(str_copy);
    return count;
}

// Function to parse comma-separated PIDs
int parse_pids(const char *pid_str, int *pids, int max_pids) {
    size_t len = strlen(pid_str);
    char *str_copy = malloc(len + 1);
    if (!str_copy) {
        fprintf(stderr, "ERROR: Failed to allocate memory for PID parsing\n");
        return -1;
    }
    strcpy(str_copy, pid_str);
    
    int count = 0;
    char *token = strtok(str_copy, ",");
    
    while (token != NULL && count < max_pids) {
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end > token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        
        int pid = atoi(token);
        if (pid <= 0) {
            fprintf(stderr, "ERROR: Invalid PID '%s' - must be a positive integer\n", token);
            free(str_copy);
            return -1;
        }
        
        pids[count] = pid;
        count++;
        token = strtok(NULL, ",");
    }
    
    free(str_copy);
    return count;
}


void recover_fault(const char *fault_name, int pid) {
    char buf[256]; 
    int removed = 0;

    if (pid == -1) {
        // Recover all instances of fault
        printf("Searching for all instances of fault '%s'...\n", fault_name);
        
        char cmd[512];
        snprintf(cmd, sizeof(cmd), "find /sys/fs/bpf -name '*khaos-*-%s*' -delete 2>/dev/null", fault_name);
        int result = system(cmd);
        if (result == 0) {
            printf("Recovery completed for fault: '%s'\n", fault_name);
            removed = 1;
        }
    } else {

        // Try kprobe pin path
        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-%s_%d", fault_name, pid);
        if (unlink(buf) == 0) {
            printf("Successfully removed pinned kprobe BPF link: %s\n", buf);
            removed = 1;
        }     

        // Try kretprobe pin path
        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kretprobe-%s_%d", fault_name, pid);
        if (unlink(buf) == 0) {
            printf("Successfully removed pinned kretprobe BPF link: %s\n", buf);
            removed = 1;
        }

        // Try packet loss sendto pin path
        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-packet-loss-sendto-%s_%d", fault_name, pid);
        if (unlink(buf) == 0) {
            printf("Successfully removed pinned packet loss sendto BPF link: %s\n", buf);
            removed = 1;
        }

        // Try packet loss recvfrom pin path
        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-packet-loss-recvfrom-%s_%d", fault_name, pid);
        if (unlink(buf) == 0) {
            printf("Successfully removed pinned packet loss recvfrom BPF link: %s\n", buf);
            removed = 1;
        }

        // Try block read error pin path
        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-block-read-error-%s_%d", fault_name, pid);
        if (unlink(buf) == 0) {
            printf("Successfully removed pinned block read error BPF link: %s\n", buf);
            removed = 1;
        }

        // Try block read error read syscall pin path
        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-block-read-error-read-%s_%d", fault_name, pid);
        if (unlink(buf) == 0) {
            printf("Successfully removed pinned block read error read syscall BPF link: %s\n", buf);
            removed = 1;
        }
    }

    if (!removed) {
        if (pid == -1) {
            fprintf(stderr, "No pinned BPF links found for fault: '%s'\n", fault_name);
        } else {
            fprintf(stderr, "Failed to remove any pinned BPF links for fault: '%s' with PID: %d\n", fault_name, pid);
        }
    }
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (use 'sudo').\n");
        return 1;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <fault_name> <pid> [optional_param] | --recover <fault_name> [pid]\n", argv[0]);
        fprintf(stderr, "       %s <fault_name> <pid1,pid2,pid3,...> [optional_param]\n", argv[0]);
        fprintf(stderr, "\nFault-specific parameters:\n");
        fprintf(stderr, "  packet_loss_sendto, packet_loss_recvfrom: [drop_rate%%] (default: 30%%)\n");
        fprintf(stderr, "  block_read_error: <block_ranges> (required, format: start1:end1,start2:end2,...)\n");
        fprintf(stderr, "\nExample:\n");
        fprintf(stderr, "  %s block_read_error 1234 \"100:199,500:599\"\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--recover") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --recover <fault_name> [pid]\n", argv[0]);
            return 1;
        }
        int pid = -1; // Default to recover all
        if (argc >= 4) {
            pid = atoi(argv[3]);
        }
        recover_fault(argv[2], pid);
        return 0;
    }

    const struct fault_entry *fault = find_fault(argv[1]);
    if (!fault) {
        fprintf(stderr, "ERROR: Unknown fault type: %s\n", argv[1]);
        return 1;
    }
    
    // Parse comma-separated PIDs
    int pids[64]; // Maximum 64 PIDs
    int num_pids = parse_pids(argv[2], pids, 64);
    if (num_pids <= 0) {
        fprintf(stderr, "ERROR: Failed to parse PIDs from '%s'\n", argv[2]);
        return 1;
    }
    
    int drop_rate = 30;
    if ((fault->type == PT_KPROBE_PACKET_LOSS_SENDTO || fault->type == PT_KPROBE_PACKET_LOSS_RECVFROM) && argc >= 4) {
        drop_rate = atoi(argv[3]);
        if (drop_rate < 0) drop_rate = 0;
        if (drop_rate > 100) drop_rate = 100;
    }

    // Parse block ranges for block_read_error fault
    struct block_range block_ranges[32];  // Maximum 32 block ranges
    int num_block_ranges = 0;
    if (fault->type == PT_KPROBE_BLOCK_READ_ERROR && argc >= 4) {
        num_block_ranges = parse_block_ranges(argv[3], block_ranges, 32);
        if (num_block_ranges <= 0) {
            fprintf(stderr, "ERROR: Failed to parse block ranges from '%s'\n", argv[3]);
            return 1;
        }
        printf("Configured %d block ranges: ", num_block_ranges);
        for (int i = 0; i < num_block_ranges; i++) {
            printf("%llu:%llu", block_ranges[i].start, block_ranges[i].end);
            if (i < num_block_ranges - 1) printf(", ");
        }
        printf("\n");
    } else if (fault->type == PT_KPROBE_BLOCK_READ_ERROR) {
        fprintf(stderr, "ERROR: block_read_error fault requires block ranges parameter (format: start1:end1,start2:end2,...)\n");
        return 1;
    }
    
    printf("Injecting fault '%s' into %d PIDs: ", fault->name, num_pids);
    for (int i = 0; i < num_pids; i++) {
        printf("%d", pids[i]);
        if (i < num_pids - 1) printf(", ");
    }
    printf("\n");

    // Loop through each PID and inject the fault
    for (int pid_idx = 0; pid_idx < num_pids; pid_idx++) {
        int pid = pids[pid_idx];
        printf("\n--- Processing PID %d ---\n", pid);
        
        struct bpf_link *link = NULL; 
        char pin_path_buf[512];
        int key = 0;  
        unsigned char value = 1;
        
        if (fault->type == PT_KPROBE) {
        struct kprobe_bpf *obj_kprobe = kprobe_bpf__open_and_load(); 

        if (!obj_kprobe) { 
            fprintf(stderr, "ERROR: Failed to open/load kprobe BPF skeleton: %s\n", strerror(errno));
            return 1; 
        }
        
        if (bpf_map__update_elem(obj_kprobe->maps.err_map, 
                                &key, sizeof(key), 
                                &fault->params.kprobe_ERRN, sizeof(fault->params.kprobe_ERRN), 
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe err_map: %s\n", strerror(errno));   
            kprobe_bpf__destroy(obj_kprobe); 
            return 1;
        }

        if (bpf_map__update_elem(obj_kprobe->maps.pid_map,
                                &pid, sizeof(pid),
                                &value, sizeof(value),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe pid_map: %s\n", strerror(errno));   
            kprobe_bpf__destroy(obj_kprobe); 
            return 1;
        }
        
        LIBBPF_OPTS(bpf_ksyscall_opts, opts_ksyscall); 
        link = bpf_program__attach_ksyscall(obj_kprobe->progs.kprobe_handler, fault->syscall, &opts_ksyscall);

        if (libbpf_get_error(link)) { 
            fprintf(stderr, "ERROR: Failed to attach kprobe (via ksyscall) to %s: %s\n", fault->syscall, strerror(errno));
            kprobe_bpf__destroy(obj_kprobe); 
            return 1;
        }

        if (snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kprobe-%s_%d", fault->name, pid) >= sizeof(pin_path_buf)) {
            fprintf(stderr, "ERROR: Pin path too long for kprobe: %s_%d\n", fault->name, pid);
            bpf_link__destroy(link);
            kprobe_bpf__destroy(obj_kprobe);
            return 1;
        }
        
        if (bpf_link__pin(link, pin_path_buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin kprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned kprobe link to %s\n", pin_path_buf);
        }
        
        bpf_link__destroy(link); 
        kprobe_bpf__destroy(obj_kprobe); 
        
        printf("Injected kprobe fault '%s' (syscall: %s, errno: %d) into PID %d\n", 
               fault->name, fault->syscall, fault->params.kprobe_ERRN, pid);

    } else if (fault->type == PT_KRETPROBE) {
        struct kretprobe_bpf *obj_kretprobe = kretprobe_bpf__open_and_load();
        if (!obj_kretprobe) {
            fprintf(stderr, "ERROR: Failed to open/load kretprobe BPF skeleton: %s\n", strerror(errno));
            return 1;
        }

        if (bpf_map__update_elem(obj_kretprobe->maps.ret_val_map, 
                                &key, sizeof(key),
                                &fault->params.kretprobe_RETV, sizeof(fault->params.kretprobe_RETV),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kretprobe ret_val_map: %s\n", strerror(errno));
            kretprobe_bpf__destroy(obj_kretprobe);
            return 1;
        }
        if (bpf_map__update_elem(obj_kretprobe->maps.pid_map,
                                &pid, sizeof(pid),
                                &value, sizeof(value),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kretprobe pid_map: %s\n", strerror(errno));
            kretprobe_bpf__destroy(obj_kretprobe);
            return 1;
        }
        
        char full_syscall_name[256];
        snprintf(full_syscall_name, sizeof(full_syscall_name), "%s%s", get_syscall_prefix(), fault->syscall);

        LIBBPF_OPTS(bpf_kprobe_opts, opts_kretprobe, .retprobe = true); // kretprobes typically use kprobe_opts struct
        link = bpf_program__attach_kprobe_opts(obj_kretprobe->progs.kretprobe_handler, full_syscall_name, &opts_kretprobe);

        if (libbpf_get_error(link)) {
            fprintf(stderr, "ERROR: Failed to attach kretprobe to %s: %s\n", fault->syscall, strerror(errno));
            kretprobe_bpf__destroy(obj_kretprobe);
            return 1;
        }

        if (snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kretprobe-%s_%d", fault->name, pid) >= sizeof(pin_path_buf)) {
            fprintf(stderr, "ERROR: Pin path too long for kretprobe: %s_%d\n", fault->name, pid);
            bpf_link__destroy(link);
            kretprobe_bpf__destroy(obj_kretprobe);
            return 1;
        }
        
        if (bpf_link__pin(link, pin_path_buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin kretprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned kretprobe link to %s\n", pin_path_buf);
        }

        bpf_link__destroy(link);
        kretprobe_bpf__destroy(obj_kretprobe);

        printf("Injected kretprobe fault '%s' (syscall: %s, forced_ret: %ld) into PID %d\n",
               fault->name, fault->syscall, fault->params.kretprobe_RETV, pid);
    } else if (fault->type == PT_KPROBE_PACKET_LOSS_SENDTO) {
        struct kprobe_packet_loss_sendto_bpf *obj_packet_loss_sendto = kprobe_packet_loss_sendto_bpf__open_and_load();
        if (!obj_packet_loss_sendto) {
            fprintf(stderr, "ERROR: Failed to open/load kprobe_packet_loss_sendto BPF skeleton: %s\n", strerror(errno));
            return 1;
        }

        // Update error map with the error code to return when dropping packets
        if (bpf_map__update_elem(obj_packet_loss_sendto->maps.err_map, 
                                &key, sizeof(key),
                                &fault->params.kprobe_ERRN, sizeof(fault->params.kprobe_ERRN),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_packet_loss_sendto err_map: %s\n", strerror(errno));
            kprobe_packet_loss_sendto_bpf__destroy(obj_packet_loss_sendto);
            return 1;
        }

        // Update pid map
        if (bpf_map__update_elem(obj_packet_loss_sendto->maps.pid_map,
                                &pid, sizeof(pid),
                                &value, sizeof(value),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_packet_loss_sendto pid_map: %s\n", strerror(errno));
            kprobe_packet_loss_sendto_bpf__destroy(obj_packet_loss_sendto);
            return 1;
        }

        // Update drop_rate map
        if (bpf_map__update_elem(obj_packet_loss_sendto->maps.drop_rate_map,
                                &key, sizeof(key),
                                &drop_rate, sizeof(drop_rate),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_packet_loss_sendto drop_rate_map: %s\n", strerror(errno));
            kprobe_packet_loss_sendto_bpf__destroy(obj_packet_loss_sendto);
            return 1;
        }

        // Attach the kprobe program to sendto
        LIBBPF_OPTS(bpf_kprobe_opts, opts_packet_loss_sendto);
        char full_syscall_name[256];
        snprintf(full_syscall_name, sizeof(full_syscall_name), "%s%s", get_syscall_prefix(), fault->syscall);
        struct bpf_link *ks_link = bpf_program__attach_kprobe_opts(obj_packet_loss_sendto->progs.kprobe_sendto_handler, full_syscall_name, &opts_packet_loss_sendto);
        if (libbpf_get_error(ks_link)) {
            fprintf(stderr, "ERROR: Failed to attach kprobe program to %s: %s\n", full_syscall_name, strerror(errno));
            kprobe_packet_loss_sendto_bpf__destroy(obj_packet_loss_sendto);
            return 1;
        }

        // Pin the kprobe link
        if (snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kprobe-packet-loss-sendto-%s_%d", fault->name, pid) >= sizeof(pin_path_buf)) {
            fprintf(stderr, "ERROR: Pin path too long for packet loss sendto: %s_%d\n", fault->name, pid);
            bpf_link__destroy(ks_link);
            kprobe_packet_loss_sendto_bpf__destroy(obj_packet_loss_sendto);
            return 1;
        }
        
        if (bpf_link__pin(ks_link, pin_path_buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin packet loss sendto kprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned packet loss sendto kprobe link to %s\n", pin_path_buf);
        }

        bpf_link__destroy(ks_link);
        kprobe_packet_loss_sendto_bpf__destroy(obj_packet_loss_sendto);

        printf("Injected kprobe_packet_loss_sendto fault '%s' (syscall: %s, packet_loss: 20%%, error: %d) into PID %d\n",
               fault->name, fault->syscall, fault->params.kprobe_ERRN, pid);
    } else if (fault->type == PT_KPROBE_PACKET_LOSS_RECVFROM) {
        struct kprobe_packet_loss_recvfrom_bpf *obj_packet_loss_recvfrom = kprobe_packet_loss_recvfrom_bpf__open_and_load();
        if (!obj_packet_loss_recvfrom) {
            fprintf(stderr, "ERROR: Failed to open/load kprobe_packet_loss_recvfrom BPF skeleton: %s\n", strerror(errno));
            return 1;
        }

        // Update error map with the error code to return when dropping packets
        if (bpf_map__update_elem(obj_packet_loss_recvfrom->maps.err_map, 
                                &key, sizeof(key),
                                &fault->params.kprobe_ERRN, sizeof(fault->params.kprobe_ERRN),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_packet_loss_recvfrom err_map: %s\n", strerror(errno));
            kprobe_packet_loss_recvfrom_bpf__destroy(obj_packet_loss_recvfrom);
            return 1;
        }

        // Update pid map
        if (bpf_map__update_elem(obj_packet_loss_recvfrom->maps.pid_map,
                                &pid, sizeof(pid),
                                &value, sizeof(value),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_packet_loss_recvfrom pid_map: %s\n", strerror(errno));
            kprobe_packet_loss_recvfrom_bpf__destroy(obj_packet_loss_recvfrom);
            return 1;
        }

        // Update drop_rate map
        if (bpf_map__update_elem(obj_packet_loss_recvfrom->maps.drop_rate_map,
                                &key, sizeof(key),
                                &drop_rate, sizeof(drop_rate),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_packet_loss_recvfrom drop_rate_map: %s\n", strerror(errno));
            kprobe_packet_loss_recvfrom_bpf__destroy(obj_packet_loss_recvfrom);
            return 1;
        }

        // Attach the kprobe program to recvfrom
        LIBBPF_OPTS(bpf_kprobe_opts, opts_packet_loss_recvfrom);
        char full_syscall_name[256];
        snprintf(full_syscall_name, sizeof(full_syscall_name), "%s%s", get_syscall_prefix(), fault->syscall);
        struct bpf_link *ks_link = bpf_program__attach_kprobe_opts(obj_packet_loss_recvfrom->progs.kprobe_recvfrom_handler, full_syscall_name, &opts_packet_loss_recvfrom);
        if (libbpf_get_error(ks_link)) {
            fprintf(stderr, "ERROR: Failed to attach kprobe program to %s: %s\n", full_syscall_name, strerror(errno));
            kprobe_packet_loss_recvfrom_bpf__destroy(obj_packet_loss_recvfrom);
            return 1;
        }

        // Pin the kprobe link
        if (snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kprobe-packet-loss-recvfrom-%s_%d", fault->name, pid) >= sizeof(pin_path_buf)) {
            fprintf(stderr, "ERROR: Pin path too long for packet loss recvfrom: %s_%d\n", fault->name, pid);
            bpf_link__destroy(ks_link);
            kprobe_packet_loss_recvfrom_bpf__destroy(obj_packet_loss_recvfrom);
            return 1;
        }
        
        if (bpf_link__pin(ks_link, pin_path_buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin packet loss recvfrom kprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned packet loss recvfrom kprobe link to %s\n", pin_path_buf);
        }

        bpf_link__destroy(ks_link);
        kprobe_packet_loss_recvfrom_bpf__destroy(obj_packet_loss_recvfrom);

        printf("Injected kprobe_packet_loss_recvfrom fault '%s' (syscall: %s, packet_loss: 20%%, error: %d) into PID %d\n",
               fault->name, fault->syscall, fault->params.kprobe_ERRN, pid);
    } else if (fault->type == PT_KPROBE_BLOCK_READ_ERROR) {
        struct kprobe_block_read_error_bpf *obj_block_read_error = kprobe_block_read_error_bpf__open_and_load();
        if (!obj_block_read_error) {
            fprintf(stderr, "ERROR: Failed to open/load kprobe_block_read_error BPF skeleton: %s\n", strerror(errno));
            return 1;
        }

        // Update error map with the error code to return for blocked reads
        if (bpf_map__update_elem(obj_block_read_error->maps.err_map,
                                &key, sizeof(key),
                                &fault->params.kprobe_ERRN, sizeof(fault->params.kprobe_ERRN),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_block_read_error err_map: %s\n", strerror(errno));
            kprobe_block_read_error_bpf__destroy(obj_block_read_error);
            return 1;
        }

        // Update pid map
        if (bpf_map__update_elem(obj_block_read_error->maps.pid_map,
                                &pid, sizeof(pid),
                                &value, sizeof(value),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_block_read_error pid_map: %s\n", strerror(errno));
            kprobe_block_read_error_bpf__destroy(obj_block_read_error);
            return 1;
        }

        // Update block ranges maps
        int zero_key = 0;
        if (bpf_map__update_elem(obj_block_read_error->maps.num_ranges_map,
                                &zero_key, sizeof(zero_key),
                                &num_block_ranges, sizeof(num_block_ranges),
                                BPF_ANY) != 0) {
            fprintf(stderr, "ERROR: Failed to update kprobe_block_read_error num_ranges_map: %s\n", strerror(errno));
            kprobe_block_read_error_bpf__destroy(obj_block_read_error);
            return 1;
        }

        // Update individual block ranges
        for (int i = 0; i < num_block_ranges; i++) {
            if (bpf_map__update_elem(obj_block_read_error->maps.block_ranges_map,
                                    &i, sizeof(i),
                                    &block_ranges[i], sizeof(block_ranges[i]),
                                    BPF_ANY) != 0) {
                fprintf(stderr, "ERROR: Failed to update kprobe_block_read_error block_ranges_map[%d]: %s\n", i, strerror(errno));
                kprobe_block_read_error_bpf__destroy(obj_block_read_error);
                return 1;
            }
        }

        // Attach using the same method as read_error fault (ksyscall attachment)
        LIBBPF_OPTS(bpf_ksyscall_opts, opts_ksyscall);

        // Attach to read syscall using ksyscall method (same as working read_error)
        struct bpf_link *read_link = bpf_program__attach_ksyscall(obj_block_read_error->progs.kprobe_read_handler, fault->syscall, &opts_ksyscall);
        if (libbpf_get_error(read_link)) {
            fprintf(stderr, "ERROR: Failed to attach kprobe (via ksyscall) to %s: %s\n", fault->syscall, strerror(errno));
            kprobe_block_read_error_bpf__destroy(obj_block_read_error);
            return 1;
        }

        // Pin the read link
        if (snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kprobe-block-read-error-%s_%d", fault->name, pid) >= sizeof(pin_path_buf)) {
            fprintf(stderr, "ERROR: Pin path too long for block read error: %s_%d\n", fault->name, pid);
            bpf_link__destroy(read_link);
            kprobe_block_read_error_bpf__destroy(obj_block_read_error);
            return 1;
        }

        if (bpf_link__pin(read_link, pin_path_buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin block read error kprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned block read error kprobe link to %s\n", pin_path_buf);
        }

        bpf_link__destroy(read_link);
        kprobe_block_read_error_bpf__destroy(obj_block_read_error);

        printf("Injected kprobe_block_read_error fault '%s' (syscall: %s, EIO on %d block ranges) into PID %d\n",
               fault->name, fault->syscall, num_block_ranges, pid);
        } else {
            fprintf(stderr, "ERROR: Unknown fault->type defined in registry for fault: %s\n", fault->name);
            return 1;
        }
        
        printf("Successfully processed PID %d\n", pid);
    }
    
    printf("\nCompleted fault injection for all %d PIDs\n", num_pids);
    return 0;
}
