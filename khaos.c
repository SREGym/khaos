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

// Define probe types
enum probe_type {
  PT_KPROBE,
  PT_KRETPROBE
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
    {"write_error",         "write",         PT_KPROBE, .params.kprobe_ERRN=-28},
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
};

#define NUM_FAULTS (sizeof(fault_registry) / sizeof(fault_registry[0]))

const struct fault_entry* find_fault(const char *name) {
    for (size_t i = 0; i < NUM_FAULTS; ++i) { 
        if (strcmp(name, fault_registry[i].name) == 0)
            return &fault_registry[i];
    }
    return NULL;
}

void recover_fault(const char *fault_name) {
    char buf[256]; 

    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-%s", fault_name);
    if (unlink(buf) == 0) {
        printf("Successfully removed pinned kprobe BPF link: %s\n", buf);
        return;
    }     

    // Try removing kretprobe pin path
    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kretprobe-%s", fault_name);
    if (unlink(buf) == 0) {
        printf("Successfully removed pinned kretprobe BPF link: %s\n", buf);
        return;
    }

    fprintf(stderr, "Failed to remove any pinned BPF links for fault: '%s'", fault_name);
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (use 'sudo').\n");
        return 1;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <fault_name> <pid> | --recover <fault_name>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--recover") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --recover <fault_name>\n", argv[0]);
            return 1;
        }
        recover_fault(argv[2]);
        return 0;
    }

    const struct fault_entry *fault = find_fault(argv[1]);
    if (!fault) {
        fprintf(stderr, "ERROR: Unknown fault type: %s\n", argv[1]);
        return 1;
    }
    int pid = atoi(argv[2]);

    struct bpf_link *link = NULL; 
    char pin_path_buf[256]; // Renamed from 'buf' to avoid conflict with recover_fault's 'buf' if it were inlined
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

        snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kprobe-%s", fault->name); 
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

        snprintf(pin_path_buf, sizeof(pin_path_buf), "/sys/fs/bpf/khaos-kretprobe-%s", fault->name);
        if (bpf_link__pin(link, pin_path_buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin kretprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned kretprobe link to %s\n", pin_path_buf);
        }

        bpf_link__destroy(link);
        kretprobe_bpf__destroy(obj_kretprobe);

        printf("Injected kretprobe fault '%s' (syscall: %s, forced_ret: %ld) into PID %d\n",
               fault->name, fault->syscall, fault->params.kretprobe_RETV, pid);
    } else {
        fprintf(stderr, "ERROR: Unknown fault->type defined in registry for fault: %s\n", fault->name);
        return 1;
    }
    
    return 0;
}
