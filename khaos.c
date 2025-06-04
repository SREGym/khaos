#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>      // For strerror
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "kprobe.skel.h"
// #include "kretprobe.skel.h" //

enum probe_type {
  PT_KPROBE,
  PT_KRETPROBE 
};

struct fault_entry {
    const char *name;
    const char *syscall;
    enum probe_type type; 
    union {
      int kprobe_ERRN; 
      long kretprobe_RETV;
    } params;
};

static struct fault_entry fault_registry[] = {
    {"read_error",          "read",          PT_KPROBE, .params.kprobe_ERRN=-5},
    {"write_error",         "write",         PT_KPROBE, .params.kprobe_ERRN=-28},
    {"fsync_error",         "fsync",         PT_KPROBE, .params.kprobe_ERRN=-5},
    {"open_error",          "openat",        PT_KPROBE, .params.kprobe_ERRN=-13},
    {"close_fail",          "close",         PT_KPROBE, .params.kprobe_ERRN=-9},
    {"dup_fail",            "dup",           PT_KPROBE, .params.kprobe_ERRN=-24},
    {"mmap_fail",           "mmap",          PT_KPROBE, .params.kprobe_ERRN=-12},
    {"mmap_oom",            "mmap",          PT_KPROBE, .params.kprobe_ERRN=-12},
    {"brk_fail",            "brk",           PT_KPROBE, .params.kprobe_ERRN=-12},
    {"mlock_fail",          "mlock",         PT_KPROBE, .params.kprobe_ERRN=-12},
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
    /* snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", fault_name); */
    if (unlink(buf) == 0) {
        printf("Successfully removed pinned BPF link: %s\n", buf);
        return; 
    }
    
    fprintf(stderr, "Failed to remove pinned BPF link.\n");
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
    char buf[256]; 
    int key = 0;  
    unsigned char value = 1;
    
    if (fault->type == PT_KPROBE) {
        struct kprobe_bpf *obj = kprobe_bpf__open_and_load(); 

        if (!obj) { 
            fprintf(stderr, "ERROR: Failed to open/load kprobe BPF skeleton: %s\n", strerror(errno));
            return 1; 
        }
        
        if (bpf_map__update_elem(obj->maps.err_map, 
                                &key, 
                                sizeof(key), 
                                &fault->params.kprobe_ERRN, 
                                sizeof(fault->params.kprobe_ERRN), 
                                BPF_ANY) != 0) 
        {
            fprintf(stderr, "ERROR: Failed to update kprobe err_map: %s\n", strerror(errno));   
            kprobe_bpf__destroy(obj); 
            return 1;
        }
        if (bpf_map__update_elem(obj->maps.pid_map,
                                &pid,
                                sizeof(pid),
                                &value,
                                sizeof(value),
                                BPF_ANY) != 0) 
        {
            fprintf(stderr, "ERROR: Failed to update kprobe pid_map: %s\n", strerror(errno));   
            kprobe_bpf__destroy(obj); 
            return 1;
        }
        
        LIBBPF_OPTS(bpf_ksyscall_opts, opts); 
        link = bpf_program__attach_ksyscall(obj->progs.kprobe_handler, fault->syscall, &opts);

        if (libbpf_get_error(link)) { 
            fprintf(stderr, "ERROR: Failed to attach kprobe (via ksyscall) to %s: %s\n", fault->syscall, strerror(errno));
            kprobe_bpf__destroy(obj); 
            return 1;
        }

        snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-kprobe-%s", fault->name); 
        if (bpf_link__pin(link, buf) != 0) {
            fprintf(stderr, "WARN: Failed to pin kprobe link for %s: %s\n", fault->name, strerror(errno));
        } else {
            printf("Pinned kprobe link to %s\n", buf);
        }
        
        bpf_link__destroy(link); 
        kprobe_bpf__destroy(obj); 
        
        printf("Injected kprobe fault '%s' (syscall: %s, errno: %d) into PID %d\n", 
               fault->name, fault->syscall, fault->params.kprobe_ERRN, pid);

    } else if (fault->type == PT_KRETPROBE) {
        fprintf(stderr, "ERROR: Kretprobe fault type for '%s' is defined but not yet implemented.\n", fault->name);
        return 1;
    } else {
        fprintf(stderr, "ERROR: Unknown fault->type defined in registry for fault: %s\n", fault->name);
        return 1;
    }
    
    return 0;
}
