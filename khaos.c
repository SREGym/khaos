#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

/* // TODO: Remove later after including skel of kprobe and kretprobe */
/* #include "khaos.skel.h" */

// Include skeletons in main khaos.c 
#include "kprobe.skel.h"


// Define probe types
enum probe_type {
  PT_KPROBE,
  PT_KRETPROBE
};

struct fault_entry {
    const char *name;
    const char *syscall;
    /* NEWLY ADDED CODE FOR DIFFERENT FAULTS  */
    enum probe_type type; 
    union {
      int kprobe_error_code;
      long kretprobe_return_value;
    } params;
    /* END  */

    /*  /* TODO: DELETE LATER AFTER SUCCESSFUL KROPE MIGEATION */ */
    /* int error_code; */
};

static struct fault_entry fault_registry[] = {
    // KPROBE FAULTS
    {"read_error",          "read",          -5},
    {"write_error",         "write",         -28},
    {"fsync_error",         "fsync",         -5},
    {"open_error",          "openat",        -13},
    {"close_fail",          "close",         -9},
    {"dup_fail",            "dup",           -24},
    {"mmap_fail",           "mmap",          -12},
    {"mmap_oom",            "mmap",          -12},
    {"brk_fail",            "brk",           -12},
    {"mlock_fail",          "mlock",         -12},
    {"getrandom_fail",      "getrandom",     -11},
    {"gettimeofday_fail",   "gettimeofday",   -1},
    {"ioctl_fail",          "ioctl",         -25},
    {"cuda_malloc_fail",    "ioctl",         -12},
    {"getaddrinfo_fail",    "recvfrom",       -1},
    {"nanosleep_throttle",  "nanosleep",      -5},
    {"nanosleep_interrupt", "nanosleep",      -4},
    {"fork_fail",           "fork",          -11},
    {"clock_drift",         "clock_gettime",  -5},
    {"setns_fail",          "setns",          -1},
    {"prlimit_fail",        "prlimit64",      -1},
    {"socket_block",        "socket",         -1},
    // KRETPOBE FAULTS
};

#define NUM_FAULTS (sizeof(fault_registry) / sizeof(fault_registry[0]))

const struct fault_entry* find_fault(const char *name) {
    for (int i = 0; i < NUM_FAULTS; ++i) {
        if (strcmp(name, fault_registry[i].name) == 0)
            return &fault_registry[i];
    }
    return NULL;
}

void recover_fault(const char *fault_name) {
    char buf[128];
    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", fault_name);
    if (unlink(buf) == 0)
        printf("Successfully removed pinned BPF link: %s\n", buf);
    else
        perror("Failed to remove pinned BPF link");
    // NOTE: Optional: We could open maps and clear them here
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
        recover_fault(argv[2]);
        return 0;
    }

    const struct fault_entry *fault = find_fault(argv[1]);
    if (!fault) {
        fprintf(stderr, "ERROR: Unknown fault type: %s\n", argv[1]);
        return 1;
    }
    int pid = atoi(argv[2]);

    struct khaos_bpf *obj = khaos_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "ERROR: Failed to open/load BPF skeleton\n");
        return 1;
    }

    int key = 0;
    if (bpf_map__update_elem(obj->maps.err_map, &key, sizeof(key), &fault->error_code, sizeof(fault->error_code), 0)) {
        fprintf(stderr, "ERROR: Failed to update err_map\n");
        return 1;
    }

    unsigned char value = 1;
    if (bpf_map__update_elem(obj->maps.pid_map, &pid, sizeof(pid), &value, sizeof(value), 0)) {
        fprintf(stderr, "ERROR: Failed to update pid_map\n");
        return 1;
    }

    LIBBPF_OPTS(bpf_ksyscall_opts, opts);
    struct bpf_link *link = bpf_program__attach_ksyscall(obj->progs.khaos, fault->syscall, &opts);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: Failed to attach ksyscall to %s\n", fault->syscall);
        return 1;
    }

    char buf[128];
    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", fault->name);
    bpf_link__pin(link, buf);
    bpf_link__destroy(link);
    khaos_bpf__destroy(obj);

    printf("Injected fault '%s' (syscall: %s, errno: -%d) into PID %d\n", fault->name, fault->syscall, fault->error_code, pid);
    return 0;
}
