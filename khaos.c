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
      int kprobe_ERRN; // NOTE: Kprobe's Error Code
      long kretprobe_RETV; // NOTE: Kretprobe's Return Value
    } params;
    /* END  */

    /*  /* TODO: DELETE LATER AFTER SUCCESSFUL KROPE MIGEATION */ */
    /* int error_code; */
};

static struct fault_entry fault_registry[] = {
    // KPROBE FAULTS
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
    
    /* // NOTE: Marked to be removed after successful migration */
    /* struct khaos_bpf *obj = khaos_bpf__open_and_load(); */
    /* if (!obj) { */
    /*     fprintf(stderr, "ERROR: Failed to open/load BPF skeleton\n"); */
    /*     return 1; */
    /* } */
    /**/
    /* int key = 0; */
    /* if (bpf_map__update_elem(obj->maps.err_map, &key, sizeof(key), &fault->error_code, sizeof(fault->error_code), 0)) { */
    /*     fprintf(stderr, "ERROR: Failed to update err_map\n"); */
    /*     return 1; */
    /* } */
    /**/
    /* unsigned char value = 1; */
    /* if (bpf_map__update_elem(obj->maps.pid_map, &pid, sizeof(pid), &value, sizeof(value), 0)) { */
    /*     fprintf(stderr, "ERROR: Failed to update pid_map\n"); */
    /*     return 1; */
    /* } */
    /**/
    /* LIBBPF_OPTS(bpf_ksyscall_opts, opts); */
    /* struct bpf_link *link = bpf_program__attach_ksyscall(obj->progs.khaos, fault->syscall, &opts); */
    /* if (libbpf_get_error(link)) { */
    /*     fprintf(stderr, "ERROR: Failed to attach ksyscall to %s\n", fault->syscall); */
    /*     return 1; */
    /* } */
    /**/
    /* char buf[128]; */
    /* snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", fault->name); */
    /* bpf_link__pin(link, buf); */
    /* bpf_link__destroy(link); */
    /* khaos_bpf__destroy(obj); */
    /**/
    /* printf("Injected fault '%s' (syscall: %s, errno: -%d) into PID %d\n", fault->name, fault->syscall, fault->error_code, pid); */
    /* return 0; */
}
