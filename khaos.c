#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

struct fault_entry {
    char *fault_name;
    char *bpf_file;
};

static struct fault_entry fault_map[] = {
    {"read_error", "faults/read_error.bpf.o"},
    {"fsync_error", "faults/fsync_error.bpf.o"},
    {"write_error", "faults/write_error.bpf.o"},
    {"mmap_oom", "faults/mmap_oom.bpf.o"},
    {"mmap_fail", "faults/mmap_fail.bpf.o"},
    {"open_error", "faults/open_error.bpf.o"},
    {"close_fail", "faults/close_fail.bpf.o"},
    {"dup_fail", "faults/dup_fail.bpf.o"},
    {"socket_block", "faults/socket_block.bpf.o"},
    {"ioctl_fail", "faults/ioctl_fail.bpf.o"},
    {"nanosleep_throttle", "faults/nanosleep_throttle.bpf.o"},
    {"nanosleep_interrupt", "faults/nanosleep_interrupt.bpf.o"},
    {"fork_fail", "faults/fork_fail.bpf.o"},
    {"clock_drift", "faults/clock_drift.bpf.o"},
    {"brk_fail", "faults/brk_fail.bpf.o"},
    {"mlock_fail", "faults/mlock_fail.bpf.o"},
    {"gettimeofday_fail", "faults/gettimeofday_fail.bpf.o"},
    {"getrandom_fail", "faults/getrandom_fail.bpf.o"},
    {"setns_fail", "faults/setns_fail.bpf.o"},
    {"prlimit_fail", "faults/prlimit_fail.bpf.o"},
    {"getaddrinfo_fail", "faults/getaddrinfo_fail.bpf.o"},
    {"cuda_malloc_fail", "faults/cuda_malloc_fail.bpf.o"},
};



#define NUM_FAULTS (sizeof(fault_map) / sizeof(fault_map[0]))

// FIXME: We need to update this to delete with the new names
void recover_fault(const char *fault_name) {
    char buf[128] = {0};

    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", fault_name);
    if (unlink(buf) == 0) {
        printf("Successfully removed pinned BPF link: %s\n", buf);
    } else {
        perror("Failed to remove pinned BPF link");
    }

    struct bpf_object *obj = bpf_object__open(fault_name);
    if (!obj) {
        fprintf(stderr, "ERROR: Failed to open BPF object for recovery.\n");
        return;
    }

    struct bpf_map *pid_map = bpf_object__find_map_by_name(obj, "pid_map");
    struct bpf_map *err_map = bpf_object__find_map_by_name(obj, "err_map");
    if (!pid_map || !err_map) {
        fprintf(stderr, "ERROR: Could not find maps.\n");
        return;
    }

    int key = 0;
    int zero = 0;

    if (bpf_map__update_elem(err_map, &key, sizeof(key), &zero, sizeof(zero), 0)) {
        fprintf(stderr, "ERROR: Failed to reset err_map.\n");
    }

    int pid_key, next_key;
    while (bpf_map__get_next_key(pid_map, &pid_key, &next_key, sizeof(int)) == 0) {
        if (bpf_map__delete_elem(pid_map, &pid_key, sizeof(int), 0)) {
            fprintf(stderr, "ERROR: Failed to delete PID %d from pid_map.\n", pid_key);
        }
        pid_key = next_key;
    }

    bpf_object__close(obj);
    printf("Fault injection successfully recovered.\n");
}

int main(int argc, char *argv[]) {
    if (getuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (use 'sudo').\n");
        return 1;
    }

    if (argc < 3) {
        fprintf(stderr, "Usage: %s <fault_type> <pid> | --recover <fault_type>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--recover") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --recover <fault_type>\n", argv[0]);
            return 1;
        }
        recover_fault(argv[2]);
        return 0;
    }

    char *fault_type = argv[1];
    int pid = atoi(argv[2]);

    struct fault_entry *selected_fault = NULL;
    for (int i = 0; i < NUM_FAULTS; i++) {
        if (strcmp(fault_map[i].fault_name, fault_type) == 0) {
            selected_fault = &fault_map[i];
            break;
        }
    }

    if (!selected_fault) {
        fprintf(stderr, "ERROR: Invalid fault type: %s\n", fault_type);
        return 1;
    }

    struct bpf_object *obj = bpf_object__open(selected_fault->bpf_file);
    if (!obj) {
        fprintf(stderr, "ERROR: Failed to open BPF program %s\n", selected_fault->bpf_file);
        return 1;
    }

    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: Failed to load BPF program\n");
        return 1;
    }

    struct bpf_map *pid_map = bpf_object__find_map_by_name(obj, "pid_map");
    if (!pid_map) {
        fprintf(stderr, "ERROR: Could not find required pid_map in BPF program.\n");
        return 1;
    }

    unsigned char value = 1;
    if (bpf_map_update_elem(bpf_map__fd(pid_map), &pid, &value, BPF_ANY)) {
        fprintf(stderr, "ERROR: Failed to insert PID %d into pid_map.\n", pid);
        return 1;
    }

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "ERROR: Could not find a BPF program in object file.\n");
        return 1;
    }

    struct bpf_link *link = bpf_program__attach(prog);
    if (!link) {
        fprintf(stderr, "ERROR: Failed to attach BPF program to kprobe.\n");
        return 1;
    }

    printf("Injected fault: %s on PID %d\n", fault_type, pid);
    return 0;
    // NOTE: Seems like the issue is with loading the BPF program and linking it, let's make sure we have all those steps
    // from the workign khaos.c on GitHub implemented. We should create the logic and load it, and attach it.
}