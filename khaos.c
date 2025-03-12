#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "khaos.skel.h"

void recover_fault(const char *target_syscall) {
    char buf[128] = {0};

    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", target_syscall);
    if (unlink(buf) == 0) {
        printf("Successfully removed pinned BPF link: %s\n", buf);
    } else {
        perror("Failed to remove pinned BPF link");
    }

    struct khaos_bpf *obj = khaos_bpf__open_and_load();
    if (!obj) {
        fprintf(stderr, "ERROR: Failed to open BPF object for recovery.\n");
        return;
    }

    int key = 0;
    int zero = 0;

    if (bpf_map__update_elem(obj->maps.err_map, &key, sizeof(key), &zero, sizeof(zero), 0)) {
        fprintf(stderr, "ERROR: Failed to reset err_map.\n");
    }

    struct bpf_map *pid_map = obj->maps.pid_map;
    int pid_key, next_key;
    while (bpf_map__get_next_key(pid_map, &pid_key, &next_key, sizeof(int)) == 0) {
        if (bpf_map__delete_elem(pid_map, &pid_key, sizeof(int), 0)) {  // <-- Fixed here
            fprintf(stderr, "ERROR: Failed to delete PID %d from pid_map.\n", pid_key);
        }
        pid_key = next_key;
    }

    khaos_bpf__destroy(obj);
    printf("Fault injection successfully recovered.\n");
}


int main(int argc, char *argv[]) {
	if (getuid() != 0) {
        fprintf(stderr, "ERROR: This program must be run as root (use 'sudo').\n");
        return 1;
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <syscall> <error_code> <pid> [<pid2> ...] | --recover <syscall>\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--recover") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s --recover <syscall>\n", argv[0]);
            return 1;
        }
        recover_fault(argv[2]);
        return 0;
    }

    char *target_syscall = argv[1];
    int err_code = -atoi(argv[2]);
    int nr_pids = argc - 3;
    int *pids = calloc(sizeof(int), nr_pids);
    int key = 0, ret = 0;
    unsigned char value = 0;
    char buf[128] = {0};
    struct khaos_bpf *obj;
    struct bpf_link *link;
    LIBBPF_OPTS(bpf_ksyscall_opts, opts);

    for (int i = 0; i < nr_pids; i++) {
        pids[i] = atoi(argv[i + 3]);
    }

    obj = khaos_bpf__open_and_load();
    if (!obj) {
        return 1;
    }

    if (bpf_map__update_elem(obj->maps.err_map, &key, sizeof(key), &err_code, sizeof(err_code), 0)) {
        fprintf(stderr, "ERROR: updating err_map failed\n");
        ret = 1;
        goto cleanup;
    }

    for (int i = 0; i < nr_pids; i++) {
        if (bpf_map__update_elem(obj->maps.pid_map, &pids[i], sizeof(pids[i]), &value, sizeof(value), 0)) {
            fprintf(stderr, "ERROR: updating pid_map failed\n");
            ret = 1;
            goto cleanup;
        }
    }

    link = bpf_program__attach_ksyscall(obj->progs.khaos, target_syscall, &opts);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "ERROR: bpf_program__attach failed\n");
        link = NULL;
        ret = 1;
        goto cleanup;
    }

    snprintf(buf, sizeof(buf), "/sys/fs/bpf/khaos-%s", target_syscall);
    bpf_link__pin(link, buf);
    bpf_link__destroy(link);

cleanup:
    khaos_bpf__destroy(obj);
    return ret;
}
