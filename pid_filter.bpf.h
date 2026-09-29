#ifndef KHAOS_PID_FILTER_BPF_H
#define KHAOS_PID_FILTER_BPF_H

#include "pid_namespace.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct khaos_pid_namespace);
    __uint(max_entries, 1);
} pid_namespace_map SEC(".maps");

static __always_inline int khaos_current_pid(void)
{
    int key = 0;
    struct bpf_pidns_info info = {};
    struct khaos_pid_namespace *pid_namespace;

    pid_namespace = bpf_map_lookup_elem(&pid_namespace_map, &key);
    if (!pid_namespace || !pid_namespace->dev || !pid_namespace->ino)
        return 0;

    if (bpf_get_ns_current_pid_tgid(pid_namespace->dev, pid_namespace->ino,
                                   &info, sizeof(info)) != 0)
        return 0;

    /* SREGym discovers a container's process ID, so match every thread in it. */
    return info.tgid;
}

#endif
