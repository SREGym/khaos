#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct  {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, long);
  __type(max_entries, 1);
} ret_val_map SEC(".maps");
