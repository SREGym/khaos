#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct  {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, long);
  __uint(max_entries, 1);
} ret_val_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, unsigned char);
  __uint(max_entries, 256);
} pid_map SEC(".maps");

SEC("kretprobe/")
int kretprobe_handler(struct pt_regs *ctx) {
  int pid = bpf_get_current_pid_tgid() & 0xffffffff;
  int key = 0;
  long *forced_ret_val;
  if (!bpf_map_lookup_elem(&pid_map, &pid))
    return 0;

  forced_ret_val = bpf_map_lookup_elem(&ret_val_map, &key);
  if (!forced_ret_val)
    return 0;

  bpf_override_return(ctx, *forced_ret_val);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
