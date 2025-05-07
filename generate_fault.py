import os
import argparse

TEMPLATE = """\
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>

struct {{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, int);
    __type(value, unsigned char);
    __uint(max_entries, 256);
}} pid_map SEC(".maps");

SEC("kprobe/{syscall}")
int {fault_name}(struct pt_regs *ctx) {{
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (!bpf_map_lookup_elem(&pid_map, &pid))
        return 0;

    return -{error_code};
}}

char LICENSE[] SEC("license") = "GPL";
"""

def generate_fault_file(fault_name, syscall, error_code, output_dir="faults"):
    os.makedirs(output_dir, exist_ok=True)
    filename = f"{output_dir}/{fault_name}.bpf.c"
    code = TEMPLATE.format(fault_name=fault_name, syscall=syscall, error_code=error_code)

    with open(filename, "w") as f:
        f.write(code)

    print(f"✅ Generated: {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate an eBPF override-return fault injector.")
    parser.add_argument("fault_name", help="Name of the fault (used for function and file name)")
    parser.add_argument("syscall", help="Syscall name to hook (e.g., fork, write, ioctl)")
    parser.add_argument("error_code", help="Error code to return (e.g., EIO = 5, ENOMEM = 12)")

    args = parser.parse_args()
    generate_fault_file(args.fault_name, args.syscall, args.error_code)
