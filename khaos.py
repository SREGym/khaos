'''Python interface to the eBPF program.'''

import argparse
import subprocess
import helpers

def inject_fault(target_syscall, error_code, pids):
    """Inject a fault into specific processes using BPF."""
    command = ["sudo", "./err_inject", target_syscall, str(error_code)] + [str(pid) for pid in pids]
    
    try:
        subprocess.run(command, check=True)
        print(f"Successfully injected fault: {target_syscall} -> {error_code} for PIDs: {pids}")
    except subprocess.CalledProcessError as e:
        print(f"Error injecting fault: {e}")

def recover_fault(target_syscall):
    """Remove BPF programs from eBPF virtual filesystem."""
    bpf_folder_path = f"/sys/fs/bpf/err_inject-{target_syscall}"
    
    try:
        subprocess.run(["sudo", "rm", "-rf", bpf_folder_path], check=True)
        print("Successfully removed BPF fault injector state.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to remove fault state: {e}")

def main():
    parser = argparse.ArgumentParser(description="Fault Injector CLI")
    parser.add_argument("syscall", help="Target syscall to inject fault into (e.g., 'write')")
    parser.add_argument("error_code", type=int, help="Error code to return (-EIO, -EPERM, etc.)")
    parser.add_argument("pids", type=int, nargs="*", help="List of PIDs to target (optional, will auto-detect if not provided)")
    parser.add_argument("--recover", action="store_true", help="Recover by removing injected faults")

    args = parser.parse_args()

    if args.recover:
        recover_fault(args.syscall)
    else:
        # Use provided PIDs or automatically find the test program's PID
        pids = args.pids if args.pids else helpers.get_pids_by_name("test_program.py")
        
        if not pids:
            print("Error: No matching process found.")
            return
        
        inject_fault(args.syscall, -abs(args.error_code), pids)

if __name__ == "__main__":
    main()
