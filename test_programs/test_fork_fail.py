import os
import time
import ctypes

libc = ctypes.CDLL("libc.so.6")
# https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/arch/x86/entry/syscalls/syscall_64.tbl
SYSCALL_FORK = 57

print("Test: fork_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        # Direct fork syscall using syscall()
        # libc.fork() calls clone syscall
        pid = libc.syscall(SYSCALL_FORK)
        if pid == 0:
            os._exit(0)
        if pid < 0:
            print(f"[fork_fail] fork failed")
    except Exception as e:
        print(f"[fork_fail] Exception: {e}")
    time.sleep(1)
