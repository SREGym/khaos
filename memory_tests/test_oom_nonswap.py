import os
import time
import ctypes

def main():
    pid = os.getpid()
    print(f"Test [oom_nonswap] for using mlock (PID: {pid})")

    libc = ctypes.CDLL("libc.so.6")
    mlock = libc.mlock
    mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    mlock.restype = ctypes.c_int

    buf = ctypes.create_string_buffer(4096)
    was_last_attempt_failed = False

    while True:
        result = mlock(buf, 4096)
        if result == 0:
            if was_last_attempt_failed:
                print("[RECOVERED] mlock successful after fault.")
            else:
                print("[OK] mlock successful.")
            was_last_attempt_failed = False
            libc.munlock(buf, 4096)
        else:
            # CORRECTED: Report the raw return code from mlock() instead of errno.
            # A return of -1 indicates failure.
            print(f"[FAILED] mlock call failed with return code: {result}")
            was_last_attempt_failed = True
        time.sleep(1)

if __name__ == "__main__":
    main()
