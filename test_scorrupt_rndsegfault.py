import os
import time
import ctypes
import mmap

def main():
    pid = os.getpid()
    print(f"[scorrupt_rndsegfault] test program using mprotect (PID: {pid})")

    libc = ctypes.CDLL("libc.so.6")
    mprotect = libc.mprotect
    mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    mprotect.restype = ctypes.c_int

    # Allocate a writable memory page
    mem = mmap.mmap(-1, mmap.PAGESIZE, access=mmap.ACCESS_WRITE)
    addr = ctypes.addressof(ctypes.c_char.from_buffer(mem))
    was_last_attempt_failed = False

    while True:
        try:
            print("Attempting to set protection to READ-ONLY...")
            ret = mprotect(ctypes.c_void_p(addr), mmap.PAGESIZE, mmap.PROT_READ)

            if ret == 0:
                # This block runs if the primary mprotect call SUCCEEDS
                if was_last_attempt_failed:
                    print("[RECOVERED] Primary mprotect call successful after fault.")
                else:
                    print("[OK] Primary mprotect call succeeded.")
                was_last_attempt_failed = False
                
                # Change it back to READ-WRITE for the next loop.
                # This revert call can ALSO be faulted.
                print("Reverting protection to READ-WRITE for next iteration...")
                revert_ret = mprotect(ctypes.c_void_p(addr), mmap.PAGESIZE, mmap.PROT_READ | mmap.PROT_WRITE)
                if revert_ret != 0:
                    print("[INFO] Revert mprotect call failed. Next test may be masked.")

            else:
                print(f"[FAILED] Primary mprotect call failed with return code: {ret}")
                was_last_attempt_failed = True

        except OSError as e:
            # This is a fallback for certain libc versions that might raise an exception
            print(f"   [FAILED] mprotect failed with exception: {e}")
            was_last_attempt_failed = True
        
        print("-" * 20)
        time.sleep(1)

if __name__ == "__main__":
    main()
