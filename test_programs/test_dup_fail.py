import os
import time
import ctypes

libc = ctypes.CDLL("libc.so.6")

print("Test: dup_fail (PID: " + str(os.getpid()) + ")")
test_fd = os.open("/dev/null", os.O_RDONLY)
while True:
    try:
        new_fd = libc.dup(test_fd)
        if new_fd == -1:
            print(f"[dup_fail] dup failed")
        else:
            os.close(new_fd)
    except Exception as e:
        print(f"[dup_fail] Exception:", e)
    time.sleep(1)
