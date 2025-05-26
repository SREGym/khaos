import os
import time

print("Test: mlock_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6")
        buf = ctypes.create_string_buffer(4096)
        result = libc.mlock(buf, 4096)
        if result < 0:
            print(f"[mlock_fail] mlock failed")
    except Exception as e:
        print(f"[mlock_fail] Exception:", e)
    time.sleep(1)
