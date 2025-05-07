import os
import time
import errno

print("Test: mlock_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import ctypes
            libc = ctypes.CDLL('libc.so.6')
            buf = ctypes.create_string_buffer(4096)
            libc.mlock(buf, 4096)
    except Exception as e:
        print(f"[mlock_fail] Exception:", e)
    time.sleep(1)
