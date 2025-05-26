import os
import time
import errno

print("Test: mmap_oom (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import mmap

        mmap.mmap(-1, 1 << 30)
    except Exception as e:
        print(f"[mmap_oom] Exception:", e)
    time.sleep(1)
