import os
import time

print("Test: mmap_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import mmap

        mmap.mmap(-1, 4096)
    except Exception as e:
        print(f"[mmap_fail] Exception:", e)
    time.sleep(1)
