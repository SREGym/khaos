import os
import time

print("Test [MEMORY]: oom_memchunk (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import mmap

        mmap.mmap(-1, 1 << 30)
    except Exception as e:
        print(f"[oom_memchunk] Memory Exception:", e)
    time.sleep(1)
