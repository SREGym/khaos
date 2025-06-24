import os
import time

print("Test [MEMORY]: hfrag_memchunk syscall (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import mmap

        mmap.mmap(-1, 1 << 30)
    except Exception as e:
        print(f"[hfrag_memchunk] Memory Exception:", e)
    time.sleep(1)
