import os
import time
import errno

print("Test: brk_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_DATA, (4096, 4096))
    except Exception as e:
        print(f"[brk_fail] Exception:", e)
    time.sleep(1)
