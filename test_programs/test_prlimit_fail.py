import os
import time
import errno

print("Test: prlimit_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import resource
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    except Exception as e:
        print(f"[prlimit_fail] Exception:", e)
    time.sleep(1)
