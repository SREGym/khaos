import os
import time
import errno

print("Test: gettimeofday_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import time
            time.time()
    except Exception as e:
        print(f"[gettimeofday_fail] Exception:", e)
    time.sleep(1)
