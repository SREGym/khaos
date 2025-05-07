import os
import time
import errno

print("Test: dup_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        os.dup(9999)
    except Exception as e:
        print(f"[dup_fail] Exception:", e)
    time.sleep(1)
