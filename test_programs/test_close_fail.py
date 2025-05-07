import os
import time
import errno

print("Test: close_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        os.close(-1)
    except Exception as e:
        print(f"[close_fail] Exception:", e)
    time.sleep(1)
