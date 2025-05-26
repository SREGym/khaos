import os
import time
import errno

print("Test: getrandom_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        os.getrandom(1, 0)
    except Exception as e:
        print(f"[getrandom_fail] Exception:", e)
    time.sleep(1)
