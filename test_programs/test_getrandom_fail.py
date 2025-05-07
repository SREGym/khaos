import os
import time
import errno

print("Test: getrandom_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        with open('/dev/random', 'rb') as f:
            f.read(1)
    except Exception as e:
        print(f"[getrandom_fail] Exception:", e)
    time.sleep(1)
