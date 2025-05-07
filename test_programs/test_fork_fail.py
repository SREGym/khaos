import os
import time
import errno

print("Test: fork_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        os.fork()
    except Exception as e:
        print(f"[fork_fail] Exception:", e)
    time.sleep(1)
