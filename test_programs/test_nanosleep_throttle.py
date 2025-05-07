import os
import time
import errno

print("Test: nanosleep_throttle (PID: " + str(os.getpid()) + ")")

while True:
    try:
        time.sleep(0.1)
    except Exception as e:
        print(f"[nanosleep_throttle] Exception:", e)
    time.sleep(1)
