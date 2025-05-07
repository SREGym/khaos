import os
import time
import errno

print("Test: clock_drift (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import time
            time.clock_gettime(time.CLOCK_REALTIME)
    except Exception as e:
        print(f"[clock_drift] Exception:", e)
    time.sleep(1)
