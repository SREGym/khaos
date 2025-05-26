import os
import time
import errno

print("Test: open_error (PID: " + str(os.getpid()) + ")")

while True:
    try:
        os.open("/dev/null", os.O_RDONLY)
    except Exception as e:
        print(f"[open_error] Exception:", e)
    time.sleep(1)
