import os
import time
import errno

print("Test: fsync_error (PID: " + str(os.getpid()) + ")")

while True:
    try:
        with open("testfile.txt", "a") as f:
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[fsync_error] Exception:", e)
    time.sleep(1)
