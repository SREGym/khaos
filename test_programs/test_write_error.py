import os
import time
import errno

print("Test: write_error (PID: " + str(os.getpid()) + ")")

while True:
    try:
        os.write(1, b"test write\n")
    except Exception as e:
        print(f"[write_error] Exception:", e)
    time.sleep(1)
