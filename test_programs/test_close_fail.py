import os
import time

print("Test: close_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        test_fd = os.open("/dev/null", os.O_RDONLY)
        os.close(test_fd)
        print("[close_fail] Successfully closed fd:", test_fd)
    except Exception as e:
        print(f"[close_fail] Exception:", e)
    time.sleep(1)
