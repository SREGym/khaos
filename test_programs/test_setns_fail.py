import os
import time
import errno

print("Test: setns_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import ctypes
            libc = ctypes.CDLL('libc.so.6')
            libc.setns(0, 0)
    except Exception as e:
        print(f"[setns_fail] Exception:", e)
    time.sleep(1)
