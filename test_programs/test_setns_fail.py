import os
import time
import errno

# Run with sudo

print("Test: setns_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import ctypes

        libc = ctypes.CDLL("libc.so.6")

        ns_path = f"/proc/self/ns/net"
        fd = os.open(ns_path, os.O_RDONLY)

        result = libc.setns(fd, 0)
        if result < 0:
            print(f"[setns_fail] setns failed")

        os.close(fd)
    except Exception as e:
        print(f"[setns_fail] Exception:", e)
    time.sleep(1)
