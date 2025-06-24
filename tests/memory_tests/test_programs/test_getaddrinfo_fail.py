import os
import time
import errno

print("Test: getaddrinfo_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import socket

        socket.getaddrinfo("www.google.com", 80)
    except Exception as e:
        print(f"[getaddrinfo_fail] Exception:", e)
    time.sleep(1)
