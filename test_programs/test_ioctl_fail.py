import os
import time
import errno

print("Test: ioctl_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import fcntl
            with open('/dev/null', 'rb') as f:
                fcntl.ioctl(f, 0x1234, 'data')
    except Exception as e:
        print(f"[ioctl_fail] Exception:", e)
    time.sleep(1)
