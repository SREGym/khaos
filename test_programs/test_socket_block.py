import os
import time
import errno

print("Test: socket_block (PID: " + str(os.getpid()) + ")")

while True:
    try:
        import socket
            s = socket.socket()
    except Exception as e:
        print(f"[socket_block] Exception:", e)
    time.sleep(1)
