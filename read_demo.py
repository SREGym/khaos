'''Simple demonstration program, run this then grab the PID to do fault injection'''

import os
import time
import datetime

def read_file_continuously():
    pid = os.getpid()
    print(f"Test program running with PID: {pid}")

    # Ensure test_file.txt exists before opening
    if not os.path.exists("test_file.txt"):
        with open("test_file.txt", "w") as f:
            f.write("Initial test data\n")

    with open("test_file.txt", "r") as f:
        while True:
            f.seek(0)
            content = f.read()
            print(f"Time: {datetime.datetime.now()} Read {len(content)} bytes from file.")
            time.sleep(1)  # Simulate some delay between reads

if __name__ == "__main__":
    read_file_continuously()
