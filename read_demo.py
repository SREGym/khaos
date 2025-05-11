import os
import time
import datetime

def read_file_continuously():
    pid = os.getpid()
    print(f"Test program running with PID: {pid}")

    # Ensure the file exists
    if not os.path.exists("test_file.txt"):
        with open("test_file.txt", "w") as f:
            f.write("Initial test data\n")

    with open("test_file.txt", "r") as f:
        while True:
            try:
                f.seek(0)
                content = f.read()
                print(f"[{datetime.datetime.now()}] Read {len(content)} bytes: {repr(content)}")
            except OSError as e:
                print(f"[{datetime.datetime.now()}] ⚠️ OSError caught during read: {e} (errno={e.errno})")
            time.sleep(1)

if __name__ == "__main__":
    read_file_continuously()
