import os
import time

FILE_PATH = "test_file.txt"

def write_and_sync():
    pid = os.getpid()
    print(f"Test program running with PID: {pid}")
    with open(FILE_PATH, "w") as f:
        while True:
            f.flush()
            os.fsync(f.fileno())  # Ensure data is written to disk
            print(f"Flushed data to disk at {time.time()}")
            time.sleep(1)  # Simulating periodic writes

if __name__ == "__main__":
    write_and_sync()
