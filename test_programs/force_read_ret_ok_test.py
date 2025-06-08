import os
import time

FILENAME = "test_read_file.txt"
CONTENT = "This is a line of test data that should be readable."

def main():
    """
    This program creates a file with content, then repeatedly tries to read it.
    The 'force_read_ret_ok' kretprobe fault will force os.read() to return 0 bytes,
    simulating an unexpected End-Of-File.
    """
    print(f"Test: force_read_ret_ok (PID: {os.getpid()})")

    with open(FILENAME, "w") as f:
        f.write(CONTENT)
    print(f"Created '{FILENAME}' with {len(CONTENT)} bytes of data.")

    try:
        while True:
            fd = os.open(FILENAME, os.O_RDONLY)
            
            try:
                data_read = os.read(fd, 128)
                num_bytes_read = len(data_read)

                if num_bytes_read > 0:
                    print(f"[SUCCESS] Successfully read {num_bytes_read} bytes: {data_read.decode('utf-8')}")
                else:
                    print(f"[ERROR] read() returned 0 bytes (EOF), but file should have data.")

            except OSError as e:
                print(f"[UNEXPECTED] Caught an OSError: {e}")
            finally:
                os.close(fd) 

            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nProgram Exited.")
    finally:
        if os.path.exists(FILENAME):
            os.remove(FILENAME)

if __name__ == "__main__":
    main()
