import os
import time
import errno

print("Test: cuda_malloc_fail (PID: " + str(os.getpid()) + ")")

while True:
    try:
        print('Simulating CUDA malloc fail — no-op in Python')
    except Exception as e:
        print(f"[cuda_malloc_fail] Exception:", e)
    time.sleep(1)
