#!/usr/bin/env python3

import os
import sys
import time
import signal
import errno
from pathlib import Path

FILENAME = "block_read_test_file.txt"
BLOCK_SIZE = 512

def cleanup(signum=None, frame=None):
    """Cleanup function to remove test file"""
    try:
        Path(FILENAME).unlink(missing_ok=True)
        print("\n[block_read_error test] Cleanup completed")
    except Exception as e:
        print(f"\n[block_read_error test] Cleanup error: {e}")
    sys.exit(0)

def create_test_file():
    """Create a test file with 8 blocks (4KB) of data"""
    block_data = (
        "This is block data for testing block-specific read errors. "
        "Each block is 512 bytes and we need multiple blocks to test "
        "the block range functionality properly. This data will be "
        "repeated to fill up the blocks with meaningful content that "
        "can help us verify that the eBPF program is working correctly. "
        "Block boundaries are important for disk I/O operations and "
        "latent sector errors typically occur at specific block ranges. "
        "The MongoDB use case requires testing how the database handles "
        "EIO errors when specific disk blocks become unreadable due to "
        "hardware issues or sector failures on the storage device."
    )

    try:
        with open(FILENAME, 'wb') as f:
            # Write 8 blocks (4KB total) of data
            for i in range(8):
                block_content = f"[Block {i}] {block_data}"

                # Pad to exactly 512 bytes
                if len(block_content) < 511:
                    block_content += 'X' * (511 - len(block_content))
                elif len(block_content) > 511:
                    block_content = block_content[:511]

                block_content += '\n'  # Make it exactly 512 bytes

                f.write(block_content.encode('utf-8'))

        print(f"[block_read_error test] Created test file with 8 blocks (4KB)")
        return True

    except Exception as e:
        print(f"Failed to create test file: {e}")
        return False

def read_block_range(fd, offset, size, description):
    """Read a specific block range and return success/failure info"""
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        data = os.read(fd, size)

        return {
            'success': True,
            'data': data,
            'bytes_read': len(data),
            'error': None
        }

    except OSError as e:
        return {
            'success': False,
            'data': None,
            'bytes_read': 0,
            'error': e,
            'errno': e.errno
        }

def main():
    print(f"[block_read_error test] Running with PID: {os.getpid()}")

    # Set up signal handlers
    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Create test file
    if not create_test_file():
        return 1

    # Open file for reading
    try:
        fd = os.open(FILENAME, os.O_RDONLY)
    except Exception as e:
        print(f"Failed to open test file for reading: {e}")
        cleanup()
        return 1

    print("[block_read_error test] Testing various block range reads...")
    print("[block_read_error test] Use Ctrl+C to stop the test")
    print()

    # Define test cases
    test_cases = [
        (0, 512, "Block 0 (offset 0-511)"),
        (512, 512, "Block 1 (offset 512-1023)"),
        (1024, 512, "Block 2 (offset 1024-1535)"),
        (1536, 512, "Block 3 (offset 1536-2047)"),
        (2048, 512, "Block 4 (offset 2048-2559)"),
        (2560, 512, "Block 5 (offset 2560-3071)"),
        (3072, 512, "Block 6 (offset 3072-3583)"),
        (3584, 512, "Block 7 (offset 3584-4095)"),
        (0, 1024, "Blocks 0-1 (offset 0-1023)"),
        (1024, 1024, "Blocks 2-3 (offset 1024-2047)"),
        (2048, 2048, "Blocks 4-7 (offset 2048-4095)")
    ]

    test_count = 0

    try:
        while True:
            test_count += 1
            print(f"--- Test {test_count} ---")

            # Cycle through test cases
            test_idx = (test_count - 1) % len(test_cases)
            offset, size, description = test_cases[test_idx]

            print(f"Reading {description}: ", end='', flush=True)

            result = read_block_range(fd, offset, size, description)

            if result['success']:
                print(f"SUCCESS - Read {result['bytes_read']} bytes")
                if result['data']:
                    # Show first 60 characters of read data
                    preview = result['data'][:60].decode('utf-8', errors='replace')
                    # Replace newlines with spaces for display
                    preview = preview.replace('\n', ' ')
                    print(f"  -> Data preview: \"{preview}\"")
            else:
                error = result['error']
                print(f"ERROR - {error} (errno={result['errno']})")
                if result['errno'] == errno.EIO:
                    print("  -> EIO detected - block range fault injection working!")

            print()
            time.sleep(2)

    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.close(fd)
        except:
            pass
        cleanup()

    return 0

if __name__ == '__main__':
    sys.exit(main())