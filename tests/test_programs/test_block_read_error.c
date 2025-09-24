#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

static const char *filename = "block_read_test_file.txt";
static int fd = -1;

void cleanup(int signum) {
    if (fd != -1) {
        close(fd);
    }
    unlink(filename);
    printf("\n[block_read_error test] Cleanup completed\n");
    exit(EXIT_SUCCESS);
}

int main() {
    printf("[block_read_error test] Running with PID: %d\n", getpid());

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // Create test file with known data
    int tmpfd = open(filename, O_RDWR | O_CREAT, 0644);
    if (tmpfd < 0) {
        perror("Failed to create test file");
        return 1;
    }

    // Write test data - create a file with at least 4KB of data (8 blocks of 512 bytes)
    const char *block_data =
        "This is block data for testing block-specific read errors. "
        "Each block is 512 bytes and we need multiple blocks to test "
        "the block range functionality properly. This data will be "
        "repeated to fill up the blocks with meaningful content that "
        "can help us verify that the eBPF program is working correctly. "
        "Block boundaries are important for disk I/O operations and "
        "latent sector errors typically occur at specific block ranges. "
        "The MongoDB use case requires testing how the database handles "
        "EIO errors when specific disk blocks become unreadable due to "
        "hardware issues or sector failures on the storage device.";

    // Write 8 blocks (4KB total) of data
    for (int i = 0; i < 8; i++) {
        char block[512];
        snprintf(block, sizeof(block), "[Block %d] %s", i, block_data);
        // Pad to 512 bytes
        int len = strlen(block);
        memset(block + len, 'X', 512 - len - 1);
        block[511] = '\n';

        if (write(tmpfd, block, 512) != 512) {
            perror("Failed to write block data");
            close(tmpfd);
            unlink(filename);
            return 1;
        }
    }
    close(tmpfd);

    // Open file for reading
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open test file for reading");
        unlink(filename);
        return 1;
    }

    printf("[block_read_error test] Created test file with 8 blocks (4KB)\n");
    printf("[block_read_error test] Testing various block range reads...\n");
    printf("[block_read_error test] Use Ctrl+C to stop the test\n\n");

    char buf[512];
    int test_count = 0;

    while (1) {
        test_count++;
        printf("--- Test %d ---\n", test_count);

        // Test different block ranges
        struct {
            off_t offset;
            size_t size;
            const char *description;
        } test_cases[] = {
            {0, 512, "Block 0 (offset 0-511)"},
            {512, 512, "Block 1 (offset 512-1023)"},
            {1024, 512, "Block 2 (offset 1024-1535)"},
            {1536, 512, "Block 3 (offset 1536-2047)"},
            {2048, 512, "Block 4 (offset 2048-2559)"},
            {2560, 512, "Block 5 (offset 2560-3071)"},
            {3072, 512, "Block 6 (offset 3072-3583)"},
            {3584, 512, "Block 7 (offset 3584-4095)"},
            {0, 1024, "Blocks 0-1 (offset 0-1023)"},
            {1024, 1024, "Blocks 2-3 (offset 1024-2047)"},
            {2048, 2048, "Blocks 4-7 (offset 2048-4095)"}
        };

        int num_tests = sizeof(test_cases) / sizeof(test_cases[0]);
        int test_idx = (test_count - 1) % num_tests;

        off_t offset = test_cases[test_idx].offset;
        size_t size = test_cases[test_idx].size;
        const char *desc = test_cases[test_idx].description;

        printf("Reading %s: ", desc);
        fflush(stdout);

        ssize_t n = pread(fd, buf, size, offset);

        if (n < 0) {
            printf("ERROR - %s (errno=%d)\n", strerror(errno), errno);
            if (errno == EIO) {
                printf("  -> EIO detected - block range fault injection working!\n");
            }
        } else {
            printf("SUCCESS - Read %zd bytes\n", n);
            if (n > 0) {
                // Show first 60 characters of read data
                char preview[61];
                int preview_len = (n < 60) ? n : 60;
                memcpy(preview, buf, preview_len);
                preview[preview_len] = '\0';
                // Replace newlines with spaces for display
                for (int i = 0; i < preview_len; i++) {
                    if (preview[i] == '\n') preview[i] = ' ';
                }
                printf("  -> Data preview: \"%.60s\"\n", preview);
            }
        }

        printf("\n");
        sleep(2);
    }

    return EXIT_SUCCESS;
}