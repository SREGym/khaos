#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

static const char *filename = "latent_sector_test_file.txt";
static int fd = -1;
static int success_count = 0;
static int error_count = 0;
static int total_operations = 0;

void cleanup(int signum) {
    if (fd >= 0) {
        close(fd);
    }
    unlink(filename);

    printf("\n[latent_sector_error test] Final Statistics:\n");
    printf("  Total operations: %d\n", total_operations);
    printf("  Successful reads: %d (%.1f%%)\n", success_count,
           total_operations > 0 ? (100.0 * success_count / total_operations) : 0.0);
    printf("  Failed reads:     %d (%.1f%%)\n", error_count,
           total_operations > 0 ? (100.0 * error_count / total_operations) : 0.0);

    exit(EXIT_SUCCESS);
}

void create_test_file() {
    // Create test file with some data to read
    int tmpfd = open(filename, O_RDWR | O_CREAT, 0644);
    if (tmpfd < 0) {
        perror("Failed to create test file");
        exit(EXIT_FAILURE);
    }

    // Write test data - multiple sectors worth
    const char *test_data = "LATENT_SECTOR_ERROR_TEST_DATA_";
    for (int i = 0; i < 100; i++) {
        ssize_t written = write(tmpfd, test_data, strlen(test_data));
        if (written < 0) {
            perror("Failed to write test data");
            close(tmpfd);
            exit(EXIT_FAILURE);
        }
    }

    close(tmpfd);
}

int perform_read_test(int use_pread, off_t offset) {
    char buf[64];
    ssize_t n;

    if (use_pread) {
        n = pread(fd, buf, sizeof(buf), offset);
    } else {
        n = read(fd, buf, sizeof(buf));
    }

    total_operations++;

    if (n < 0) {
        error_count++;
        if (errno == EIO) {
            printf("[latent_sector_error test] %s FAILED with EIO (errno=%d) - injected error!\n",
                   use_pread ? "pread64" : "read", errno);
        } else {
            printf("[latent_sector_error test] %s FAILED with unexpected error: %s (errno=%d)\n",
                   use_pread ? "pread64" : "read", strerror(errno), errno);
        }
        return 0;
    } else {
        success_count++;
        printf("[latent_sector_error test] %s SUCCESS: read %zd bytes\n",
               use_pread ? "pread64" : "read", n);
        return 1;
    }
}

int main(int argc, char *argv[]) {
    int test_duration = 30;  // Default 30 seconds
    int error_rate = 50;     // Default expected error rate

    if (argc >= 2) {
        test_duration = atoi(argv[1]);
        if (test_duration <= 0) test_duration = 30;
    }

    if (argc >= 3) {
        error_rate = atoi(argv[2]);
        if (error_rate < 0) error_rate = 0;
        if (error_rate > 100) error_rate = 100;
    }

    printf("[latent_sector_error test] Running with PID: %d\n", getpid());
    printf("[latent_sector_error test] Test duration: %d seconds\n", test_duration);
    printf("[latent_sector_error test] Expected error rate: %d%%\n", error_rate);
    printf("[latent_sector_error test] This test exercises both read() and pread64() syscalls\n");
    printf("[latent_sector_error test] Press Ctrl+C to stop early and see statistics\n\n");

    // Setup cleanup handlers
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    // Create test file
    create_test_file();

    // Open file for reading
    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open test file");
        unlink(filename);
        exit(EXIT_FAILURE);
    }

    time_t start_time = time(NULL);
    time_t end_time = start_time + test_duration;
    int operation_count = 0;

    while (time(NULL) < end_time) {
        // Alternate between read() and pread64() syscalls
        if (operation_count % 2 == 0) {
            // Use regular read() - this will advance file position
            perform_read_test(0, 0);
        } else {
            // Use pread64() at a random offset - doesn't advance file position
            off_t offset = (operation_count / 2) * 64;  // Different offset each time
            perform_read_test(1, offset);
        }

        operation_count++;

        // Print progress every 10 operations
        if (operation_count % 10 == 0) {
            float current_error_rate = total_operations > 0 ? (100.0 * error_count / total_operations) : 0.0;
            printf("[latent_sector_error test] Progress: %d ops, %.1f%% error rate\n",
                   total_operations, current_error_rate);
        }

        // Small delay to avoid overwhelming the system
        usleep(100000);  // 100ms between operations
    }

    // Final cleanup and statistics
    cleanup(0);
    return EXIT_SUCCESS;
}