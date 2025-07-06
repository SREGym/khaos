#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>

#define TEST_FILE "test_mmap_file.bin"
#define MMAP_SIZE 4096

static int prepare_file(void) {
    int fd = open(TEST_FILE, O_CREAT | O_RDWR, 0644);
    if (fd == -1) {
        perror("open test file");
        return -1;
    }
    if (ftruncate(fd, MMAP_SIZE) != 0) {
        perror("ftruncate");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}

int main(void) {
    if (prepare_file() != 0)
        return 1;

    printf("[TEST] force_mmap_eagain (PID: %d) – mmap() once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos force_mmap_eagain %d\n\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_mmap_eagain\n\n");

    while (1) {
        int fd = open(TEST_FILE, O_RDONLY);
        if (fd == -1) {
            perror("open");
            sleep(1);
            continue;
        }

        void *addr = mmap(NULL, MMAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr == MAP_FAILED) {
            if (errno == EAGAIN) {
                printf("[EXPECTED] mmap failed with EAGAIN (fault active).\n");
            } else {
                printf("[UNEXPECTED] mmap failed errno %d (%s).\n", errno, strerror(errno));
            }
        } else {
            printf("[SUCCESS] mmap succeeded (fault inactive).\n");
            munmap(addr, MMAP_SIZE);
        }

        close(fd);
        sleep(1);
    }

    return 0;
} 