#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define TEST_SIZE 4096

int main(void) {
    printf("[TEST] force_mprotect_eacces (PID: %d) – mprotect() once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos force_mprotect_eacces %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_mprotect_eacces\n\n");

    // Allocate a page of memory with mmap 
    void *mem = mmap(NULL, TEST_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    while (1) {
        errno = 0;
        // Try to change protection from RW to RO
        int rc = mprotect(mem, TEST_SIZE, PROT_READ);

        if (rc == -1) {
            if (errno == EACCES) {
                printf("[EXPECTED] mprotect failed with EACCES (fault active).\n");
            } else {
                printf("[UNEXPECTED] mprotect failed errno %d (%s).\n", errno, strerror(errno));
            }
        } else {
            printf("[SUCCESS] mprotect succeeded (fault inactive).\n");
            // Restore RW permissions for next iteration
            mprotect(mem, TEST_SIZE, PROT_READ | PROT_WRITE);
        }

        sleep(1);
    }

    munmap(mem, TEST_SIZE);
    return 0;
} 