#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define TEST_SIZE 4096

int main(void) {
    printf("[TEST] force_mlock_eperm (PID: %d) – mlock() once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos force_mlock_eperm %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_mlock_eperm\n\n");

    // Allocate a page of memory to lock/unlock
    void *mem = malloc(TEST_SIZE);
    if (!mem) {
        perror("malloc");
        return 1;
    }

    while (1) {
        errno = 0;
        int rc = mlock(mem, TEST_SIZE);

        if (rc == -1) {
            if (errno == EPERM) {
                printf("[EXPECTED] mlock failed with EPERM (fault active).\n");
            } else {
                printf("[UNEXPECTED] mlock failed errno %d (%s).\n", errno, strerror(errno));
            }
        } else {
            printf("[SUCCESS] mlock succeeded (fault inactive).\n");
            // Unlock the memory to avoid accumulating locked pages
            munlock(mem, TEST_SIZE);
        }

        sleep(1);
    }

    free(mem);
    return 0;
} 