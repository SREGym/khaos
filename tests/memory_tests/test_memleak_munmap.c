/*
 * Memory Leak Test: munmap() Prevention
 * 
 * Maps 1MB regions continuously, then tries to unmap older ones.
 * When fault is active, munmap() fails → memory usage grows indefinitely.
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define TEST_SIZE (1024 * 1024)  // 1MB

int main(void) {
    printf("[TEST] memleak_munmap (PID: %d) – munmap() once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos memleak_munmap %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover memleak_munmap\n\n");

    void *mapped_regions[10];
    int region_count = 0;

    while (1) {
        // Map some memory
        void *mem = mmap(NULL, TEST_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            perror("mmap failed");
            sleep(1);
            continue;
        }

        mapped_regions[region_count % 10] = mem;
        region_count++;
        printf("[INFO] Mapped memory region #%d at %p\n", region_count, mem);

        // Try to unmap older regions to free memory (after we have at least 3 regions)
        if (region_count > 3) {
            int old_index = (region_count - 6) % 10;
            void *old_mem = mapped_regions[old_index];
            
            errno = 0;
            int rc = munmap(old_mem, TEST_SIZE);
            
            if (rc == -1) {
                if (errno == EINVAL) {
                    printf("[EXPECTED] munmap failed with EINVAL (fault active - memory leak simulated).\n");
                } else {
                    printf("[UNEXPECTED] munmap failed errno %d (%s).\n", errno, strerror(errno));
                }
            } else {
                printf("[SUCCESS] munmap succeeded (fault inactive).\n");
            }
        }

        sleep(1);
    }

    return 0;
} 