/*
 * Memory Leak Test: brk() Shrink Prevention
 * 
 * Continuously expands and tries to shrink heap space using brk().
 * When fault is active, shrinking fails → heap memory cannot be released.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define EXPAND_SIZE 4

int main(void) {
    printf("[TEST] mem_leak_brk_shrink (PID: %d) – brk() expand/shrink cycle.\n", getpid());
    printf("Inject the fault with: sudo ./khaos mem_leak_brk_shrink %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover mem_leak_brk_shrink\n\n");

    void *initial_brk = sbrk(0);
    printf("[INFO] Initial program break: %p\n", initial_brk);

    int cycle = 0;

    while (1) {
        cycle++;

        void *current_brk = (void*)syscall(__NR_brk, 0);
        printf("\n[CYCLE %d] Starting expand/shrink cycle at %p...\n", cycle, current_brk);

        void *new_brk = (char *)current_brk + EXPAND_SIZE;
        
        errno = 0;
        long result = syscall(__NR_brk, new_brk);
        if (result == -1) {
            printf("[FAILED] brk expand failed: %s (errno=%d)\n", strerror(errno), errno);
        } else {
            void *actual_new_brk = (void*)syscall(__NR_brk, 0);
            printf("[SUCCESS] Heap expanded to %p (+%ld bytes)\n", actual_new_brk, (char*)actual_new_brk - (char*)current_brk);
            current_brk = actual_new_brk;
        }

        sleep(2);

        new_brk = (char *)current_brk - EXPAND_SIZE;
        
        errno = 0;
        result = syscall(__NR_brk, new_brk);
        if (result == -1) {
            if (errno == EAGAIN) {
                printf("[EXPECTED] EAGAIN: brk shrink failed: %s (errno=%d) - fault active\n", strerror(errno), errno);
            } else {
                printf("[UNEXPECTED] brk shrink failed: %s (errno=%d) - fault inactive\n", strerror(errno), errno);
            }
        } else {
            void *actual_new_brk = (void*)syscall(__NR_brk, 0);
            printf("[SUCCESS] Heap shrunk back to %p (-%ld bytes) (fault inactive)\n", actual_new_brk, (char*)current_brk - (char*)actual_new_brk);
        }

        sleep(2);
    }

    return 0;
}