#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/syscall.h>

int main(void) {
    printf("[TEST] force_brk_eagain (PID: %d) – direct brk syscall once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos force_brk_eagain %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_brk_eagain\n\n");

    while (1) {
        void *cur_break = sbrk(0);
        void *new_break = (char*)cur_break + 128;
        
        errno = 0;
        // Direct syscall - bypass glibc wrapper completely
        long result = syscall(__NR_brk, new_break);

        // printf("[DEBUG] syscall(__NR_brk) returned: %ld, errno: %d (%s)\n", result, errno, strerror(errno));
        
        if (result == -1) {
            if (errno == EAGAIN) {
                printf("[EXPECTED] brk syscall failed with EAGAIN (fault active).\n");
            } else {
                printf("[UNEXPECTED] brk syscall failed errno %d (%s).\n", errno, strerror(errno));
            }
        } else {
            printf("[SUCCESS] brk syscall succeeded (fault inactive).\n");
            syscall(__NR_brk, cur_break);
        }

        sleep(1);
    }

    return 0;
} 