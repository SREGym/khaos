// test_brk.c
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

int main() {
    pid_t pid = getpid();
    printf("[brk_fail test] Running with PID: %d\n", pid);
    void *current_brk = sbrk(0);
    printf("Initial brk: %p\n", current_brk);

    while (1) {
        void *new_brk = sbrk(4096);  // try to grow heap
        if (new_brk == (void *)-1) {
            perror("sbrk failed");
        } else {
            printf("brk moved to: %p\n", new_brk);
        }
        sleep(1);
    }
    return 0;
}
