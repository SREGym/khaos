// Recovery track ONLY possible with ltrace due to sbrk's restrictions on states
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    pid_t pid = getpid();
    printf("[hfrag_heapspace] Running with PID: %d\n", pid);
    void *current_brk = sbrk(0);
    printf("[OK] Initial brk: %p\n", current_brk);

    while (1) {
        void *new_brk = sbrk(4096);  
        if (new_brk == (void *)-1) {
            perror("[FAILED] sbrk failed");
        } else {
            printf("[OK] brk moved to: %p\n", new_brk);
        }
        sleep(1);
    }
    return 0;
}
