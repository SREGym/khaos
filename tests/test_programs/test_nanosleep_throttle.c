#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>

int main() {
    printf("Test: nanosleep_interrupt (PID: %d)\n", getpid());
    
    struct timespec tp;
    
    while(1) {
        tp.tv_sec = 0;
        tp.tv_nsec = 100000000;
        
        struct timespec rem;
        int result = syscall(SYS_nanosleep, &tp, &rem);
        if (result < 0) {
            printf("[nanosleep_interrupt] Error: %d\n", errno);
        }
        
        sleep(1);
    }
    
    return 0;
}
