#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>

int main() {
    printf("Test: gettimeofday_fail (PID: %d)\n", getpid());
    
    struct timeval tv;
    
    while(1) {
        int result = syscall(SYS_gettimeofday, &tv, NULL);
        if (result < 0) {
            printf("[gettimeofday_fail] Error: %d\n", errno);
        }
        
        sleep(1);
    }
    
    return 0;
}
