#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>

int main() {
    printf("Test: clock_drift (PID: %d)\n", getpid());
    
    struct timespec tp;
    
    while(1) {
        // Direct clock_gettime syscall using syscall()
        // Otherwise vDSO may be used in Linux systems and clock_gettime will not be called
        // More here: https://berthub.eu/articles/posts/on-linux-vdso-and-clockgettime/

        // int result = clock_gettime(CLOCK_REALTIME, &tp);
        int result = syscall(SYS_clock_gettime, CLOCK_REALTIME, &tp);
        if (result < 0) {
            printf("[clock_drift] Error: %d\n", errno);
        }
        
        sleep(1);
    }
    
    return 0;
}
