#define _GNU_SOURCE  // Required for SYS_clock_gettime on some systems

#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>

#ifndef SYS_clock_gettime
  #error "SYS_clock_gettime is not defined on this platform"
#endif

int main() {
    printf("Test: clock_drift (PID: %d)\n", getpid());

    struct timespec tp;

    while (1) {
        int result = syscall(SYS_clock_gettime, CLOCK_REALTIME, &tp);
        if (result < 0) {
            perror("[clock_drift] syscall clock_gettime failed");
        } else {
            printf("Time: %ld.%09ld\n", tp.tv_sec, tp.tv_nsec);
        }

        sleep(1);
    }

    return 0;
}
