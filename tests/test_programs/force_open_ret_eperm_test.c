#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

int main(void) {
    const char *path = "/etc/hosts";

    printf("[TEST] force_open_ret_eperm (PID: %d) – the test will attempt open() once per second.\n",
           getpid());
    printf("Inject the fault anytime with: sudo ./khaos force_open_ret_eperm %d\n\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_open_ret_eperm\n\n");

    while (1) {
        int fd = open(path, O_RDONLY);

        if (fd == -1) {
            if (errno == EPERM) {
                printf("[EXPECTED] open() failed with EPERM (fault active).\n");
            } else {
                printf("[UNEXPECTED] open() failed with errno %d (%s).\n", errno, strerror(errno));
            }
        } else {
            printf("[SUCCESS] open() succeeded (fault inactive).\n");
            close(fd);
        }

        sleep(1);
    }

    return 0;
} 