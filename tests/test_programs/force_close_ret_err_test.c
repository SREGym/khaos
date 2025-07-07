#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

int main(void) {
    printf("[TEST] force_close_ret_err (PID: %d) – close() once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos force_close_ret_err %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_close_ret_err\n\n");

    while (1) {
        // Open a file to get a valid file descriptor
        int fd = open("/etc/hosts", O_RDONLY);
        if (fd == -1) {
            perror("open");
            sleep(1);
            continue;
        }

        errno = 0;
        int rc = close(fd);

        if (rc == -1) {
            printf("[EXPECTED] close failed with errno %d (%s) (fault active).\n", errno, strerror(errno));
            close(fd);
        } else {
            printf("[SUCCESS] close succeeded (fault inactive).\n");
        }

        sleep(1);
    }

    return 0;
} 