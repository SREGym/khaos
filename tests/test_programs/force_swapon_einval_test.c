#include <stdio.h>
#include <unistd.h>
#include <sys/swap.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

/*
 Note: This test uses a non-existent swap file, so swapon will normally
 fail with ENOENT. When the fault is active, it should fail with EINVAL.
*/

int main(void) {
    if (getuid() != 0) {
        fprintf(stderr, "This test must be run as root (swapon requires root privileges).\n");
        fprintf(stderr, "Usage: sudo %s\n", __FILE__);
        return 1;
    }

    printf("[TEST] force_swapon_einval (PID: %d) – swapon() once per second.\n", getpid());
    printf("Inject the fault with: sudo ./khaos force_swapon_einval %d\n", getpid());
    printf("Recover the fault with: sudo ./khaos --recover force_swapon_einval\n\n");

    const char *fake_swap_file = "/tmp/nonexistent_swap_file";

    while (1) {
        errno = 0;
        int rc = swapon(fake_swap_file, 0);

        if (rc == -1) {
            if (errno == EINVAL) {
                printf("[EXPECTED] swapon failed with EINVAL (fault active).\n");
            } else if (errno == ENOENT) {
                printf("[SUCCESS] swapon failed with ENOENT (fault inactive - expected for non-existent file).\n");
            } else {
                printf("[UNEXPECTED] swapon failed errno %d (%s).\n", errno, strerror(errno));
            }
        } else {
            printf("[UNEXPECTED] swapon succeeded (this should not happen with fake file).\n");
            swapoff(fake_swap_file);
        }

        sleep(1);
    }

    return 0;
} 