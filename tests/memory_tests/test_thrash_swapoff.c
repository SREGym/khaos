#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <sys/types.h>

#define SWAP_FILE "./test_swapoff_file"

// This helper function sets up AND enables the swap file
void setup_and_enable_swap() {
    char cmd_buf[256];
    
    swapoff(SWAP_FILE);
    remove(SWAP_FILE);

    snprintf(cmd_buf, sizeof(cmd_buf), "fallocate -l 10M %s", SWAP_FILE);
    if (system(cmd_buf) != 0) { exit(1); }
    
    if (chmod(SWAP_FILE, 0600) != 0) { exit(1); }
    
    snprintf(cmd_buf, sizeof(cmd_buf), "mkswap %s > /dev/null", SWAP_FILE);
    if (system(cmd_buf) != 0) { exit(1); }

    // Enable the swap so we have something to turn off
    if (swapon(SWAP_FILE, 0) != 0) {
        perror("[SETUP ERROR] Could not use swapon for swapoff test (try running with sudo)");
        exit(1);
    }
}

int main() {
    pid_t pid = getpid();
    printf("[thrash_swapon] test program using swapoff (PID: %d) ---\n", pid);
    printf("This program must be run with sudo.\n");

    int was_last_attempt_failed = 0;

    while (1) {
        setup_and_enable_swap();
        
        // Attempt to disable the swap file
        if (swapoff(SWAP_FILE) == 0) {
            if (was_last_attempt_failed) {
                printf("[RECOVERED] swapoff is now succeeding.\n");
            } else {
                printf("[OK] swapoff successful.\n");
            }
            was_last_attempt_failed = 0;
        } else {
            if (!was_last_attempt_failed) {
                printf("[FAILED] swapoff failed: %s\n", strerror(errno));
            }
            was_last_attempt_failed = 1;
        }
        
        remove(SWAP_FILE);
        sleep(4);
    }
    return 0;
}
