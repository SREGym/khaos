#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/swap.h>
#include <sys/stat.h>

#define SWAP_FILE "./test_swapon_file"

// This helper function creates and formats a clean swap file
void prepare_swap_file() {
    char cmd_buf[256];
    
    swapoff(SWAP_FILE); 
    remove(SWAP_FILE);  

    // Create a non-sparse file
    snprintf(cmd_buf, sizeof(cmd_buf), "fallocate -l 10M %s", SWAP_FILE);
    if (system(cmd_buf) != 0) {
        fprintf(stderr, "[SETUP ERROR] fallocate failed.\n");
        exit(1);
    }
    
    // Set secure permissions
    if (chmod(SWAP_FILE, 0600) != 0) {
        perror("[SETUP ERROR] chmod failed");
        exit(1);
    }
    
    // Format as swap
    snprintf(cmd_buf, sizeof(cmd_buf), "mkswap %s > /dev/null", SWAP_FILE);
    if (system(cmd_buf) != 0) {
        fprintf(stderr, "[SETUP ERROR] mkswap failed.\n");
        exit(1);
    }
}

int main() {
    pid_t pid = getpid();
    printf("[thrash_swapon] test program using swapon (PID: %d) ---\n", pid);
    printf("This program must be run with sudo.\n");

    int was_last_attempt_failed = 0; // 0 for false, 1 for true

    while (1) {
        prepare_swap_file();
        
        if (swapon(SWAP_FILE, 0) == 0) {
            if (was_last_attempt_failed) {
                printf("[RECOVERED] swapon is now succeeding.\n");
            } else {
                printf("[OK] swapon successful.\n");
            }
            was_last_attempt_failed = 0;
            swapoff(SWAP_FILE); // Clean up for the next loop
        } else {
            if (!was_last_attempt_failed) {
                printf("[FAILED] swapon failed: %s\n", strerror(errno));
            }
            was_last_attempt_failed = 1;
        }
        
        remove(SWAP_FILE);
        sleep(4);
    }
    return 0;
}
