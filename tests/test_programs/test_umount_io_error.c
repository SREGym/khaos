#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <signal.h>

const char *target = "./test_umount";

void cleanup(int signum) {
    // clean the test directory
    rmdir(target);
    exit(EXIT_SUCCESS);
}

int main() {

    // run with sudo becuase mounting requires root privileges
    if (geteuid() != 0) {
        fprintf(stderr, "[umount_io_error test] Error: This program must be run with sudo.\n");
        return EXIT_FAILURE;
    }

    printf("[umount_io_error test] Running with PID: %d\n", getpid());
    
    // creat directory for mount test
    mkdir(target, 0755);
    
    signal(SIGINT, cleanup);  
    signal(SIGTERM, cleanup);
    
    mount("none", target, "tmpfs", 0, NULL);
    while (1) {
        
        int ret = umount(target);

        if (ret < 0) {
            printf("[umount_io_error test] Error: %s (errno=%d)\n", strerror(errno), errno);
        } else {
            printf("[umount_io_error test] Unmounted tmpfs at %s\n", target);
            
            mount("none", target, "tmpfs", 0, NULL);
        }

        sleep(1);
    }

    return EXIT_SUCCESS;
}