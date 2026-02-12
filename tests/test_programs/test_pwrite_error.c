#define _GNU_SOURCE
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

static const char *filename = "pwrite_test_file.txt";
static int fd = -1;

void cleanup(int signum) {
    
    close(fd);
    unlink(filename);
    exit(EXIT_SUCCESS);
}

int main() {

    printf("[pwrite_error test] Running with PID: %d\n", getpid());

    // open test file
    int tmpfd = open(filename, O_RDWR | O_CREAT, 0644);
    
    // add test data
    const char *init = "Initial data for pwrite test\n";
    write(tmpfd, init, strlen(init));
    close(tmpfd);

    fd = open(filename, O_WRONLY);
    
    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    const char *data = "PWTEST";

    while (1) {

        ssize_t n = pwrite(fd, data, strlen(data), 0);

        if (n < 0) {
            printf("[pwrite_error test] Error: %s (errno=%d)\n", strerror(errno), errno);

        } else {
            printf("[pwrite_error test] Wrote %zd bytes\n", n);
        }

        sleep(1);
    }

    return EXIT_SUCCESS;
} 