#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <time.h>

static const char *filename = "pread_test_file.txt";
static int fd = -1;

void cleanup(int signum) {
    
    unlink(filename);  // Delete the test file
    exit(EXIT_SUCCESS);
}

int main() {
    printf("[pread_error test] Running with PID: %d\n", getpid());

    // open test file
    int tmpfd = open("pread_test_file.txt", O_RDWR | O_CREAT, 0644);

    const char *init = "Data for pread test\n";
    write(tmpfd, init, strlen(init));
    close(tmpfd);

    fd = open("pread_test_file.txt", O_RDONLY);

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    off_t offset = 0;
    char buf[128];

    while (1) {
        ssize_t n = pread(fd, buf, sizeof(buf), offset);
        if (n < 0) {
            printf("[pread_error test] Error: %s (errno=%d)\n", strerror(errno), errno);
        } else {
            printf("[pread_error test] Read %zd bytes\n", n);
        }
        sleep(1);
    }

    return EXIT_SUCCESS;
} 