#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>

int main() {

    pid_t pid = getpid();
    printf("[bind_enetdown test] Running with PID: %d\n", pid);

    // Prepare the sockaddr_in structure
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345); 
    addr.sin_addr.s_addr = htonl(INADDR_ANY); 
    
    while (1) {
        
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("socket creation failed");
            return EXIT_FAILURE;
        }

        int ret = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));

        if (ret < 0) {
            printf("[bind_enetdown test] Error: %s (errno=%d)\n", strerror(errno), errno);
        } else {
            printf("[bind_enetdown test] socket bound to port 12345\n");
        }
        sleep(1);

        close(sockfd);
    }


    return EXIT_SUCCESS;
}