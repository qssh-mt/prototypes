#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>


int main(int argc, char **argv) {
    char buf[256];
    int n;

    if (argc != 4) {
        exit(EXIT_FAILURE);
    }

    char *local_ip = argv[1];
    unsigned int local_port = atoi(argv[2]);

    char *remote_ip = argv[3];
    unsigned int remote_port = atoi(argv[4]);

    
    struct sockaddr_in local_addr;
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(local_port);
    local_addr.sin_addr.s_addr = inet_addr(local_ip);
    
    struct sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote_port);
    remote_addr.sin_addr.s_addr = inet_addr(remote_ip);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int ret = bind(sockfd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    ret = recv(sockfd, buf, &n, 0); 
    int sent_bytes = sendto(sockfd, (void *)buf, n, 0, addr, sizeof(addr));
    
    printf("Sent %d bytes\n", sent_bytes);
    fflush(stdout);
    

    return 0;
}
