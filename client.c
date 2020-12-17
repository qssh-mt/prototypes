#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "obfs.h"


void obfs_envelope_allocate(struct obfs_envelope_struct *envelope, uint32_t len) {
    envelope->payload = calloc(len, sizeof(uint8_t));
    if (envelope->payload == NULL) {
        exit(EXIT_FAILURE);
    }
}

void obfs_envelope_free(struct obfs_envelope_struct *envelope) {
    if(envelope->payload) {
        free(envelope->payload);
        envelope->payload = NULL;
    }
    memset(envelope->nonce, 0, 16 * sizeof(uint8_t));
    memset(envelope->tag, 0, 16 * sizeof(uint8_t));
}

void ssh_quic_init_allocate(struct ssh_quic_init *packet, uint8_t v, uint8_t f, uint8_t k, uint8_t c, uint8_t e) {
    packet->packet_type = 1;
    packet->client_quic_versions = calloc(v, sizeof(uint32_t));
    packet->trusted_fingerprints = calloc(f, sizeof(uint8_t *));
    for (int i = 0; i < f; i++) {
        packet->trusted_fingerprints[i] = calloc(256, sizeof(uint8_t));
    }
    packet->kex_algs = calloc(k, sizeof(struct kex_alg));
    packet->quic_tls_cipher_suite = calloc(c, sizeof(uint8_t *));
    for (int i = 0; i < c; i++) {
        packet->quic_tls_cipher_suite[i] = calloc(256, sizeof(uint8_t));
    }
    packet->ext_pairs = calloc(e, sizeof(struct ext_pair));
}

void ssh_quic_init_reply_allocate(struct ssh_quic_reply *packet, uint8_t v, uint8_t c, uint8_t e) {
    packet->packet_type = 2;
    packet->server_quic_versions = calloc(v, sizeof(uint32_t));
    packet->quic_tls_cipher_suite = calloc(c, sizeof(uint8_t *));
    for (int i = 0; i < c; i++) {
        packet->quic_tls_cipher_suite[i] = calloc(256, sizeof(uint8_t));
    }
    packet->ext_pairs = calloc(e, sizeof(struct ext_pair));
}

int main(int argc, char **argv) {
    if (argc != 4) {
        exit(EXIT_FAILURE);
    }

    char *local_ip = argv[1];
    unsigned int local_port = atoi(argv[2]);

    char *remote_ip = argv[3];
    unsigned int remote_port = atoi(argv[4]);

    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(local_port);
    addr.sin_addr.s_addr = inet_addr(local_ip);

    int sent_bytes = sendto(sockfd, (void *)buf, n, 0, addr, sizeof(addr));
    
    printf("Sent %d bytes\n", sent_bytes);
    fflush(stdout);
    
    return 0;
}

