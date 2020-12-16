#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


struct obfs_envelope_struct {
    uint8_t nonce[16];
    uint8_t *payload;
    uint8_t tag[16];
};

void obfs_envelope_free(struct obfs_envelope_struct *envelope);

void obfs_envelope_allocate(struct obfs_envelope_struct *envelope, uint32_t len);

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

struct kex_alg {
    uint8_t name[256];
    char *data;
};

struct ext_pair{
    uint8_t name[256];
    char *data;
};

struct ssh_quic_init {
    uint8_t packet_type;
    uint8_t client_connection_id[256];
    uint8_t server_name_indication[256];
    uint8_t v;
    uint32_t *client_quic_versions;
    char *client_sig_algs;
    uint8_t f;
    uint8_t **trusted_fingerprints;
    uint8_t k;
    struct kex_alg *kex_algs;    
    uint8_t c;
    uint8_t **quic_tls_cipher_suite;
    uint8_t e;
    struct ext_pair *ext_pairs;
    uint8_t *padding;
};

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

struct ssh_quic_reply {
    uint8_t packet_type;
    uint8_t client_conn_id[256];
    uint8_t server_conn_id[256];
    uint8_t v;
    uint32_t *server_quic_versions;
    char *server_quic_trnsp_params;
    char *server_sig_algs;
    char *server_kex_algs;
    uint8_t c;
    uint8_t **quic_tls_cipher_suite;
    uint8_t e;
    struct ext_pair *ext_pairs;
    char *server_kex_alg_data;
};

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

