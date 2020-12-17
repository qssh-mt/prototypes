#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct obfs_envelope_struct {
    uint8_t nonce[16];
    uint8_t *payload;
    uint8_t tag[16];
};

void obfs_envelope_free(struct obfs_envelope_struct *envelope);

void obfs_envelope_allocate(struct obfs_envelope_struct *envelope, uint32_t len);

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
};

void ssh_quic_init_allocate(struct ssh_quic_init *packet, uint8_t v, uint8_t f, uint8_t k, uint8_t c, uint8_t e);


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

void ssh_quic_init_reply_allocate(struct ssh_quic_reply *packet, uint8_t v, uint8_t c, uint8_t e);

