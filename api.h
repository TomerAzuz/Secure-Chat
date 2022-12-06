#ifndef _API_H_
#define _API_H_

#include <openssl/ssl.h>

#define BUFFER_LEN    1024
#define USERNAME_LEN  17
#define PWD_LEN       33
#define TIMESTAMP_LEN 28
#define SIG_LEN       257
#define RSA_LEN       257

struct api_msg {
    char buffer[BUFFER_LEN];
    int type;
    char sender[USERNAME_LEN];
    char recipient[USERNAME_LEN];
    char pwd[PWD_LEN];
    char timestamp[TIMESTAMP_LEN];
    char sig[SIG_LEN];
    char aes1[RSA_LEN]; // encrypted with recipient's key
    char aes2[RSA_LEN]; // encrypted with sender's key
} __attribute__((packed));

struct api_state {
    int fd;
};

int api_recv(SSL *ssl, struct api_state *state, struct api_msg *msg);
void api_recv_free(struct api_msg *msg);
void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);
void api_init_msg(struct api_msg *msg);
int api_send(SSL *ssl, int fd, struct api_msg *msg);
int send_msg_type(SSL *ssl, int fd, int msg_type, const char *username);

#endif /* defined(_API_H_) */
