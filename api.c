#include <assert.h>
#include <string.h>

#include "api.h"
#include "ssl-nonblock.h"
#include "parser.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(SSL *ssl, struct api_state *state, struct api_msg *msg) {

    assert(state);
    assert(msg);
    api_init_msg(msg);

    int msg_size = sizeof(struct api_msg);
    int bytes_read = 0;
    int r;
    while(bytes_read < msg_size)  {
        r = ssl_block_read(ssl, state->fd, msg + bytes_read, msg_size - bytes_read);
        if(r <= 0) {
            return r;
        }
        bytes_read += r;
    }
    return 1;
}

int api_send(SSL *ssl, int fd, struct api_msg *msg) {
    assert(msg);
    int r = ssl_block_write(ssl, fd, msg, sizeof(struct api_msg));
    if(r < 0) {
        return -1;
    }
    return 0;
}

int send_msg_status(SSL *ssl, int fd, int msg_type, const char *username)  {
    struct api_msg *msg = calloc(1, sizeof(struct api_msg));
    msg->type = msg_type;
    if(msg->type == AUTH_ERROR) {
        memcpy(msg->sender, username, USERNAME_LEN);
    }
    int r = api_send(ssl, fd, msg);
    free(msg);
    return r;
}

void api_init_msg(struct api_msg *msg) {
    memset(msg->buffer, '\0', BUFFER_LEN);
    msg->type = 0;
    memset(msg->sender, '\0', USERNAME_LEN);
    memset(msg->recipient, '\0', USERNAME_LEN);
    memset(msg->pwd, '\0', PWD_LEN);
    memset(msg->timestamp, '\0', TIMESTAMP_LEN);
    memset(msg->sig, '\0', SIG_LEN);
    memset(msg->aes, '\0', RSA_LEN);
    msg->cert = NULL;
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {
    assert(msg);
    memset(msg, 0, sizeof(*msg));
    X509_free(msg->cert);
}

/**
 * @brief         Frees api_state context
 * @param state   Initialized API state to be cleaned up
 */
void api_state_free(struct api_state *state) {

    assert(state);
  /* TODO clean up API state */
}

/**
 * @brief         Initializes api_state context
 * @param state   API state to be initialized
 * @param fd      File descriptor of connection socket
 */
void api_state_init(struct api_state *state, int fd) {

    assert(state);

    /* initialize to zero */
    memset(state, 0, sizeof(*state));

    /* store connection socket */
    state->fd = fd;

    /* TODO initialize API state */
}
