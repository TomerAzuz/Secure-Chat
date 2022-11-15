#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>

#include "api.h"

/**
 * @brief         Receive the next message from the sender and stored in @msg
 * @param state   Initialized API state
 * @param msg     Information about message is stored here
 * @return        Returns 1 on new message, 0 in case socket was closed,
 *                or -1 in case of error.
 */
int api_recv(struct api_state *state, struct api_msg *msg) {

    assert(state);
    assert(msg);
    api_init_msg(msg);

    /* read the message size */
    size_t msg_size = 0;
    ssize_t ret = recv(state->fd, &msg_size, sizeof(size_t), 0);
    if(ret == 0)    {
        state->fd = 0;
        return 0;
    }
    /* read the message */
    ssize_t bytes_read = 0;
    while(bytes_read < msg_size)  {
        ret = recv(state->fd, msg + bytes_read, msg_size - bytes_read, 0);
        if(ret <= 0) {
            return -1;
        }
        bytes_read += ret;
    }
    return 1;
}

void api_init_msg(struct api_msg *msg) {
    memset(msg->buffer, '\0', BUFFER_LEN);
    msg->type = 0;
    memset(msg->username, '\0', USERNAME_LEN);
    memset(msg->pwd, '\0', PWD_LEN);
    memset(msg->timestamp, '\0', TIMESTAMP_LEN);
}

/**
 * @brief         Clean up information stored in @msg
 * @param msg     Information about message to be cleaned up
 */
void api_recv_free(struct api_msg *msg) {

    assert(msg);
    memset(msg, 0, sizeof(*msg));
    /* TODO clean up state allocated for msg */
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
