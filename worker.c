#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "parser.h"
#include "database.h"

struct worker_state {
    struct api_state api;
    int eof;
    int server_fd;  /* server <-> worker bidirectional notification channel */
    int server_eof;
    char username[USERNAME_LEN];
};

/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
    assert(state);
    char *pubmsg = get_last_pubmsg();
    size_t msg_size = strlen(pubmsg);
    size_t ret = send(state->api.fd, &msg_size, sizeof(size_t), 0);
    if(ret <= 0)    {
        free(pubmsg);
        return -1;
    }
    ret = send(state->api.fd, pubmsg, msg_size, 0);
    free(pubmsg);
    return ret <= 0 ? -1 : 0;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
/* TODO call this function to notify other workers through server */
__attribute__((unused))
static int notify_workers(struct worker_state *state) {
    char buf = 0;
    ssize_t r;

    /* we only need to send something to notify the other workers,
     * data does not matter
     */
    r = write(state->server_fd, &buf, sizeof(buf));
    if (r < 0 && errno != EPIPE) {
        perror("error: write of server_fd failed");
        return -1;
    }
    return 0;
}
/**
 * @brief retrieve all message from the database
 * @param state
 * @return 0 on success, -1 otherwise
 */
int send_all_msgs(struct worker_state *state) {
    assert(state);
    ssize_t r;
    char *all_msgs = get_all_msgs();
    size_t msgs_size = strlen(all_msgs);
    r = send(state->api.fd, &msgs_size, sizeof(size_t), 0);
    if(r < 0)  {
        goto cleanup;
    }
    r = send(state->api.fd, all_msgs, msgs_size, 0);
    if(r < 0)  {
        goto cleanup;
    }
    free(all_msgs);
    return 0;

    cleanup:
        free(all_msgs);
        return -1;
}

int handle_register(struct worker_state *state, const struct api_msg *msg)  {
    assert(state);
    assert(msg);

    strcpy(state->username, msg->username);
    int r = store_account(state->username, msg->pwd);
    if(r != 0)  return -1;
    r = send_all_msgs(state);
    if(r != 0)  return -1;
    return 0;
}

int handle_login(struct worker_state *state, const struct api_msg *msg)  {
    assert(state);
    assert(msg);

    strcpy(state->username, msg->username);
    int r = send_all_msgs(state);
    if(r != 0)  return -1;
    return 0;
}

int handle_users()  {
    // TODO
    return -1;
}

int handle_private()   {
    // TODO
    return -1;
}

int handle_public(struct worker_state *state,
                 const struct api_msg *msg)    {
    assert(state);
    assert(msg);

    int r = insert_msg(msg->buffer, msg->username, msg->timestamp);
    if(r < 0) return -1;
    r = notify_workers(state);
    return r;
}

/**
 * @brief         Handles a message coming from client
 * @param state   Initialized worker state
 * @param msg     Message to handle
 */
static int execute_request(struct worker_state *state,
                           const struct api_msg *msg) {
    assert(state);
    assert(msg);
    if(!state->server_eof)  {
        switch(msg->type)   {
            case REGISTER:
                return handle_register(state, msg);
            case LOGIN:
                return handle_login(state, msg);
            case USERS:
                return handle_users();
            case PRIV_MSG:
                return handle_private();
            default:
                return handle_public(state, msg);
        }
    }
    return 0;
}

/**
 * @brief         Reads an incoming request from the client and handles it.
 * @param state   Initialized worker state
 */
static int handle_client_request(struct worker_state *state) {
    struct api_msg msg;
    int r, success = 1;

    assert(state);
    /* wait for incoming request, set eof if there are no more requests */
    r = api_recv(&state->api, &msg);
    if (r < 0) {
        return -1;
    }
    if (r == 0) {
        state->eof = 1;
        return 0;
    }

    /* execute request */
    if (execute_request(state, &msg) != 0) {
        success = 0;
    }

    /* clean up state associated with the message */
    api_recv_free(&msg);
    return success ? 0 : -1;
}

static int handle_s2w_read(struct worker_state *state) {
    char buf[256];
    ssize_t r;
    /* notification from the server that the workers must notify their clients
     * about new messages; these notifications are idempotent so the number
     * does not actually matter, nor does the data sent over the pipe
     */
    errno = 0;
    r = read(state->server_fd, buf, sizeof(buf));
    if (r < 0) {
        perror("error: read server_fd failed");
        return -1;
    }
    if (r == 0) {
        state->server_eof = 1;
        return 0;
    }

    /* notify our client */
    if (handle_s2w_notification(state) != 0) return -1;

    return 0;
}

/**
 * @brief Registers for: client request events, server notification
 *        events. In case of a client request, it processes the
 *        request and sends a response to client. In case of a server
 *        notification it notifies the client of all newly received
 *        messages.
 *
 */
static int handle_incoming(struct worker_state *state) {
    int fdmax, r, success = 1;
    fd_set readfds;

    assert(state);

    /* list file descriptors to wait for */
    FD_ZERO(&readfds);
    /* wake on incoming messages from client */
    FD_SET(state->api.fd, &readfds);
    /* wake on incoming server notifications */
    if (!state->server_eof) FD_SET(state->server_fd, &readfds);
    fdmax = max(state->api.fd, state->server_fd);

    /* wait for at least one to become ready */
    r = select(fdmax+1, &readfds, NULL, NULL, NULL);
    if (r < 0) {
        if (errno == EINTR) return 0;
        perror("error: select failed");
        return -1;
    }

    /* handle ready file descriptors */
    /* TODO once you implement encryption you may need to call ssl_has_data
     * here due to buffering (see ssl-nonblock example)
     */
    if (FD_ISSET(state->api.fd, &readfds)) {
        if (handle_client_request(state) != 0) success = 0;
    }
    if (FD_ISSET(state->server_fd, &readfds)) {
        if (handle_s2w_read(state) != 0) success = 0;
    }
    return success ? 0 : -1;
}

/**
 * @brief Initialize struct worker_state before starting processing requests.
 * @param state        worker state
 * @param connfd       connection file descriptor
 * @param pipefd_w2s   pipe to notify server (write something to notify)
 * @param pipefd_s2w   pipe to be notified by server (can read when notified)
 *
 */
static int worker_state_init(
        struct worker_state *state,
        int connfd,
        int server_fd) {

    /* initialize */
    memset(state, 0, sizeof(*state));
    state->server_fd = server_fd;

    /* set up API state */
    api_state_init(&state->api, connfd);
    return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(struct worker_state *state) {

    /* clean up API state */
    api_state_free(&state->api);

    /* close file descriptors */
    close(state->server_fd);
    close(state->api.fd);
}

/**
 * @brief              Worker entry point. Called by the server when a
 *                     worker is spawned.
 * @param connfd       File descriptor for connection socket
 * @param pipefd_w2s   File descriptor for pipe to send notifications
 *                     from worker to server
 * @param pipefd_s2w   File descriptor for pipe to send notifications
 *                     from server to worker
 */
__attribute__((noreturn))
void worker_start(
        int connfd,
        int server_fd) {
    struct worker_state state;
    int success = 1;

    /* initialize worker state */
    if (worker_state_init(&state, connfd, server_fd) != 0) {
        goto cleanup;
    }
    /* TODO any additional worker initialization */

    /* handle for incoming requests */
    while (!state.eof) {
        if (handle_incoming(&state) != 0) {
            success = 0;
            break;
        }
    }

    cleanup:
    /* cleanup worker */
    /* TODO any additional worker cleanup */
    worker_state_free(&state);

    exit(success ? 0 : 1);
}
