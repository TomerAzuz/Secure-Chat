#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "api.h"
#include "util.h"
#include "worker.h"
#include "parser.h"
#include "database.h"
#include "ssl-nonblock.h"
#include "crypto.h"

struct worker_state {
    SSL *ssl;
    struct api_state api;
    int eof;
    int server_fd;  /* server <-> worker bidirectional notification channel */
    int server_eof;
    char username[USERNAME_LEN];
    int logged_in;
};

int is_privmsg_for_me(const char *username, struct api_msg *msg) {
    if(msg->type != PRIV_MSG) {
        return PUB_MSG;
    }
    if((strncmp(username, msg->sender, USERNAME_LEN-1) == 0) ||
       (strncmp(username, msg->recipient, USERNAME_LEN-1) == 0)) {
        return 1;
    }
    return -1;
}
/**
 * @brief Reads an incoming notification from the server and notifies
 *        the client.
 */
static int handle_s2w_notification(struct worker_state *state) {
    assert(state);
    struct api_msg *msg = get_last_msg();
    if(!msg)    {
        return -1;
    }
    if(is_privmsg_for_me(state->username, msg) < 0)  {
        free(msg);
        return 0;
    }
    int ret = api_send(state->ssl, state->api.fd, msg);
    free(msg);
    return ret;
}

/**
 * @brief         Notifies server that the worker received a new message
 *                from the client.
 * @param state   Initialized worker state
 */
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

int send_all_msgs(struct worker_state *state) {
    assert(state);
    struct api_msg **all_msgs = get_all_msgs();
    if(!all_msgs)   {
        return -1;
    }
    int num_msgs = 0;
    int r;

    /* count messages */
    while(all_msgs[num_msgs++]);

    for(int i = 0; i < num_msgs-1; i++)   {
        if(is_privmsg_for_me(state->username, all_msgs[i]) < 0)  {
            continue;
        }
        r = api_send(state->ssl, state->api.fd, all_msgs[i]);
        if(r < 0)  {
            goto cleanup;
        }
    }
    for(int i = 0; i < num_msgs-1; i++) {
        free(all_msgs[i]);
    }
    free(all_msgs);
    return 0;

    cleanup:
    for(int i = 0; i < num_msgs-1; i++) {
        free(all_msgs[i]);
    }
    free(all_msgs);
    return -1;
}

int handle_register(struct worker_state *state, struct api_msg *msg)  {
    assert(state);
    assert(msg);
    strncpy(state->username, msg->sender, USERNAME_LEN-1);
    //EVP_PKEY *pubkey = X509_get0_pubkey(cacert);
    char *salt = (char*) generate_salt();
    if(!salt)   {
        return -1;
    }
    if(salt_hash_pwd(msg->pwd, salt) != 0)  {
        goto cleanup;
    }
    if(store_account(state->username, msg->pwd, salt) != 0) {
        goto cleanup;
    }
    if(send_msg_status(state->ssl, state->api.fd, REGISTER, NULL) != 0)  {
        goto cleanup;
    }
    if(send_all_msgs(state) != 0) {
        goto cleanup;
    }
    state->logged_in = 1;
    return 0;

    cleanup:
    free(salt);
    return -1;
}

int auth_user(struct api_msg *msg) {
    /* get salt from db */
    char *salt = get_salt(msg->sender);
    if(!salt)   {
        return -1;
    }
    /* salt hash password from user */
    if(salt_hash_pwd(msg->pwd, salt) != 0)   {
        free(salt);
        return -1;
    }
    /* get password from db */
    char *pwd = get_pwd(msg->sender);
    if(!pwd)    {
        free(salt);
        return -1;
    }
    if(strncmp(pwd, msg->pwd, PWD_LEN-1) != 0)   {
        free(salt);
        free(pwd);
        return -1;
    }

    free(salt);
    free(pwd);
    return 0;
}

int handle_login(struct worker_state *state, struct api_msg *msg)  {
    assert(state);
    assert(msg);
    strncpy(state->username, msg->sender, USERNAME_LEN-1);
    int r;
    if(auth_user(msg) != 0)    {
        r = send_msg_status(state->ssl, state->api.fd, AUTH_ERROR, msg->sender);
        return r < 0 ? r : 0;
    }
    else    {
        r = send_msg_status(state->ssl, state->api.fd, LOGIN, NULL);
        if(r != 0) return -1;
    }
    if(update_online(msg->sender, 1) != 1)  {
        return -1;
    }
    state->logged_in = 1;
    return send_all_msgs(state);
}

int handle_users(struct worker_state *state)  {
    struct api_msg *online_users = get_online_users();
    if(!online_users) {
        return -1;
    }
    online_users->type = USERS;
    if(api_send(state->ssl, state->api.fd, online_users) != 0)  {
        free(online_users);
        return -1;
    }
    free(online_users);
    return 0;
}

int handle_msg(struct worker_state *state,
                  const struct api_msg *msg)    {
    assert(state);
    assert(msg);

    int r = insert_msg(msg);
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
                           struct api_msg *msg) {
    assert(state);
    assert(msg);
    if(!state->server_eof)  {
        switch(msg->type)   {
            case REGISTER:
                return handle_register(state, msg);
            case LOGIN:
                return handle_login(state, msg);
            case USERS:
                return handle_users(state);
            default:
                return handle_msg(state, msg);
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
    r = api_recv(state->ssl, &state->api, &msg);
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

    if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->ssl)) {
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
    memset(state->username, '\0', USERNAME_LEN);
    /* set up API state */
    api_state_init(&state->api, connfd);

    state->logged_in = 0;
    return 0;
}

/**
 * @brief Clean up struct worker_state when shutting down.
 * @param state        worker state
 *
 */
static void worker_state_free(struct worker_state *state) {

    if(state->logged_in)    {
        update_online(state->username, 0);
    }
    /* clean up API state */
    api_state_free(&state->api);

    /* close file descriptors */
    close(state->server_fd);
    close(state->api.fd);

    SSL_free(state->ssl);
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
        int server_fd,
        SSL *ssl) {
    struct worker_state state;
    int success = 1;

    /* initialize worker state */
    if (worker_state_init(&state, connfd, server_fd) != 0) {
        goto cleanup;
    }
    state.ssl = ssl;

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
