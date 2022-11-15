#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include "parser.h"
#include "sanitizer.h"

struct client_state {
    struct api_state api;
    int eof;
    struct ui_state ui;
    int logged_in;
};

/**
 * @brief Connects to @hostname on port @port and returns the
 *        connection fd. Fails with -1.
 */
static int client_connect(struct client_state *state,
                          const char *hostname, uint16_t port) {
    int fd;
    struct sockaddr_in addr;

    assert(state);
    assert(hostname);

    /* look up hostname */
    if (lookup_host_ipv4(hostname, &addr.sin_addr) != 0) return -1;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    /* create TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("error: cannot allocate server socket");
        return -1;
    }

    /* connect to server */
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != 0) {
        perror("error: cannot connect to server");
        close(fd);
        return -1;
    }

    return fd;
}
/**
 * @param state
 * @param login
 * @return 0 if user is not logged in and sends unauthorized commands, 1 otherwise
 */
int is_logged_in(struct client_state *state, int login)   {
    assert(state);
    if(state->logged_in != login)    {
        message_user(INVALID_CMD, NULL);
        return 0;
    }
    return 1;
}

int send_msg_to_worker(struct client_state *state, struct api_msg *msg) {
    assert(state);
    assert(msg);

    /* send the size of the message */
    size_t msg_size = sizeof(struct api_msg);
    ssize_t ret = send(state->api.fd, &msg_size, sizeof(size_t), 0);
    if(ret <= 0) {
        return -1;
    }
    /* send the message */
    ret = send(state->api.fd, msg, msg_size, 0);
    if(ret <= 0) {
        return -1;
    }
    return 0;
}

int handle_register(struct client_state *state, struct api_msg *msg)   {
    assert(state);
    assert(msg);

    state->logged_in = 1;
    message_user(REGISTER, NULL);
    memcpy(state->ui.username, msg->username, USERNAME_LEN);
    return send_msg_to_worker(state, msg);
}

int handle_login(struct client_state *state, struct api_msg *msg)  {
    assert(state);
    assert(msg);

    state->logged_in = 1;
    message_user(LOGIN, NULL);
    memcpy(state->ui.username, msg->username, USERNAME_LEN);
    return send_msg_to_worker(state, msg);
}

int handle_users()  {
    // TODO
    return -1;
}

int handle_public(struct client_state *state, struct api_msg *msg) {
    assert(state);
    assert(msg);

    /* store timestamp in message */
    char *timestamp = get_timestamp();
    memcpy(msg->timestamp, timestamp, TIMESTAMP_LEN);
    free(timestamp);

    /* store username */
    strcpy(msg->username, state->ui.username);

    /* remove whitespace from message */
    char* trimmed = remove_whitespace(msg->buffer);
    memcpy(msg->buffer, trimmed, strlen(trimmed));

    return send_msg_to_worker(state, msg);
}

int handle_private(struct client_state *state, struct api_msg *msg) {
    assert(state);
    assert(msg);

    char *buf = msg->buffer;
    /* skip recipient */
    int count = 0;
    while(*buf != ' ')  {
        count++;
        buf++;
    }

    char *trimmed = remove_whitespace(buf);
    buf -= count;
    buf = strtok(buf, " ");

    char priv_msg[BUFFER_LEN];

    strcat(priv_msg, buf);
    strcat(priv_msg, " ");
    strcat(priv_msg, trimmed);
    memset(msg->buffer, '\0', BUFFER_LEN);
    strcpy(msg->buffer, priv_msg);
    return handle_public(state, msg);
}

static int client_process_command(struct client_state *state) {
    assert(state);
    int ret = 0;
    size_t msg_size = sizeof(struct api_msg);
    state->eof = 0;
    struct api_msg *msg = calloc(1, msg_size);
    if(read_input(msg->buffer) == 0)    {
        state->eof = 1;
    }
    else if(is_cmd(msg->buffer))    {
        int msg_type = get_cmd(msg, state->logged_in);
        switch(msg_type)    {
            case REGISTER:
                ret = handle_register(state, msg);
                break;
            case LOGIN:
                ret = handle_login(state, msg);
                break;
            case USERS:
                ret = handle_users();
                break;
            case EXIT:
                free(msg);
                exit(EXIT_SUCCESS);
            default:
                message_user(msg_type, msg->buffer);
                free(msg);
                return 0;
        }
        free(msg);
        return ret;
    }
    else if(is_logged_in(state, 1) && is_valid_msg(msg->buffer)) {
        if(msg->buffer[0] == '@')   {
            ret = handle_private(state, msg);
        }
        else ret = handle_public(state, msg);
    }
    free(msg);
    return ret;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(struct client_state *state,
                           const struct api_msg *msg) {
    assert(state);
    assert(msg);

    if(state->logged_in) {
        printf("%s", msg->buffer);
        return 0;
    }
    return -1;
}

/**
 * @brief         Reads an incoming request from the server and handles it.
 * @param state   Initialized client state
 */
static int handle_server_request(struct client_state *state) {
    struct api_msg msg;
    int r, success = 1;

    assert(state);

    /* wait for incoming request, set eof if there are no more requests */
    r = api_recv(&state->api, &msg);
    if (r < 0) return -1;
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

/**
 * @brief register for multiple IO event, process one
 *        and return. Returns 0 if the event was processed
 *        successfully and -1 otherwise.
 *
 */
static int handle_incoming(struct client_state *state) {
    int fdmax, r;
    fd_set readfds;

    assert(state);

    /* TODO if we have work queued up, this might be a good time to do it */

    /* TODO ask user for input if needed */

    /* list file descriptors to wait for */
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    FD_SET(state->api.fd, &readfds);
    fdmax = state->api.fd;

    /* wait for at least one to become ready */
    r = select(fdmax+1, &readfds, NULL, NULL, NULL);
    if (r < 0) {
        if (errno == EINTR) return 0;
        perror("error: select failed");
        return -1;
    }

    /* handle ready file descriptors */
    if (FD_ISSET(STDIN_FILENO, &readfds)) {
        return client_process_command(state);
    }
    /* TODO once you implement encryption you may need to call ssl_has_data
     * here due to buffering (see ssl-nonblock example)
     */
    if (FD_ISSET(state->api.fd, &readfds)) {
        return handle_server_request(state);
    }
    return 0;
}

static int client_state_init(struct client_state *state) {
    /* clear state, invalidate file descriptors */
    memset(state, 0, sizeof(*state));

    /* initialize UI */
    ui_state_init(&state->ui);
    state->logged_in = 0;

    /* TODO any additional client state initialization */

    return 0;
}

static void client_state_free(struct client_state *state) {

    /* TODO any additional client state cleanup */

    /* cleanup API state */
    api_state_free(&state->api);

    /* cleanup UI state */
    ui_state_free(&state->ui);
}

static void usage(void) {
    printf("usage:\n");
    printf("  client host port\n");
    exit(1);
}

int main(int argc, char **argv) {
    int fd;
    uint16_t port;
    struct client_state state;

    /* check arguments */
    if (argc != 3) usage();
    if (parse_port(argv[2], &port) != 0) usage();

    /* preparations */
    client_state_init(&state);

    /* connect to server */
    fd = client_connect(&state, argv[1], port);
    if (fd < 0) return 1;
    setvbuf(stdout, NULL, _IONBF, 0);
    /* initialize API */
    api_state_init(&state.api, fd);

    /* TODO any additional client initialization */

    /* client things */
    while (!state.eof && handle_incoming(&state) == 0);

    /* clean up */
    /* TODO any additional client cleanup */
    client_state_free(&state);
    close(fd);

    return 0;
}
