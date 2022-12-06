#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "api.h"
#include "ui.h"
#include "util.h"
#include "parser.h"
#include "sanitizer.h"
#include "ssl-nonblock.h"
#include "crypto.h"

struct client_state {
    struct api_state api;
    int eof;
    struct ui_state ui;
    int logged_in;
    SSL *ssl;
};

int auth_server(struct client_state *state)   {
    /* check server certificate */
    if(!SSL_get_peer_certificate(state->ssl))    {
        return -1;
    }
    if(SSL_get_verify_result(state->ssl) != X509_V_OK)  {
        return -1;
    }
    /* verify hostname */
    X509_VERIFY_PARAM *param = SSL_get0_param(state->ssl);
    if(!param) {
        return -1;
    }
    const char servername[] = "server.example.com/";
    X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (!X509_VERIFY_PARAM_set1_host(param, servername, sizeof(servername) - 1)) {
        return -1;
    }
    return 0;
}

int ssl_connect(struct client_state *state, SSL_CTX *ctx)   {
    state->ssl = SSL_new(ctx);
    if(!state->ssl) {
        SSL_CTX_free(ctx);
        return -1;
    }
    SSL_set_verify(state->ssl, SSL_VERIFY_PEER, NULL);

    if(set_nonblock(state->api.fd) != 0)    {
        return -1;
    }
    if(SSL_set_fd(state->ssl, state->api.fd) != 1)  {
        return -1;
    }
    if(ssl_block_connect(state->ssl, state->api.fd) != 1)  {
        return -1;
    }
    return auth_server(state);
}


int setup_ssl(struct client_state *state) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx)  {
        return -1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    const char ca_cert[] = "./keys/clientkeys/ca-cert.pem";
    if(SSL_CTX_load_verify_locations(ctx, ca_cert, NULL) != 1)    {
        SSL_CTX_free(ctx);
        return -1;
    }
    if(ssl_connect(state, ctx) != 0) {
        goto cleanup;
    }
    return 0;

    cleanup:
    SSL_CTX_free(ctx);
    SSL_free(state->ssl);
    return -1;
}

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

int username_exists(const char *username)    {
    char *path = get_key_path(username, "keypub");
    if(!path)  {
        return -1;
    }
    return access(path, R_OK) == 0 ? 1 : 0;
}

int handle_register(struct client_state *state, struct api_msg *msg)   {
    assert(state);
    assert(msg);
    memcpy(state->ui.username, msg->sender, USERNAME_LEN);
    if(username_exists(msg->sender))   {
        message_user(USERNAME_TAKEN, msg);
        return 0;
    }
    /* generate rsa key pair */
    if(generate_rsa_keys(msg->sender) != 0)   {
        return -1;
    }
    /* hash password */
    if(hash_pwd(msg->pwd) != 0)    {
        return -1;
    }
    /* sign message */
    if(sign_msg(msg) != 0)  {
        return -1;
    }
    return api_send(state->ssl, state->api.fd, msg);
}

int handle_login(struct client_state *state, struct api_msg *msg)  {
    assert(state);
    assert(msg);
    memcpy(state->ui.username, msg->sender, USERNAME_LEN);

    if(!username_exists(msg->sender))   {
        message_user(AUTH_ERROR, NULL);
        return -1;
    }
    if(hash_pwd(msg->pwd) != 0) {
        return -1;
    }
    if(sign_msg(msg) != 0)  {
        return -1;
    }
    return api_send(state->ssl, state->api.fd, msg);
}

int handle_users(struct client_state *state, struct api_msg *msg)  {
    assert(msg);
    msg->type = USERS;
    memcpy(msg->sender, state->ui.username, USERNAME_LEN);
    if(sign_msg(msg) != 0)  {
        return -1;
    }
    return api_send(state->ssl, state->api.fd, msg);
}


int handle_public(struct client_state *state, struct api_msg *msg) {
    assert(state);
    assert(msg);
    if(is_valid_msg(msg->buffer))   {
        msg->type = PUB_MSG;
        /* store timestamp in message */
        char *timestamp = get_timestamp();
        memcpy(msg->timestamp, timestamp, TIMESTAMP_LEN);
        free(timestamp);

        /* store sender */
        strcpy(msg->sender, state->ui.username);

        /* sign message */
        if(sign_msg(msg) != 0)  {
            return -1;
        }
        return api_send(state->ssl, state->api.fd, msg);
    }
    message_user(INVALID_FORMAT, NULL);
    return 0;
}

int handle_private(struct client_state *state, struct api_msg *msg) {
    assert(state);
    assert(msg);

    msg->type = PRIV_MSG;
    /* store recipient */
    int count = 0;
    char *buf = msg->buffer;
    while(*buf != ' ' && count < USERNAME_LEN)  {
        count++;
        buf++;
        msg->recipient[count-1] = *buf;
    }
    msg->recipient[count-1] = '\0';
    if(!is_valid_username(msg->recipient))  {
        printf("invalid username\n");
        return 0;
    }
    if(!username_exists(msg->recipient))    {
        message_user(USER_NOT_FOUND, NULL);
        return 0;
    }

    /* remove whitespace */
    char *trimmed = remove_whitespace(buf);
    if(!is_valid_msg(trimmed))  {
        message_user(INVALID_FORMAT, NULL);
        return 0;
    }
    buf -= count;
    buf = strtok(buf, " ");

    /* store timestamp */
    char *timestamp = get_timestamp();
    memcpy(msg->timestamp, timestamp, TIMESTAMP_LEN);
    free(timestamp);

    /* store sender */
    strcpy(msg->sender, state->ui.username);

    /* copy message to buffer */
    char priv_msg[BUFFER_LEN];
    memset(priv_msg, '\0', BUFFER_LEN);
    strcat(priv_msg, buf);
    strcat(priv_msg, " ");
    strcat(priv_msg, trimmed);

    /* encrypt message with AES */
    struct aes_key *aes = get_aes_key(msg->sender);
    unsigned char *plaintext = (unsigned char *) trimmed;
    unsigned char *ciphertext = aes_encrypt(plaintext, aes);
    memset(msg->buffer, '\0', BUFFER_LEN);
    strcpy(msg->buffer, (char*) ciphertext);
    free(ciphertext);;

    /* encrypt AES with recipient's key */
    unsigned char key_and_iv[AES_LEN + IV_LEN];
    memset(key_and_iv, '\0', AES_LEN + IV_LEN);
    strcat((char*)key_and_iv, (char*)aes->key);
    strcat((char*)key_and_iv, " ");
    strcat((char*)key_and_iv, (char*)aes->iv);
    unsigned char *encrypted_aes1 = use_rsa(msg->recipient, key_and_iv, 1);
    memcpy(msg->aes1, encrypted_aes1, RSA_LEN-1);
    msg->aes1[RSA_LEN-1] = '\0';
    free(encrypted_aes1);

    /* encrypt AES with sender's key */
    unsigned char *encrypted_aes2 = use_rsa(msg->sender, key_and_iv, 1);
    memcpy(msg->aes2, encrypted_aes2, RSA_LEN-1);
    msg->aes2[RSA_LEN-1] = '\0';
    free(encrypted_aes2);

    if(sign_msg(msg) != 0)  {
        return -1;
    }
    return api_send(state->ssl, state->api.fd, msg);
}

int handle_msg(struct client_state *state, struct api_msg *msg)    {
    if(state->logged_in) {
        /* remove whitespace from message */
        char trimmed_msg[BUFFER_LEN];
        memset(trimmed_msg, '\0', BUFFER_LEN);
        char *trimmed = remove_whitespace(msg->buffer);

        /* copy trimmed message to buffer */
        memcpy(trimmed_msg, trimmed, strlen(trimmed)+1);
        memset(msg->buffer, '\0', BUFFER_LEN);
        memcpy(msg->buffer, trimmed_msg, strlen(trimmed_msg)+1);

        return is_private_msg(msg->buffer) ? handle_private(state, msg) : handle_public(state, msg);
    }
    message_user(INVALID_CMD, msg);
    return -1;
}

static int client_process_command(struct client_state *state) {
    assert(state);
    int ret = 0;

    size_t msg_size = sizeof(struct api_msg);
    struct api_msg *msg = calloc(1, msg_size);
    if(!msg)    {
        return -1;
    }
    if(read_input(msg->buffer) == 0)    {
        state->eof = 1;
    }
    else if(is_cmd(msg->buffer))    {
        int msg_type = get_msg_type(msg, state->logged_in);
        switch(msg_type)    {
            case REGISTER:
                ret = handle_register(state, msg);
                break;
            case LOGIN:
                ret = handle_login(state, msg);
                break;
            case USERS:
                ret = handle_users(state, msg);
                break;
            case EXIT:
                free(msg);
                exit(EXIT_SUCCESS);
            default:
                message_user(msg_type, msg);
                free(msg);
                return 0;
        }
        free(msg);
        return ret;
    }
    else    {
        ret = handle_msg(state, msg);
    }
    free(msg);
    return ret;
}

int handle_incoming_privmsg(const char *username, struct api_msg *msg)   {
    /* decrypt aes key */
    unsigned char *decrypted_key = NULL;
    if(strcmp(msg->sender, username) == 0)  {
        decrypted_key = use_rsa(msg->sender, (unsigned char*) msg->aes2, 0);
        if(!decrypted_key)  {
            return -1;
        }
    }
    else    {
        decrypted_key = use_rsa(msg->recipient, (unsigned char*) msg->aes1, 0);
        if(!decrypted_key)  {
            return -1;
        }
    }
    decrypted_key[AES_LEN-1] = '\0';
    unsigned char *iv = decrypted_key + AES_LEN;

    /* store key */
    struct aes_key aes;
    memset(&aes, 0, sizeof(struct aes_key));
    memcpy(aes.key, decrypted_key, AES_LEN-1);
    memcpy(aes.iv, iv, IV_LEN-1);

    /* decrypt message with aes */
    unsigned char *decrypted_msg = aes_decrypt((unsigned char*) msg->buffer, &aes);
    if(!decrypted_msg)  {
        return -1;
    }
    /* copy plaintext to buffer */
    memset(msg->buffer, '\0', BUFFER_LEN);
    memcpy(msg->buffer, decrypted_msg, BUFFER_LEN-1);
    msg->buffer[BUFFER_LEN-1] = '\0';

    free(decrypted_msg);
    free(decrypted_key);
    return 0;
}

/**
 * @brief         Handles a message coming from server (i.e, worker)
 * @param state   Initialized client state
 * @param msg     Message to handle
 */
static int execute_request(struct client_state *state,
                           struct api_msg *msg) {
    assert(state);
    assert(msg);
    switch (msg->type)  {
        case REGISTER:
            state->logged_in = 1;
            message_user(REGISTER, NULL);
            break;
        case LOGIN:
            state->logged_in = 1;
            message_user(LOGIN, NULL);
            break;
        case USERS:
            message_user(USERS, msg);
            break;
        case AUTH_ERROR:
            message_user(AUTH_ERROR, NULL);
            return -1;
        default:
            if(state->logged_in) {
                if(strcmp(msg->sender, state->ui.username) != 0)  {
                    if(verify_sig(msg) != 0)    {
                        return -1;
                    }
                }
                if(msg->type == PUB_MSG)    {
                    message_user(PUB_MSG, msg);
                }
                else   {
                    if(handle_incoming_privmsg(state->ui.username, msg) != 0)   {
                        return -1;
                    }
                    message_user(PRIV_MSG, msg);
                }
            }
            return 0;
    }
    return 0;
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
    r = api_recv(state->ssl, &state->api, &msg);
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

    if (FD_ISSET(state->api.fd, &readfds) && ssl_has_data(state->ssl)) {
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
    state->ssl = NULL;
    return 0;
}

static void client_state_free(struct client_state *state) {
    /* cleanup API state */
    api_state_free(&state->api);
    /* cleanup UI state */
    ui_state_free(&state->ui);
    /* free ssl */
    if(state->ssl)  {
        SSL_free(state->ssl);
    }
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

    if(setup_ssl(&state) != 0)   {
        printf("SSL setup failed\n");
        return -1;
    }

    /* client things */
    while (!state.eof && handle_incoming(&state) == 0);

    /* clean up */
    /* TODO any additional client cleanup */
    client_state_free(&state);
    close(fd);

    return 0;
}
