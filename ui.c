#include <assert.h>
#include <stdio.h>

#include "ui.h"
#include "api.h"
#include "parser.h"

/**
 * @brief         Frees ui_state context
 * @param state   Initialized UI state to be cleaned up
 */
void ui_state_free(struct ui_state *state) {
    assert(state);
    ui_state_init(state);
}

/**
 * @brief         Initializes ui_state context
 * @param state   UI state to be initialized
 */
void ui_state_init(struct ui_state *state) {
    assert(state);
}

void message_user(int msg_type, const struct api_msg *msg)    {
    switch (msg_type) {
        case INVALID_CMD:
            fprintf(stdout, "error: command not currently available\n");
            break;
        case INVALID_FORMAT:
            fprintf(stdout, "error: invalid command format\n");
            break;
        case UNKNOWN_CMD:
            fprintf(stdout, "error: unknown command %s\n", msg->buffer);
            break;
        case AUTH_ERROR:
            fprintf(stdout, "error: invalid credentials\n");
            break;
        case USERNAME_TAKEN:
            fprintf(stdout, "error: user %s already exists\n", msg->sender);
            break;
        case USER_NOT_FOUND:
            fprintf(stdout, "error: user not found\n");
            break;
        case REGISTER:
            fprintf(stdout, "registration succeeded\n");
            break;
        case LOGIN:
            fprintf(stdout, "authentication succeeded\n");
            break;
        case USERS:
            fprintf(stdout, "%s\n", msg->buffer);
            break;
        case PRIV_MSG:
            fprintf(stdout, "%s %s: @%s %s\n", msg->timestamp, msg->sender, msg->recipient, msg->buffer);
            break;
        default:
            fprintf(stdout,"%s %s: %s\n", msg->timestamp, msg->sender, msg->buffer);
    }
}

int read_input(char *buf) {
    char *input = fgets(buf, BUFFER_LEN, stdin);
    return input ? 1 : 0;
}