#include <assert.h>
#include <stdio.h>
#include <string.h>

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

void message_user(int msg_type, const char *msg)    {
    switch (msg_type) {
        case INVALID_CMD:
            fprintf(stdout, "error: command not currently available\n");
            break;
        case INVALID_FORMAT:
            fprintf(stdout, "error: invalid command format\n");
            break;
        case UNKNOWN_CMD:
            fprintf(stdout, "error: unknown command %s\n", msg);
            break;
        case REGISTER:
            fprintf(stdout, "registration succeeded\n");
            break;
        case LOGIN:
            fprintf(stdout, "authentication succeeded\n");
            break;
        default:
            fprintf(stdout, "%s\n", msg);
    }
}

int read_input(char *buf) {
    int ret = fgets(buf, BUFFER_LEN - 1, stdin) ? 1 : 0;
    buf[strlen(buf)] = '\0';
    return ret;
}