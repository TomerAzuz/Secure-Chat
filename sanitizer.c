#include <string.h>

#include "api.h"
#include "sanitizer.h"
#include "parser.h"

int is_valid_username(char *username) {
    return is_empty(username) || strlen(username) >= USERNAME_LEN ? 0 : 1;
}

int is_valid_pwd(char *pwd) {
    return is_empty(pwd) || strlen(pwd) >= PWD_LEN ? 0 : 1;
}

int is_valid_msg(char *msg) {
    return is_empty(msg) || strlen(msg) >= BUFFER_LEN ? 0 : 1;
}

int is_empty(const char *msg) {
    return !msg || msg[0] == '\n' || msg[0] == '\t' || msg[0] == ' ' || msg[0] == '\0' || strlen(msg) == 0 ? 1 : 0;
}

int valid_msg_type(int msg_type) {
    return msg_type >= 0;
}

/**
 *
 * @param msg_type
 * @param arg
 * @return message type if there are no args, invalid format otherwise
 */
int no_args(int msg_type, char *arg)   {
    return !arg || is_empty(arg) ? msg_type : INVALID_FORMAT;
}

/**
 * @brief remove leading and trailing whitespace from message
 * @param msg
 */
char *remove_whitespace(char *msg)    {
    while(*msg == ' ')   {
        msg++;
    }
    char *end = msg + strlen(msg) - 1;
    while (*(end) == ' ')   {
        *(end) = '\0';
        end--;
    }
    msg[strcspn(msg, "\n")] = 0;
    return msg;
}
