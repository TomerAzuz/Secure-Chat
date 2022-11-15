#include <string.h>

#include "api.h"
#include "parser.h"
#include "sanitizer.h"

int is_cmd(const char* buf)   {
    return buf[0] == '/' ? 1 : 0;
}

int parse_cmd(char *cmd, int is_logged_in) {
    size_t len = strlen(cmd);
    if(strncmp(cmd, "/register", len) == 0)   {
        return !is_logged_in ? REGISTER : INVALID_CMD;
    }
    if(strncmp(cmd, "/login", len) == 0)  {
        return !is_logged_in ? LOGIN : INVALID_CMD;
    }
    if(strncmp(cmd, "/users", len) == 0)  {
        return is_logged_in ? USERS : INVALID_CMD;
    }
    if(strncmp(cmd, "/exit", len) == 0)   {
        return EXIT;
    }
    return UNKNOWN_CMD;
}

/**
 * @brief extract the arguments from the message
 * @param msg, buf, arg
 * @return The message type if args are valid, invalid format otherwise
 */
int get_args(struct api_msg *msg, char *buf, char *arg)  {
    unsigned int num_args = 0;
    while(arg && !(is_empty(arg))) {
        if(num_args == 0)   {
            if(is_valid_username(arg))  {
                memcpy(msg->username, arg, strlen(arg));
                msg->username[strlen(msg->username)] = '\0';
            }
            /* invalid username */
            else return INVALID_FORMAT;
        }
        else if(num_args == 1)   {
            if(is_valid_pwd(arg))   {
                memcpy(msg->pwd, arg, strlen(arg));
                msg->pwd[strcspn(msg->pwd, "\n")] = 0;
                msg->pwd[strlen(msg->pwd)] = '\0';
            }
            /* invalid password */
            else return INVALID_FORMAT;
        }
        /* invalid num args */
        else return INVALID_FORMAT;

        arg += strlen(arg) + 1;
        while(*arg == ' ')  {
            arg++;
        }
        num_args++;
    }
    return num_args < 2 ? INVALID_FORMAT : 1;
}

/**
 * @brief extract cmd from message
 * @param msg
 * @param is_logged_in
 * @return The message type if cmd is valid, invalid format otherwise
 */
int get_cmd(struct api_msg *msg, int is_logged_in)  {
    char *buf = msg->buffer;
    char *cmd = strtok(buf, " ");
    if(!cmd || is_empty(cmd))   {
        return INVALID_CMD;
    }
    msg->buffer[strcspn(msg->buffer, "\n")] = 0;
    cmd[strlen(cmd)] = '\0';

    msg->type = parse_cmd(cmd, is_logged_in);

    /* invalid msg */
    if(!valid_msg_type(msg->type)) {
        return msg->type;
    }

    buf += strlen(cmd) + 1;
    char *arg = strtok(buf, " ");

    if(msg->type == USERS || msg->type == EXIT)  {
        return no_args(msg->type, arg);
    }

    // skip whitespace
    int whitespace = 0;
    while(*arg == ' ')  {
        whitespace++;
        arg++;
    }
    buf += strlen(arg) + 1 + whitespace;

    /* invalid num args */
    if(get_args(msg, buf, arg) < 0)   {
        return INVALID_FORMAT;
    }
    return msg->type;
}