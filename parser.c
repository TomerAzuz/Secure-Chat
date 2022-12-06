#include <string.h>

#include "api.h"
#include "parser.h"
#include "sanitizer.h"

int is_private_msg(const char* buf)    {
    return buf[0] == '@' &&
           strlen(buf) > 1 &&
           strstr(buf, " ") ? 1 : 0;
}

int is_cmd(const char* buf)   {
    return buf[0] == '/' ? 1 : 0;
}

int parse_cmd(char *cmd, int is_logged_in) {
    if(strncmp(cmd, "/register\0", 10) == 0)   {
        return !is_logged_in ? REGISTER : INVALID_CMD;
    }
    if(strncmp(cmd, "/login\0", 7) == 0)  {
        return !is_logged_in ? LOGIN : INVALID_CMD;
    }
    if(strncmp(cmd, "/users\0", 7) == 0)  {
        return is_logged_in ? USERS : INVALID_CMD;
    }
    if(strncmp(cmd, "/exit\0", 6) == 0)   {
        return EXIT;
    }
    return UNKNOWN_CMD;
}

/**
 * @brief extract the arguments from the message
 * @param msg, buf, arg
 * @return The message type if args are valid, invalid format otherwise
 */
int get_args(struct api_msg *msg, char *arg)  {
    unsigned int num_args = 0;
    while(arg && !is_empty(arg)) {
        if(num_args == 0)   {
            if(is_valid_username(arg))  {
                memcpy(msg->sender, arg, strlen(arg));
            }
            else {
                printf("invalid username\n");
                return INVALID_FORMAT;
            }
        }
        else if(num_args == 1)   {
            if(is_valid_pwd(arg))   {
                memcpy(msg->pwd, arg, strlen(arg));
            }
            else {
                printf("invalid password\n");
                return INVALID_FORMAT;
            }
        }
        /* invalid num args */
        else return INVALID_FORMAT;

        arg += strlen(arg) + 1;
        while(*arg == ' ')  {
            arg++;
        }
        arg[strcspn(arg, "\n")] = 0;
        arg = strtok(arg, " ");

        num_args++;
    }
    return num_args == 2 ? 1 : INVALID_FORMAT;
}

/**
 * @brief extract cmd from message
 * @param msg
 * @param is_logged_in
 * @return The message type if cmd is valid, invalid format otherwise
 */
int get_msg_type(struct api_msg *msg, int is_logged_in)  {
    char *buf = msg->buffer;

    /* extract the command */
    char *cmd = strtok(buf, " ");
    if(is_empty(cmd))   {
        return INVALID_CMD;
    }
    cmd[strcspn(cmd, "\n")] = 0;
    cmd[strlen(cmd)] = '\0';

    msg->type = parse_cmd(cmd, is_logged_in);

    /* invalid msg */
    if(!valid_msg_type(msg->type)) {
        return msg->type;
    }
    /* extract first argument */
    buf += strlen(cmd) + 1;
    char *arg = strtok(buf, " ");

    /* commands with no arguments */
    if(msg->type == USERS || msg->type == EXIT)  {
        return no_args(msg->type, arg);
    }
    if(is_empty(arg))   {
        return INVALID_FORMAT;
    }
    /* skip whitespace */
    while(*arg == ' ')  {
        arg++;
    }
    return get_args(msg, arg) < 0 ? INVALID_FORMAT : msg->type;
}