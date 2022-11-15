#ifndef _PARSER_H_
#define _PARSER_H_

#define UNKNOWN_CMD      (-3)
#define INVALID_CMD      (-2)
#define INVALID_FORMAT   (-1)
#define REGISTER         1
#define LOGIN            2
#define USERS            3
#define PRIV_MSG         4
#define EXIT             5

int is_cmd(const char* buf);
int parse_cmd(char *cmd, int is_logged_in);
int get_args(struct api_msg *msg, char *buf, char *arg);
int get_cmd(struct api_msg *msg, int is_logged_in);

#endif
