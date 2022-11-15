#ifndef _SANITIZER_H_
#define _SANITIZER_H_

int is_valid_username(char *username);
int is_valid_pwd(char *pwd);
int is_valid_msg(char *msg);
int is_empty(const char *msg);
int valid_msg_type(int msg_type);
int no_args(int msg_type, char *arg);
char* remove_whitespace(char *msg);

#endif
