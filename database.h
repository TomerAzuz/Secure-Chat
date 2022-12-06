#ifndef _DATABASE_H_
#define _DATABASE_H_

#include <sqlite3.h>

int store_account(const char *username, const char* pwd, const char *salt);
int insert_msg(const struct api_msg *msg);
struct api_msg** get_all_msgs(void);
struct api_msg* get_last_msg(void);
char *get_salt(const char *username);
char *get_pwd(const char *username);
struct api_msg *get_online_users(void);
int update_online(const char *username, int active);

#endif
