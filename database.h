#ifndef _DATABASE_H_
#define _DATABASE_H_

#include <sqlite3.h>

sqlite3 *db;

int open_db(void);
int store_account(const char *username, const char* pwd);
int insert_msg(const char *msg, const char *sender, const char *timestamp);
char *get_all_msgs();
char *get_last_pubmsg(void);

#endif
