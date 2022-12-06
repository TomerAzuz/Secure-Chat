#include <string.h>
#include <stdlib.h>

#include "api.h"
#include "database.h"
#include "crypto.h"

sqlite3 *db;

int open_db(void)   {
    return sqlite3_open("chat.db", &db);
}

int store_account(const char *username, const char* pwd, const char *salt) {
    if(open_db() != SQLITE_OK)  {
        return -1;
    }
    sqlite3_stmt *stmt;
    const char *query = "INSERT INTO users (username, pwd, salt, online) VALUES (?, ?, ?, 1);";
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK)    {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 2, pwd, -1, SQLITE_STATIC) != SQLITE_OK) {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 3, salt, -1, SQLITE_STATIC) != SQLITE_OK) {
        goto cleanup;
    }
    if(sqlite3_step(stmt) != SQLITE_DONE)          {
        goto cleanup;
    }
    if(sqlite3_finalize(stmt) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_close(db);
    return SQLITE_OK;

    cleanup:
        sqlite3_close(db);
        return -1;
}

char *get_salt(const char *username) {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    sqlite3_stmt *stmt;
    const char *query = "SELECT salt FROM users WHERE username = ?;";

    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt)    {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK)    {
        goto cleanup;
    }
    if(sqlite3_step(stmt) != SQLITE_ROW)    {
        goto cleanup;
    }
    char *salt = calloc(SALT_LEN, sizeof(char));
    snprintf(salt, SALT_LEN, "%s", sqlite3_column_text(stmt, 0));
    if(sqlite3_finalize(stmt) != SQLITE_OK) {
        free(salt);
        goto cleanup;
    }
    salt[SALT_LEN-1] = '\0';
    sqlite3_close(db);
    return salt;

    cleanup:
        sqlite3_close(db);
        return NULL;
}

char *get_pwd(const char *username) {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    sqlite3_stmt *stmt;
    const char *query = "SELECT pwd FROM users WHERE username = ?;";

    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt)    {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK)    {
        goto cleanup;
    }
    if(sqlite3_step(stmt) != SQLITE_ROW)    {
        goto cleanup;
    }
    char *pwd = calloc(PWD_LEN, sizeof(char));
    snprintf(pwd, PWD_LEN, "%s", sqlite3_column_text(stmt, 0));
    if(sqlite3_finalize(stmt) != SQLITE_OK) {
        free(pwd);
        goto cleanup;
    }
    sqlite3_close(db);
    return pwd;

    cleanup:
        sqlite3_close(db);
        return NULL;
}

int insert_msg(const struct api_msg *msg) {
    if(open_db() != SQLITE_OK)  {
        goto cleanup;
    }
    sqlite3_stmt *stmt;

    const char *query = "INSERT INTO msgs (msg, sender, recipient, timestamp, sig, key) VALUES (?, ?, ?, ?, ?, ?);";
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 1, msg->buffer, BUFFER_LEN-1, SQLITE_STATIC) != SQLITE_OK) {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 2, msg->sender, USERNAME_LEN-1, SQLITE_STATIC) != SQLITE_OK)  {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 3, msg->recipient, USERNAME_LEN-1, SQLITE_STATIC) != SQLITE_OK)   {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 4, msg->timestamp, TIMESTAMP_LEN-1, SQLITE_STATIC) != SQLITE_OK)   {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 5, msg->sig, SIG_LEN-1, SQLITE_STATIC) != SQLITE_OK)   {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 6, msg->aes, RSA_LEN-1, SQLITE_STATIC) != SQLITE_OK)   {
        goto cleanup;
    }
    int r = sqlite3_step(stmt);
    if(r != SQLITE_DONE) {
        goto cleanup;
    }
    if(sqlite3_finalize(stmt) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_close(db);
    return SQLITE_OK;

    cleanup:
        sqlite3_close(db);
        return -1;
}

int set_msg_fields(struct api_msg *msg, sqlite3_stmt *stmt)    {
    msg->type = 0;
    if(!sqlite3_column_text(stmt, 0))   {
        return -1;
    }
    memcpy(msg->timestamp, sqlite3_column_text(stmt, 0), TIMESTAMP_LEN-1);
    if(!sqlite3_column_text(stmt, 1))   {
        return -1;
    }
    memcpy(msg->sender,  sqlite3_column_text(stmt, 1), USERNAME_LEN-1);
    if(!sqlite3_column_text(stmt, 2))   {
        return -1;
    }
    memcpy(msg->buffer, sqlite3_column_text(stmt, 2), BUFFER_LEN-1);
    if(!sqlite3_column_text(stmt, 3))   {
        return -1;
    }
    memcpy(msg->sig, sqlite3_column_text(stmt, 3), SIG_LEN-1);
    unsigned const char *recipient = sqlite3_column_text(stmt, 4);
    if(!recipient)   {
        return -1;
    }
    /* public message */
    if(recipient[0] == ' ') {
        return 0;
    }
    memcpy(msg->recipient, sqlite3_column_text(stmt, 4), USERNAME_LEN-1);
    if(!sqlite3_column_text(stmt, 5))   {
        return -1;
    }
    memcpy(msg->aes, sqlite3_column_text(stmt, 5), RSA_LEN-1);
    if(strlen(msg->recipient) > 0 && strlen(msg->aes) > 0)   {
        msg->type = 4;
    }
    return 0;
}

struct api_msg** get_all_msgs(void)    {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    unsigned int capacity = 10;
    size_t msg_size = sizeof(struct api_msg*);
    struct api_msg **msgs = calloc(1, capacity * msg_size);
    if(!msgs)   {
        return NULL;
    }
    sqlite3_stmt *stmt;
    const char *query = "SELECT timestamp, sender, msg, sig, recipient, key FROM msgs ORDER BY id ASC;";
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        goto cleanup;
    }
    unsigned long num_msgs = 0;
    while(sqlite3_step(stmt) != SQLITE_DONE)    {
        int num_cols = sqlite3_column_count(stmt);
        for(int i = 0; i < num_cols; i+=6)  {
            if(num_msgs >= capacity - 1)    {
                capacity *= 2;
                struct api_msg **temp = (struct api_msg**) realloc(msgs, capacity * msg_size);
                if(!temp) {
                    goto cleanup;
                }
                msgs = temp;
            }
            struct api_msg *msg = calloc(1, sizeof(struct api_msg));
            api_init_msg(msg);
            msgs[num_msgs++] = msg;
            if(set_msg_fields(msg, stmt) != 0)  {
                goto cleanup;
            }
        }
    }
    msgs[num_msgs] = NULL;
    if(sqlite3_finalize(stmt) != SQLITE_OK) {
        goto cleanup;
    }
    sqlite3_close(db);
    return msgs;

    cleanup:
        for(int i = 0; i < num_msgs; i++) {
            free(msgs[i]);
        }
        free(msgs);
        sqlite3_close(db);
        return NULL;
}


struct api_msg* get_last_msg(void) {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    struct api_msg *msg = calloc(1, sizeof(struct api_msg));
    if(!msg) {
        return NULL;
    }
    sqlite3_stmt  *stmt;
    const char *query = "SELECT timestamp, sender, msg, sig, recipient, key from msgs WHERE id = (SELECT MAX(ID) FROM msgs);";

    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt)  {
        goto cleanup;
    }
    int r = sqlite3_step(stmt);
    if(r != SQLITE_ROW)    {
        goto cleanup;
    }
    if(set_msg_fields(msg, stmt) != 0)  {
        goto cleanup;
    }
    r = sqlite3_finalize(stmt);
    if(r != SQLITE_OK)  {
        goto cleanup;
    }
    sqlite3_close(db);
    return msg;

    cleanup:
        free(msg);
        sqlite3_close(db);
        return NULL;
}

int update_online(const char *username, const int active)   {
    if(open_db() != SQLITE_OK)  {
        return -1;
    }
    sqlite3_stmt *stmt;
    const char* query = "UPDATE users SET online = ? WHERE username = ?;";
    int r = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    while(r == SQLITE_BUSY) {
        sqlite3_busy_timeout(db, 10);
        r = sqlite3_prepare_v2(db, query, -1, &stmt, NULL);
    }
    if(r != SQLITE_OK)    {
        sqlite3_close(db);
        return -1;
    }
    if(sqlite3_bind_int(stmt, 1, active) != SQLITE_OK)    {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 2, username, -1, SQLITE_STATIC) != SQLITE_OK)    {
        goto cleanup;
    }
    r = sqlite3_step(stmt);
    while(r == SQLITE_BUSY) {
        sqlite3_busy_timeout(db, 10);
        r = sqlite3_step(stmt);
    }
    if(r != SQLITE_DONE)   {
        goto cleanup;
    }
    if(sqlite3_finalize(stmt) != SQLITE_OK)  {
        goto cleanup;
    }
    sqlite3_close(db);
    return 1;

    cleanup:
        sqlite3_close(db);
        return -1;
}

struct api_msg *get_online_users(void)  {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    sqlite3_stmt  *stmt;
    const char *query = "SELECT username from users WHERE online = 1;";
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt)  {
        goto cleanup;
    }
    struct api_msg *msg = calloc(1, sizeof(struct api_msg));
    if(!msg) {
        goto cleanup;
    }
    while(sqlite3_step(stmt) != SQLITE_DONE)    {
        int num_cols = sqlite3_column_count(stmt);
        for(int i = 0; i < num_cols; i++)  {
            const char *user = (const char*) sqlite3_column_text(stmt, i);
            strncat(msg->buffer, user, strlen(user));
            strcat(msg->buffer, "\n");
        }
    }
    msg->buffer[strlen(msg->buffer)-1] = '\0';
    sqlite3_close(db);
    return msg;

    cleanup:
        sqlite3_close(db);
        return NULL;
}