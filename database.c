#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "database.h"
#include "api.h"

int open_db(void)   {
    return sqlite3_open("chat.db", &db);
}

int store_account(const char *username, const char* pwd) {
    if(open_db() != SQLITE_OK)  {
        return -1;
    }
    sqlite3_stmt *stmt;
    const char *query = "INSERT INTO users (username, pwd) VALUES (?, ?);";
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        goto cleanup;
    }
    if(!stmt)   {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 1, username, -1, SQLITE_STATIC) != SQLITE_OK)    {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 2, pwd, -1, SQLITE_STATIC) != SQLITE_OK) {
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

int insert_msg(const char *msg, const char *sender, const char *timestamp) {
    if(open_db() != SQLITE_OK)  {
        goto cleanup;
    }
    sqlite3_stmt *stmt;
    const char *query = "INSERT INTO msgs (msg, sender, timestamp) VALUES (?, ?, ?);";
    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt) {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 1, msg, -1, SQLITE_STATIC) != SQLITE_OK) {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 2, sender, -1, SQLITE_STATIC) != SQLITE_OK)  {
        goto cleanup;
    }
    if(sqlite3_bind_text(stmt, 3, timestamp, -1, SQLITE_STATIC) != SQLITE_OK)   {
        goto cleanup;
    }
    if(sqlite3_step(stmt) != SQLITE_DONE)   {
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

char *get_all_msgs()    {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    size_t size = sizeof(struct api_msg);
    char *msgs = calloc(1, size * sizeof(char*));
    if(!msgs)   {
        return NULL;
    }
    sqlite3_stmt *stmt;
    const char *query = "SELECT timestamp, sender, msg FROM msgs ORDER BY id ASC;";

    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        goto cleanup;
    }

    while(sqlite3_step(stmt) != SQLITE_DONE)    {
        int num_cols = sqlite3_column_count(stmt);
        for(int i = 0; i < num_cols; i+=3)  {
            char msg[size];
            snprintf(msg, size, "%s %s: %s\n", sqlite3_column_text(stmt, i),
                                                                 sqlite3_column_text(stmt, i + 1),
                                                                 sqlite3_column_text(stmt, i + 2));
            strcat(msgs, msg);
        }
    }

    if(sqlite3_finalize(stmt) != SQLITE_OK) {
        goto cleanup;
    }

    sqlite3_close(db);
    msgs[strlen(msgs)] = '\0';
    return msgs;

    cleanup:
    free(msgs);
    sqlite3_close(db);
    return NULL;
}

char *get_last_pubmsg(void) {
    if(open_db() != SQLITE_OK)  {
        return NULL;
    }
    char *public_msg = calloc(BUFFER_LEN, sizeof(char));
    if(!public_msg) {
        return NULL;
    }
    sqlite3_stmt  *stmt;
    const char *query = "SELECT timestamp, sender, msg from msgs WHERE id = (SELECT MAX(ID) FROM msgs);";

    if(sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK || !stmt)  {
        goto cleanup;
    }

    sqlite3_step(stmt);

    snprintf(public_msg, BUFFER_LEN, "%s %s: %s\n", sqlite3_column_text(stmt, 0),
                                                                      sqlite3_column_text(stmt, 1),
                                                                      sqlite3_column_text(stmt, 2));
    if(sqlite3_finalize(stmt) != SQLITE_OK)  {
        goto cleanup;
    }
    sqlite3_close(db);
    public_msg[strlen(public_msg)] = '\0';
    return public_msg;

    cleanup:
        free(public_msg);
        sqlite3_close(db);
        return NULL;
}