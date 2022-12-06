#ifndef _UI_H_
#define _UI_H_

#include "api.h"

struct ui_state {
    char username[USERNAME_LEN];
};

void ui_state_free(struct ui_state *state);
void ui_state_init(struct ui_state *state);
int read_input(char *buf);
void message_user(int msg_type, const struct api_msg *msg);

#endif /* defined(_UI_H_) */
