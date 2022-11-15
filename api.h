#ifndef _API_H_
#define _API_H_

#define BUFFER_LEN   1024
#define USERNAME_LEN  17
#define PWD_LEN       17
#define TIMESTAMP_LEN 50

struct api_msg {
    char buffer[BUFFER_LEN];
    int type;
    char username[USERNAME_LEN];
    char pwd[PWD_LEN];
    char timestamp[TIMESTAMP_LEN];
} __attribute__((packed));

struct api_state {
    int fd;
    /* TODO add required fields */
};


int api_recv(struct api_state *state, struct api_msg *msg);
        void api_recv_free(struct api_msg *msg);

void api_state_free(struct api_state *state);
void api_state_init(struct api_state *state, int fd);
void api_init_msg(struct api_msg *msg);

/* TODO add API calls to send messages to perform client-server interactions */

#endif /* defined(_API_H_) */
